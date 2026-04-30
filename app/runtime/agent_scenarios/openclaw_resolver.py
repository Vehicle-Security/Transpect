import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging import version


@dataclass
class OpenClawCandidate:
    path: str
    source: str
    exists: bool = False
    executable: bool = False
    version: str | None = None
    parsed_version: str | None = None  # e.g. "2026.4.24" -> "2026.4.24"
    ok: bool = False
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "source": self.source,
            "exists": self.exists,
            "executable": self.executable,
            "version": self.version,
            "parsed_version": self.parsed_version,
            "ok": self.ok,
            "reason": self.reason,
        }


@dataclass
class OpenClawResolution:
    selected_candidate: OpenClawCandidate | None = None
    candidates: list[OpenClawCandidate] = field(default_factory=list)
    platform: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    min_version: str = "2026.4.24"

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_candidate": self.selected_candidate.to_dict() if self.selected_candidate else None,
            "candidates": [c.to_dict() for c in self.candidates],
            "platform": self.platform,
            "errors": self.errors,
            "warnings": self.warnings,
            "min_version": self.min_version,
        }


class OpenClawResolver:
    """Resolves the best OpenClaw binary candidate across platforms."""

    def __init__(self, min_version: str = "2026.4.24") -> None:
        self.min_version = min_version
        self.platform_system = platform.system()

    def resolve(self, cli_bin: str | None = None) -> OpenClawResolution:
        res = OpenClawResolution(platform=self.platform_system, min_version=self.min_version)
        candidates_to_check: list[tuple[str, str]] = []

        # 1. CLI parameter
        if cli_bin:
            candidates_to_check.append((cli_bin, "cli"))

        # 2. Environment variable
        env_bin = os.environ.get("OPENCLAW_BIN")
        if env_bin:
            candidates_to_check.append((env_bin, "env"))

        # 3. PATH
        path_bin = shutil.which("openclaw")
        if path_bin:
            candidates_to_check.append((path_bin, "path"))

        # 4 & 5 & 6 & 7 & 8: Common platform paths & global npm paths
        home = Path.home()
        if self.platform_system == "Windows":
            appdata = os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))
            candidates_to_check.extend([
                (str(Path(appdata) / "npm" / "openclaw.cmd"), "windows_npm_shim"),
                (str(Path(appdata) / "npm" / "openclaw"), "windows_npm_shim_sh"),
                (str(home / "AppData" / "Roaming" / "nvm" / "v*" / "openclaw.cmd"), "windows_nvm"),
            ])
        else:
            candidates_to_check.extend([
                (str(home / ".npm-global" / "bin" / "openclaw"), "npm_global"),
                (str(home / ".nvm" / "versions" / "node" / "*" / "bin" / "openclaw"), "nvm_linux_mac"),
                ("/usr/local/bin/openclaw", "usr_local_bin"),
                ("/opt/homebrew/bin/openclaw", "homebrew_mac"),
            ])

        # Evaluate candidates
        seen_paths = set()
        for raw_path, source in candidates_to_check:
            # Handle basic globbing for NVM paths
            if "*" in raw_path:
                import glob
                matched_paths = glob.glob(raw_path)
                for mp in matched_paths:
                    self._evaluate_and_add(mp, source, res, seen_paths)
            else:
                self._evaluate_and_add(raw_path, source, res, seen_paths)

            if res.selected_candidate:
                # If we found a fully working one that meets constraints, we can stop evaluating others to save time,
                # or we can evaluate all to find the *highest* version.
                # The requirements say "选择满足版本要求的最高版本" (Select highest version that meets requirements)
                # But typically we want the highest priority one that is valid. Let's evaluate all and pick the best.
                pass

        # Select best candidate
        valid_candidates = [c for c in res.candidates if c.ok]
        if valid_candidates:
            # Sort by parsed version (highest first). If equal, relies on the stable sort (order of insertion, which is priority order).
            def sort_key(c: OpenClawCandidate) -> version.Version:
                try:
                    return version.parse(c.parsed_version or "0.0.0")
                except version.InvalidVersion:
                    return version.parse("0.0.0")

            valid_candidates.sort(key=sort_key, reverse=True)
            res.selected_candidate = valid_candidates[0]
        else:
            res.errors.append("No valid OpenClaw binary found.")

        return res

    def _evaluate_and_add(self, path_str: str, source: str, res: OpenClawResolution, seen_paths: set[str]) -> None:
        path = Path(path_str).resolve()
        path_key = str(path)
        if path_key in seen_paths:
            return
        seen_paths.add(path_key)

        candidate = OpenClawCandidate(path=path_key, source=source)
        res.candidates.append(candidate)

        if not path.exists():
            candidate.reason = "Path does not exist"
            return
        candidate.exists = True

        if not os.access(path, os.X_OK):
            candidate.reason = "Not executable"
            return
        candidate.executable = True

        # Run openclaw --version
        try:
            # Add timeout to prevent hanging if it's a completely wrong binary
            proc = subprocess.run(
                [path_key, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            if proc.returncode != 0:
                candidate.reason = f"Command failed with code {proc.returncode}"
                return

            v_out = proc.stdout.strip()
            # The version might have prefix or suffix, extract the semantic part
            # e.g., "OpenClaw v2026.4.24" -> "2026.4.24"
            import re
            m = re.search(r"(\d+\.\d+\.\d+)", v_out)
            if m:
                candidate.version = v_out
                candidate.parsed_version = m.group(1)
            else:
                candidate.version = v_out
                candidate.parsed_version = v_out

            try:
                parsed = version.parse(candidate.parsed_version)
                min_v = version.parse(res.min_version)
                if parsed < min_v:
                    candidate.reason = f"Version {candidate.parsed_version} < {res.min_version}"
                    return
            except version.InvalidVersion:
                candidate.reason = f"Invalid version format: {candidate.parsed_version}"
                return

            candidate.ok = True
            candidate.reason = "ok"

        except subprocess.TimeoutExpired:
            candidate.reason = "Timeout running --version"
        except Exception as e:
            candidate.reason = f"Execution error: {e}"
