import inspect
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FridaPermissionStatus:
    checked: bool = False
    can_enumerate_processes: bool = False
    can_attach_self: bool | None = None
    can_attach_target: bool | None = None
    task_for_pid_likely_blocked: bool = False
    sip_maybe_related: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "can_enumerate_processes": self.can_enumerate_processes,
            "can_attach_self": self.can_attach_self,
            "can_attach_target": self.can_attach_target,
            "task_for_pid_likely_blocked": self.task_for_pid_likely_blocked,
            "sip_maybe_related": self.sip_maybe_related,
            "error": self.error,
        }


@dataclass
class FridaCliTools:
    frida_ps_found: bool = False
    frida_trace_found: bool = False
    frida_ls_devices_found: bool = False
    paths: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frida_ps_found": self.frida_ps_found,
            "frida_trace_found": self.frida_trace_found,
            "frida_ls_devices_found": self.frida_ls_devices_found,
            "paths": self.paths,
        }


@dataclass
class FridaResolution:
    available: bool = False
    package_available: bool = False
    attach_ready: bool = False
    python_executable: str | None = None
    python_arch: str | None = None
    system_arch: str | None = None
    arch_mismatch: bool = False
    import_ok: bool = False
    module_path: str | None = None
    version: str | None = None
    has_attach: bool = False
    has_get_local_device: bool = False
    has_enumerate_processes: bool = False
    cli_tools: FridaCliTools = field(default_factory=FridaCliTools)
    shadowed: bool = False
    shadow_path: str | None = None
    local_shadow_candidates: list[str] = field(default_factory=list)
    permission_status: FridaPermissionStatus = field(default_factory=FridaPermissionStatus)
    platform_notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    install_hint: str | None = None
    macos_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "package_available": self.package_available,
            "attach_ready": self.attach_ready,
            "python_executable": self.python_executable,
            "python_arch": self.python_arch,
            "system_arch": self.system_arch,
            "arch_mismatch": self.arch_mismatch,
            "import_ok": self.import_ok,
            "module_path": self.module_path,
            "version": self.version,
            "has_attach": self.has_attach,
            "has_get_local_device": self.has_get_local_device,
            "has_enumerate_processes": self.has_enumerate_processes,
            "cli_tools": self.cli_tools.to_dict(),
            "shadowed": self.shadowed,
            "shadow_path": self.shadow_path,
            "local_shadow_candidates": self.local_shadow_candidates,
            "permission_status": self.permission_status.to_dict(),
            "platform_notes": self.platform_notes,
            "errors": self.errors,
            "warnings": self.warnings,
            "install_hint": self.install_hint,
            "macos_hint": self.macos_hint,
        }


class FridaResolver:
    """Diagnoses Frida availability, handles shadows, and probes OS permissions."""

    def __init__(self) -> None:
        pass

    def _system_arch(self) -> str | None:
        if platform.system() == "Darwin" and platform.machine() == "x86_64" and Path("/opt/homebrew").exists():
            # Under Rosetta, uname/platform report x86_64 even on Apple Silicon.
            # The Homebrew prefix is a practical local signal that native target
            # processes such as OpenClaw's Node are likely arm64.
            return "arm64"
        try:
            return subprocess.check_output(["uname", "-m"], text=True, stderr=subprocess.DEVNULL).strip() or None
        except Exception:
            return platform.machine() or None

    def _resolve_cli_tools(self, res: FridaResolution) -> None:
        for tool in ["frida-ps", "frida-trace", "frida-ls-devices"]:
            sibling = Path(sys.executable).resolve().parent / tool
            resolved = str(sibling) if sibling.exists() else shutil.which(tool)
            if resolved:
                res.cli_tools.paths[tool] = resolved
                if tool == "frida-ps":
                    res.cli_tools.frida_ps_found = True
                elif tool == "frida-trace":
                    res.cli_tools.frida_trace_found = True
                elif tool == "frida-ls-devices":
                    res.cli_tools.frida_ls_devices_found = True
        
        if res.import_ok and not res.shadowed and not (res.cli_tools.frida_ps_found and res.cli_tools.frida_trace_found):
            res.warnings.append("frida_cli_tools_not_on_path")
            res.install_hint = (res.install_hint or "") + " Verify that pip --user bin directory is in your PATH."

    def resolve(self, self_attach_check: bool = False) -> FridaResolution:
        res = FridaResolution()
        res.platform_notes.append(platform.system())
        res.python_executable = sys.executable
        res.python_arch = platform.machine() or None
        res.system_arch = self._system_arch()
        if platform.system() == "Darwin" and res.system_arch == "arm64" and res.python_arch == "x86_64":
            res.arch_mismatch = True
            res.warnings.append("frida_python_arch_mismatch")
            res.macos_hint = (
                "Apple Silicon host is arm64 but the current Python/Frida interpreter is x86_64. "
                "Use an arm64 Python virtualenv and install the official frida/frida-tools packages there."
            )

        try:
            import frida  # type: ignore[import-untyped]
            res.import_ok = True
            try:
                mod_path = inspect.getfile(frida)
                res.module_path = mod_path
                # Shadow detection: if module is directly in our workspace as frida/__init__.py or frida.py
                cwd = Path.cwd().resolve()
                try:
                    mod_resolved = Path(mod_path).resolve()
                    if str(mod_resolved).startswith(str(cwd)) and "site-packages" not in str(mod_resolved):
                        res.shadowed = True
                        res.shadow_path = str(mod_resolved)
                        res.local_shadow_candidates.append(str(mod_resolved))
                        res.warnings.append("frida_import_shadowed")
                        res.install_hint = "Rename local ./frida or frida.py; it shadows the official pip frida package."
                except Exception:
                    pass
            except TypeError:
                # Built-in namespace module => definitely shadowed if no __file__
                res.shadowed = True
                res.warnings.append("frida_import_shadowed")
                res.local_shadow_candidates.extend(str(path.resolve()) for path in Path.cwd().glob("frida*") if path.exists())
                res.install_hint = (
                    "Install the official frida package into the Python interpreter used by Transpect. "
                    "If import still resolves to a local ./frida namespace, rename that local directory."
                )

            res.version = getattr(frida, "__version__", None)
            res.has_attach = hasattr(frida, "attach")
            res.has_get_local_device = hasattr(frida, "get_local_device")
            
        except ImportError as e:
            res.import_ok = False
            res.errors.append(f"frida_import_failed: {e}")
            res.warnings.append("frida_import_failed")
            res.install_hint = "uv sync --extra frida"

        self._resolve_cli_tools(res)

        res.package_available = bool(
            res.import_ok and not res.shadowed and res.has_attach and res.has_get_local_device
        )
        res.available = res.package_available
        if res.arch_mismatch:
            res.install_hint = (
                "Create/use an arm64 Python environment before installing Frida, for example: "
                "CONDA_SUBDIR=osx-arm64 conda create -y -n transpect-frida-arm64 "
                "python=3.12 && conda activate transpect-frida-arm64 && "
                "uv sync --extra frida"
            )

        if not res.package_available:
            return res

        # Device & Process Enumeration
        import frida  # type: ignore[import-untyped]
        try:
            device = frida.get_local_device()
            device.enumerate_processes()
            res.has_enumerate_processes = True
            res.permission_status.can_enumerate_processes = True
        except Exception as e:
            err_str = str(e).lower()
            res.errors.append(f"frida_enumerate_processes_failed: {e}")
            res.warnings.append("frida_enumerate_processes_failed")
            if "permission" in err_str or "denied" in err_str or "not permitted" in err_str:
                res.permission_status.error = str(e)

        # macOS specific self-attach smoke test
        if platform.system() == "Darwin" and self_attach_check:
            res.permission_status.checked = True
            try:
                # Target self to verify task_for_pid / kernel auth
                session = frida.attach(os.getpid())
                session.detach()
                res.permission_status.can_attach_self = True
            except Exception as e:
                res.permission_status.can_attach_self = False
                err_str = str(e).lower()
                res.permission_status.error = str(e)
                if any(x in err_str for x in ["task_for_pid", "not permitted", "permission", "access denied"]):
                    res.permission_status.task_for_pid_likely_blocked = True
                    res.warnings.append("frida_task_for_pid_permission_required")
                    res.macos_hint = "Run from Terminal.app/iTerm2 and approve task_for_pid prompt if shown; for local tests you may try sudo. Avoid attaching protected system processes."
                elif "sip" in err_str or "system integrity protection" in err_str:
                    res.permission_status.sip_maybe_related = True
                    res.warnings.append("frida_sip_maybe_blocking")

        res.attach_ready = bool(
            res.package_available
            and res.has_enumerate_processes
            and not res.permission_status.task_for_pid_likely_blocked
            and not res.permission_status.sip_maybe_related
        )

        return res
