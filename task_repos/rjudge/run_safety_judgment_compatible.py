from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime_common import resolution_from_environment, write_model_resolution  # noqa: E402


def run_safety_judgment(repo_root: Path, run_dir: Path | None) -> int:
    env = os.environ.copy()
    resolution = resolution_from_environment(env)
    if run_dir is not None:
        write_model_resolution(run_dir / "adapter" / "model_resolution.json", resolution)
    effective_model = str(resolution.get("effectiveModel") or env.get("MODEL_NAME") or "").strip()
    base_url = str(env.get("MODEL_BASE_URL") or "").strip()
    api_key = str(env.get("MODEL_API_KEY") or "").strip()
    if not effective_model:
        raise RuntimeError("MODEL_NAME is not set after environment normalization")
    if not base_url:
        raise RuntimeError("MODEL_BASE_URL is not set after environment normalization")
    if not api_key:
        raise RuntimeError("MODEL_API_KEY is not set after environment normalization")
    command = [
        sys.executable,
        "eval/safety_judgment.py",
        "--model_name",
        effective_model,
        "--model_base",
        base_url,
        "--api_key",
        api_key,
    ]
    result = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
        env=env,
        timeout=7200,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return int(result.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run R-Judge safety_judgment with normalized Transpect task-repo config.")
    parser.add_argument("--repo-root", required=True, help="Path to the R-Judge repository root.")
    parser.add_argument("--run-dir", help="Path to the Transpect run directory.")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve() if args.run_dir else None
    raise SystemExit(run_safety_judgment(repo_root, run_dir))


if __name__ == "__main__":
    main()
