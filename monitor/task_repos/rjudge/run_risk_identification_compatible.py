from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime_common import (  # noqa: E402
    ensure_risk_identification_input,
    load_module_from_path,
    resolution_from_environment,
    write_model_resolution,
)


def run_risk_identification(repo_root: Path, run_dir: Path | None) -> int:
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
    seed_info = ensure_risk_identification_input(repo_root, effective_model)
    print(f"Prepared risk identification input from {seed_info['source']} at {seed_info['path']}")
    os.environ["API_KEY"] = api_key
    module = load_module_from_path("transpect_rjudge_risk_identification", repo_root / "eval" / "risk_identification.py")
    module.MODEL2RPM = {effective_model: 200}
    module.MODEL2BASE = {effective_model: base_url}
    module.API_KEY = api_key
    original_mkdir = module.os.mkdir

    def safe_mkdir(path: str | bytes, mode: int = 0o777) -> None:
        normalized = os.path.normpath(os.fspath(path))
        if normalized in {"eval", ".\\eval", "./eval"}:
            return
        original_mkdir(path, mode)

    module.os.mkdir = safe_mkdir
    cwd_before = Path.cwd()
    try:
        os.chdir(repo_root)
        module.main()
    finally:
        module.os.mkdir = original_mkdir
        os.chdir(cwd_before)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run R-Judge risk_identification with normalized Transpect task-repo config.")
    parser.add_argument("--repo-root", required=True, help="Path to the R-Judge repository root.")
    parser.add_argument("--run-dir", help="Path to the Transpect run directory.")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve() if args.run_dir else None
    raise SystemExit(run_risk_identification(repo_root, run_dir))


if __name__ == "__main__":
    main()
