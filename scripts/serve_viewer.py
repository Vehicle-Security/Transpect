from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="runtime.serve_viewer",
    old_path="scripts/serve_viewer.py",
    new_path="scripts/runtime/serve_viewer.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
