from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="runtime.setup_runtime",
    old_path="scripts/setup_runtime.py",
    new_path="scripts/runtime/setup_runtime.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
