from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="runtime.clean_runtime",
    old_path="scripts/clean_runtime.py",
    new_path="scripts/runtime/clean_runtime.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
