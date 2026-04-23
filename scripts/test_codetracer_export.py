from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="validate.test_codetracer_export",
    old_path="scripts/test_codetracer_export.py",
    new_path="scripts/validate/test_codetracer_export.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
