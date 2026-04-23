from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="export.export_codetracer_bundle",
    old_path="scripts/export_codetracer_bundle.py",
    new_path="scripts/export/export_codetracer_bundle.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
