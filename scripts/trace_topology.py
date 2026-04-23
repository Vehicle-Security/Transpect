from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="validate.trace_topology",
    old_path="scripts/trace_topology.py",
    new_path="scripts/validate/trace_topology.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
