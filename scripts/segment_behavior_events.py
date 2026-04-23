from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="diagnosis.segment_behavior_events",
    old_path="scripts/segment_behavior_events.py",
    new_path="scripts/diagnosis/segment_behavior_events.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
