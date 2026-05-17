from __future__ import annotations

from compat.entrypoint import export_public, load_compat_module, run_compat_main

_IMPL = load_compat_module(
    module_name="capture.capture_frida",
    old_path="tools/capture_frida.py",
    new_path="tools/capture/capture_frida.py",
)
__all__ = export_public(_IMPL, globals())

if __name__ == "__main__":
    run_compat_main(_IMPL)
