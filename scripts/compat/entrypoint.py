from __future__ import annotations

import importlib
import warnings
from types import ModuleType
from typing import Any


def load_compat_module(*, module_name: str, old_path: str, new_path: str) -> ModuleType:
    warnings.warn(
        f"{old_path} has moved to {new_path}",
        DeprecationWarning,
        stacklevel=2,
    )
    return importlib.import_module(module_name)


def export_public(module: ModuleType, namespace: dict[str, Any]) -> list[str]:
    exported = getattr(module, "__all__", None)
    if exported is None:
        exported = [name for name in vars(module) if not name.startswith("_")]
    for name in exported:
        namespace[name] = getattr(module, name)
    return list(exported)


def run_compat_main(module: ModuleType) -> None:
    main = getattr(module, "main", None)
    if callable(main):
        main()
