"""Classifier family package.

Modules are discovered automatically; importing this package does not import
every classifier until :func:`load_all` is called.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import List

_LOADED = False
_LOAD_ERRORS: List[str] = []


def load_all() -> None:
    """Import every classifier module so decorators register them."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    for module_info in pkgutil.walk_packages(__path__, __name__ + "."):
        if module_info.name.endswith(".__init__"):
            continue
        try:
            importlib.import_module(module_info.name)
        except Exception as exc:  # a broken optional module must not break import
            _LOAD_ERRORS.append("%s: %s" % (module_info.name, exc))


def load_errors() -> List[str]:
    return list(_LOAD_ERRORS)


def reset() -> None:
    """Test helper: allow a fresh discovery pass."""
    global _LOADED
    _LOADED = False
    _LOAD_ERRORS.clear()
