"""Solving-engine selection: CRUISER_ENGINE=opencode | codex; unset means the claude CLI (returns None)."""
from __future__ import annotations

from types import ModuleType
from typing import Optional


def current() -> Optional[ModuleType]:
    from . import codex_engine, opencode_engine
    for eng in (opencode_engine, codex_engine):
        if eng.enabled():
            return eng
    return None
