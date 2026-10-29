"""Solving-engine selection: CRUISER_ENGINE=opencode | codex; unset means the claude CLI (returns None)."""
from __future__ import annotations

import os
from types import ModuleType
from typing import Optional


def current() -> Optional[ModuleType]:
    from . import codex_engine, opencode_engine
    for eng in (opencode_engine, codex_engine):
        if eng.enabled():
            return eng
    return None


def child_env(cwd: str, base: Optional[dict] = None) -> dict:
    """Environment for a child started in the workspace cwd: opencode resolves its directory from $PWD,
    not the process cwd, and prompts point the agent at $CRUISER_WORKSPACE_DIR."""
    return {**(os.environ if base is None else base), "PWD": cwd, "CRUISER_WORKSPACE_DIR": cwd}
