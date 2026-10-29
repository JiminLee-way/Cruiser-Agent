#!/usr/bin/env python
"""Claude Code hook: force-inject the challenge description/hint/shared blackboard into the session context (without relying on the model to read them on its own).

- SessionStart: at session start, inject the challenge description + challenge hint + solving-state digest and latest ledger entries once (each if non-empty)
- PostToolUse: count tool calls and inject the latest content every 10 calls (roughly every 10 steps)

The challenge code comes from the CRUISER_CHALLENGE_CODE environment variable (already injected into worker/solver processes).
Outputs hookSpecificOutput.additionalContext; outputs nothing when there is nothing to inject.
"""
from __future__ import annotations

import json
import os
import sys

_MAX_INJECT_CHARS = 3000


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    event = payload.get("hook_event_name") or ""
    code = os.environ.get("CRUISER_CHALLENGE_CODE", "")
    if not code or event not in ("SessionStart", "PostToolUse"):
        return 0

    root = os.path.dirname(os.path.abspath(__file__))
    reports = os.path.join(root, "reports")
    def build_context() -> str:
        """Assemble the injected content: challenge description + challenge hint + solving-state digest and latest ledger entries (nothing is injected if all are empty)."""
        sys.path.insert(0, root)
        from cruiser.opencode_engine import context_block
        return context_block(reports, code)

    def emit(ctx: str) -> None:
        print(json.dumps(
            {"hookSpecificOutput": {"hookEventName": event, "additionalContext": ctx}},
            ensure_ascii=False,
        ))

    if event == "SessionStart":
        ctx = build_context()
        if ctx:
            emit(ctx)
        return 0

    # PostToolUse: inject once every 10 tool calls
    session = payload.get("session_id") or "unknown"
    counter_path = f"/tmp/cruiser_bbhook_{session}.count"
    try:
        with open(counter_path, "r") as f:
            n = int(f.read().strip()) + 1
    except Exception:
        n = 1
    try:
        with open(counter_path, "w") as f:
            f.write(str(n))
    except Exception:
        pass
    if n % 10 == 0:
        ctx = build_context()
        if ctx:
            emit(f"(The following is injected automatically every 10 steps; pay attention to and use new findings from other sessions)\n{ctx}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
