"""OpenCode solving engine (CRUISER_ENGINE=opencode).

Replaces the claude CLI with a logged-in opencode CLI (`opencode auth login`, e.g. an OpenCode Go plan):
- solving session: opencode run --standalone --auto --format json -m <model> <prompt>
- event conversion: opencode JSON events become claude stream-json shaped events (system / assistant /
  user / result), so step counting, flag-candidate extraction and the watcher activity digest are reused
- resume: the same slot continues its conversation with `--session <id>`
- watcher: OpencodeLLM offers the langchain-style invoke(messages).content interface

opencode has no PostToolUse hook like claude, so the challenge description, hint and shared solve state
are written into the prompt at the start of each session (and of each resumed session).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Iterator, Optional

NAME = "opencode"
BINARY_NAME = "opencode"
_DEFAULT_MODEL = "opencode-go/deepseek-v4.1-flash"
_DEFAULT_WATCHER_MODEL = "opencode-go/deepseek-v4-pro"
_MAX_INJECT_CHARS = 3000


def enabled() -> bool:
    return (os.environ.get("CRUISER_ENGINE") or "").strip().lower() == "opencode"


def solve_model() -> str:
    return (os.environ.get("CRUISER_OPENCODE_MODEL") or _DEFAULT_MODEL).strip()


def watcher_model() -> str:
    return (os.environ.get("CRUISER_OPENCODE_WATCHER_MODEL") or _DEFAULT_WATCHER_MODEL).strip()


def binary() -> str:
    path = shutil.which(BINARY_NAME)
    if not path:
        raise RuntimeError("opencode CLI is not installed or not on PATH")
    return path


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def context_block(reports_dir: str, code: str) -> str:
    """Session-start injection shared by blackboard_hook.py and all engines:
    challenge description + hint + solve-state digest and latest ledger entries."""
    if not code:
        return ""
    parts = []
    desc = _read(os.path.join(reports_dir, f"desc_{code}.txt"))
    if desc:
        parts.append(f"[Challenge description]\n{desc[:_MAX_INJECT_CHARS]}")
    hint = _read(os.path.join(reports_dir, f"hint_{code}.txt"))
    if hint:
        parts.append(f"[Challenge hint (obtained at a score cost; use it fully)]\n{hint[:_MAX_INJECT_CHARS]}")
    from . import ledger
    shared = ledger.context_text(code, budget=_MAX_INJECT_CHARS)
    if shared:
        parts.append(shared)
    return "\n\n".join(parts)


def _run_cmd(message: str, model: Optional[str], session_id: Optional[str] = None) -> list[str]:
    cmd = [binary(), "run", "--standalone", "--auto", "--format", "json", "-m", model or solve_model()]
    if session_id:
        cmd += ["--session", session_id]
    return cmd + [message]


def session_cmd(prompt: str, system_prompt: str, context: str, model: Optional[str] = None, **_) -> list[str]:
    message = system_prompt.strip() + "\n\n"
    if context:
        message += context + "\n\n"
    return _run_cmd(message + prompt, model)


def resume_cmd(session_id: str, prompt: str, model: Optional[str] = None, **_) -> list[str]:
    return _run_cmd(prompt, model, session_id)


def claude_events(stdout) -> Iterator[dict]:
    """Convert the opencode JSON event stream to claude stream-json events; add a result at process exit."""
    announced = False
    for raw in stdout or []:
        line = raw.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except Exception:
            continue
        if not announced and evt.get("sessionID"):
            announced = True
            yield {"type": "system", "subtype": "init", "session_id": evt["sessionID"]}
        etype = evt.get("type")
        part = evt.get("part") or {}
        if etype == "text":
            text = str(part.get("text") or "")
            if text.strip():
                yield {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}
        elif etype == "tool_use":
            state = part.get("state") or {}
            inp = state.get("input") if isinstance(state.get("input"), dict) else {}
            yield {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": str(part.get("tool") or "?"), "input": inp},
            ]}}
            output = state.get("output")
            if output is not None:
                yield {"type": "user", "message": {"content": [
                    {"type": "tool_result", "content": str(output)},
                ]}}
        elif etype == "error":
            err = evt.get("error") or part
            yield {"type": "result", "subtype": f"opencode_error: {str(err)[:400]}"}
            return
    yield {"type": "result", "subtype": "opencode_exit"}


class _Reply:
    def __init__(self, content: str):
        self.content = content


class OpencodeLLM:
    """One-shot call for the watcher / [flag-method] writer: invoke(messages) -> obj.content."""

    def __init__(self, workspace: str, model: Optional[str] = None, timeout_s: float = 240.0):
        self.workspace = workspace
        self.model = model or watcher_model()
        self.timeout_s = timeout_s

    def invoke(self, messages) -> _Reply:
        from .engines import child_env
        prompt = "\n\n".join(str(getattr(m, "content", m)) for m in messages)
        cmd = [binary(), "run", "--standalone", "--format", "json", "-m", self.model, prompt]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout_s,
                cwd=self.workspace, env=child_env(self.workspace),
            ).stdout
        except Exception:
            return _Reply("")
        texts = []
        for line in (out or "").splitlines():
            try:
                evt = json.loads(line)
            except Exception:
                continue
            if evt.get("type") == "text":
                texts.append(str((evt.get("part") or {}).get("text") or ""))
        return _Reply("\n".join(texts))


WatcherLLM = OpencodeLLM
