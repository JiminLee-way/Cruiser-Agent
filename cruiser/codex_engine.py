"""Codex solving engine (CRUISER_ENGINE=codex).

Replaces the claude CLI with a logged-in codex CLI (ChatGPT account):
- solving session: codex exec --json -s workspace-write -C <root> --add-dir <reports> <prompt>, stdin closed
  (otherwise codex waits for more input); writes are limited to the root and reports/, network is off by
  default; CRUISER_CODEX_SANDBOX=danger-full-access runs without a sandbox
- resume: the same slot continues its thread with `codex exec resume <thread_id>` (which takes sandbox
  settings only through -c overrides)
- event conversion: codex JSONL events become claude stream-json shaped events (system / assistant /
  user / result)
- watcher: WatcherLLM is a one-shot read-only codex exec offering invoke(messages).content

The challenge description, hint and shared solve state are injected like in the opencode engine.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Iterator, Optional

from . import opencode_engine as _opencode

NAME = "codex"
BINARY_NAME = "codex"
context_block = _opencode.context_block  # same session-start injection as the opencode engine
_DEFAULT_MODEL = "gpt-6-sol"
_DEFAULT_WATCHER_MODEL = "gpt-6-sol"


def enabled() -> bool:
    return (os.environ.get("CRUISER_ENGINE") or "").strip().lower() == "codex"


def solve_model() -> str:
    return (os.environ.get("CRUISER_CODEX_MODEL") or _DEFAULT_MODEL).strip()


def watcher_model() -> str:
    return (os.environ.get("CRUISER_CODEX_WATCHER_MODEL") or _DEFAULT_WATCHER_MODEL).strip()


def binary() -> str:
    path = shutil.which(BINARY_NAME)
    if not path:
        raise RuntimeError("codex CLI is not installed or not on PATH")
    return path


def _base_cmd(model: str, resume: bool = False) -> list[str]:
    cmd = [binary(), "exec"] + (["resume"] if resume else []) + ["--json", "--skip-git-repo-check", "-m", model]
    # Same as the Daybreak switch in the Codex app; on unless CRUISER_CODEX_DAYBREAK=0
    if (os.environ.get("CRUISER_CODEX_DAYBREAK") or "1").strip() != "0":
        cmd += ["-c", "daybreak=true"]
    effort = (os.environ.get("CRUISER_CODEX_EFFORT") or "").strip()
    if effort:
        cmd += ["-c", f'model_reasoning_effort="{effort}"']
    return cmd


def _full_access() -> bool:
    return (os.environ.get("CRUISER_CODEX_SANDBOX") or "").strip() == "danger-full-access"


def working_root(ws_dir: str) -> str:
    return os.environ.get("CRUISER_CODEX_ROOT") or ws_dir


def _writable_extra(root: str, *dirs: str) -> list[str]:
    return [d for d in dirs if d and os.path.abspath(d) != os.path.abspath(root)]


def session_cmd(prompt: str, system_prompt: str, context: str, *, ws_dir: str, reports_dir: str,
                model: Optional[str] = None) -> list[str]:
    message = system_prompt.strip() + "\n\n"
    if context:
        message += context + "\n\n"
    message += prompt
    root = working_root(ws_dir)
    if _full_access():
        return _base_cmd(model or solve_model()) + [
            "--dangerously-bypass-approvals-and-sandbox", "-C", root, message,
        ]
    cmd = _base_cmd(model or solve_model()) + ["-s", "workspace-write", "-C", root]
    for extra in _writable_extra(root, reports_dir, ws_dir):
        cmd += ["--add-dir", extra]
    if os.environ.get("CRUISER_CODEX_NETWORK") == "1":
        cmd += ["-c", "sandbox_workspace_write.network_access=true"]
    return cmd + [message]


def resume_cmd(session_id: str, prompt: str, *, ws_dir: str, reports_dir: str,
               model: Optional[str] = None) -> list[str]:
    cmd = _base_cmd(model or solve_model(), resume=True)
    if _full_access():
        cmd += ["--dangerously-bypass-approvals-and-sandbox"]
    else:
        root = working_root(ws_dir)
        roots = json.dumps([root] + _writable_extra(root, reports_dir, ws_dir))
        cmd += ["-c", 'sandbox_mode="workspace-write"', "-c", f"sandbox_workspace_write.writable_roots={roots}"]
        if os.environ.get("CRUISER_CODEX_NETWORK") == "1":
            cmd += ["-c", "sandbox_workspace_write.network_access=true"]
    return cmd + [session_id, prompt]


def claude_events(stdout) -> Iterator[dict]:
    """Convert the codex JSONL event stream to claude stream-json events; end at turn completion or exit."""
    for raw in stdout or []:
        line = raw.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except Exception:
            continue
        etype = evt.get("type") or ""
        item = evt.get("item") or {}
        itype = item.get("type") or ""
        if etype == "thread.started" and evt.get("thread_id"):
            yield {"type": "system", "subtype": "init", "session_id": evt["thread_id"]}
        elif etype == "item.started" and itype == "command_execution":
            yield {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "shell", "input": {"command": str(item.get("command") or "")}},
            ]}}
        elif etype == "item.completed":
            if itype == "agent_message":
                text = str(item.get("text") or "")
                if text.strip():
                    yield {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}
            elif itype == "command_execution":
                yield {"type": "user", "message": {"content": [
                    {"type": "tool_result", "content": str(item.get("aggregated_output") or "")},
                ]}}
            elif itype in ("file_change", "mcp_tool_call", "web_search"):
                yield {"type": "assistant", "message": {"content": [
                    {"type": "tool_use", "name": itype, "input": {}},
                ]}}
        elif etype == "turn.completed":
            yield {"type": "result", "subtype": "codex_turn_completed"}
            return
        elif etype in ("turn.failed", "error"):
            err = evt.get("error") or evt.get("message") or evt
            yield {"type": "result", "subtype": f"codex_error: {str(err)[:400]}"}
            return
    yield {"type": "result", "subtype": "codex_exit"}


class _Reply:
    def __init__(self, content: str):
        self.content = content


class WatcherLLM:
    """One-shot call for the watcher / [flag-method] writer: read-only sandbox, invoke(messages) -> obj.content."""

    def __init__(self, workspace: str, model: Optional[str] = None, timeout_s: float = 300.0):
        self.workspace = workspace
        self.model = model or watcher_model()
        self.timeout_s = timeout_s

    def invoke(self, messages) -> _Reply:
        prompt = "\n\n".join(str(getattr(m, "content", m)) for m in messages)
        cmd = _base_cmd(self.model) + ["-s", "read-only", "-C", self.workspace, prompt]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout_s,
                stdin=subprocess.DEVNULL,
            ).stdout
        except Exception:
            return _Reply("")
        texts = []
        for line in (out or "").splitlines():
            try:
                evt = json.loads(line)
            except Exception:
                continue
            item = evt.get("item") or {}
            if evt.get("type") == "item.completed" and item.get("type") == "agent_message":
                texts.append(str(item.get("text") or ""))
        return _Reply("\n".join(texts))
