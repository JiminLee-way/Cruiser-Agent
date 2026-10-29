"""Exploration-direction task board: the watcher publishes directions, workers claim them (claiming erases them) and report back.

One file per challenge, reports/tasks_<code>.txt, line format:
    [t-xxxxxx] direction text (one line)
All reads and writes happen under a file lock; rewrites go through a temp file + atomic os.replace,
so when several workers claim the same direction concurrently only one succeeds.
"""
from __future__ import annotations

import fcntl
import os
import re
import time
import uuid
from typing import Optional

from .flagshape import redact

_MAX_PENDING = 5  # maximum number of pending directions on the board; nothing more is published beyond this
_TASK_LINE_RE = re.compile(r"^\[(t-[0-9a-f]{6})\]\s*(.*)$")
# Claim memory duration: a direction erased by a claim still takes part in dedup for this long (prevents the watcher from republishing it);
# it unfreezes automatically after the timeout, so a claimer dying abnormally does not lock the direction forever
_CLAIMED_TTL_S = 45 * 60


def _reports_dir() -> str:
    # located relative to the project root, independent of the caller's cwd
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "reports")


def _tasks_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"tasks_{code}.txt")


def _lock_path(code: str) -> str:
    return _tasks_path(code) + ".lock"


def _claimed_path(code: str) -> str:
    return _tasks_path(code) + ".claimed"


def _normalize(text: str) -> str:
    # lowercase + keep only letters/digits/CJK characters, removing differences in path separators, punctuation and whitespace
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", (text or "").lower())


def _bigrams(s: str) -> set[str]:
    if len(s) < 2:
        return {s} if s else set()
    return {s[i: i + 2] for i in range(len(s) - 1)}


def _similar(a: str, b: str) -> bool:
    """Normalized containment, or a character-bigram overlap coefficient >= 0.6, counts as the same direction."""
    na, nb = _normalize(a), _normalize(b)
    if not na or not nb:
        return False
    if na == nb or na in nb or nb in na:
        return True
    ba, bb = _bigrams(na), _bigrams(nb)
    if not ba or not bb:
        return False
    return len(ba & bb) / min(len(ba), len(bb)) >= 0.6


def _read_lines_unlocked(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]
    except Exception:
        return []


def _write_lines_atomic(path: str, lines: list[str]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")
    os.replace(tmp, path)


def list_tasks(code: str) -> list[dict]:
    """Return the list of pending directions: [{"id": "t-xxxxxx", "text": "..."}]."""
    if not code:
        return []
    out = []
    for ln in _read_lines_unlocked(_tasks_path(code)):
        m = _TASK_LINE_RE.match(ln.strip())
        if m:
            out.append({"id": m.group(1), "text": m.group(2).strip()})
    return out


def list_claimed(code: str, ttl_s: float = _CLAIMED_TTL_S) -> list[dict]:
    """Return recently claimed (in-progress) directions: [{"ts": int, "worker": str, "text": str}].

    Only records within the TTL are kept; older records are considered unfrozen and are not returned.
    """
    if not code:
        return []
    now = time.time()
    out = []
    for ln in _read_lines_unlocked(_claimed_path(code)):
        parts = ln.split("|", 2)
        if len(parts) != 3:
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        if now - ts <= ttl_s:
            out.append({"ts": ts, "worker": parts[1], "text": parts[2].strip()})
    return out


def publish_task(code: str, text: str) -> bool:
    """Watcher publishes a direction: deduplicated against "pending board + recently claimed"; nothing is published when the board is full (>=5).
    Returns whether anything was actually written."""
    text = redact(text).strip()
    if not code or not text:
        return False
    os.makedirs(_reports_dir(), exist_ok=True)
    with open(_lock_path(code), "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = _read_lines_unlocked(_tasks_path(code))
            existing = []
            for ln in lines:
                m = _TASK_LINE_RE.match(ln.strip())
                if m:
                    existing.append(m.group(2).strip())
            if len(existing) >= _MAX_PENDING:
                return False
            # dedup scope = pending + recently claimed (prevents the watcher from republishing after a claim erased it)
            pool = existing + [c["text"] for c in list_claimed(code)]
            if any(_similar(text, e) for e in pool):
                return False
            tid = f"t-{uuid.uuid4().hex[:6]}"
            lines.append(f"[{tid}] {text}")
            _write_lines_atomic(_tasks_path(code), lines)
            return True
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def claim_task(code: str, worker_id: str, task_id: Optional[str] = None) -> Optional[dict]:
    """Claim a direction: under the lock, find and erase the entry and return it; returns None if already claimed by someone else / not found.

    When task_id is empty, the first direction on the board is claimed.
    """
    if not code:
        return None
    os.makedirs(_reports_dir(), exist_ok=True)
    with open(_lock_path(code), "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = _read_lines_unlocked(_tasks_path(code))
            keep: list[str] = []
            claimed: Optional[dict] = None
            for ln in lines:
                m = _TASK_LINE_RE.match(ln.strip())
                if m and claimed is None and (task_id is None or m.group(1) == task_id):
                    claimed = {"id": m.group(1), "text": m.group(2).strip()}
                    continue  # erase
                keep.append(ln)
            if claimed is None:
                return None
            _write_lines_atomic(_tasks_path(code), keep)
            # write the claim log (also pruning expired records), used for publish dedup and as watcher reference
            claimed_lines = [
                f"{c['ts']}|{c['worker']}|{c['text']}"
                for c in list_claimed(code)
            ]
            claimed_lines.append(f"{int(time.time())}|{worker_id}|{claimed['text']}")
            _write_lines_atomic(_claimed_path(code), claimed_lines)
            return claimed
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def retire_task(code: str, ref: str) -> bool:
    """For watcher curation: remove a direction from the board. ref is matched exactly by task id (t-xxxxxx) first,
    otherwise by content similarity. Returns whether anything was actually removed."""
    ref = (ref or "").strip()
    if not code or not ref:
        return False
    os.makedirs(_reports_dir(), exist_ok=True)
    id_match = re.fullmatch(r"t-[0-9a-f]{6}", ref)
    with open(_lock_path(code), "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = _read_lines_unlocked(_tasks_path(code))
            keep: list[str] = []
            removed = False
            for ln in lines:
                m = _TASK_LINE_RE.match(ln.strip())
                if m and not removed:
                    if (id_match and m.group(1) == ref) or (not id_match and _similar(ref, m.group(2).strip())):
                        removed = True
                        continue
                keep.append(ln)
            if not removed:
                return False
            _write_lines_atomic(_tasks_path(code), keep)
            return True
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def report_task(code: str, worker_id: str, text: str, task: str = "") -> bool:
    """Report completion: written to the shared ledger (cruiser.ledger) as a task result, and shown in the blackboard view and the watcher input."""
    from . import ledger
    return ledger.add_result(code, worker_id, task, text) is not None
