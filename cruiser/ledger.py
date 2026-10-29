"""Shared fact ledger: append-only, never deleted; the blackboard text is rendered from it.

One reports/ledger_<code>.jsonl per challenge, with record types:
- fact    a new fact or lead: {"id": "f-xxxxxx", "author", "text", "kind"}
- status  a state change of an existing entry: {"target", "status": verified|disputed|superseded, "note", "by"}
- result  the conclusion of a directed task: {"id": "r-xxxxxx", "author", "task", "text"}
- digest  the full "solve state" rewritten by a watcher: {"author", "text"} (latest wins)

Entries are always referenced by id, never fuzzy-matched. A disputed entry keeps its text and the reason,
so other sessions can re-examine it; only superseded entries (replaced by a newer one) are hidden from the
rendered view. reports/info_<code>.txt remains a rendered view in the same format for the dashboard and
older readers.

Each session slot's engine session id is kept in reports/sessions_<code>.json, so after a stage switch the
same slot continues its conversation instead of starting over.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import time
import uuid
from typing import Optional

_DIGEST_MAX_CHARS = 3000
_STATUS_TAG = {"verified": "[verified] ", "disputed": "[disputed] "}


def _reports_dir() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "reports")


def _ledger_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"ledger_{code}.jsonl")


def _board_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"info_{code}.txt")


def _sessions_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"sessions_{code}.json")


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _read_records(code: str) -> list[dict]:
    out = []
    try:
        with open(_ledger_path(code), "r", encoding="utf-8") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    return out


def _append(code: str, record: dict, *, render: bool = True) -> None:
    os.makedirs(_reports_dir(), exist_ok=True)
    record = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), **record}
    with open(_ledger_path(code) + ".lock", "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            with open(_ledger_path(code), "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            if render:
                _render_board_unlocked(code)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def facts(code: str, include_superseded: bool = False) -> list[dict]:
    """Materialized entries: [{id, ts, author, text, kind, status, notes}], in write order."""
    by_id: dict[str, dict] = {}
    order: list[str] = []
    for r in _read_records(code):
        if r.get("type") == "fact" and r.get("id"):
            by_id[r["id"]] = {
                "id": r["id"], "ts": r.get("ts", ""), "author": r.get("author", ""),
                "text": r.get("text", ""), "kind": r.get("kind", "fact"),
                "status": "open", "notes": [],
            }
            order.append(r["id"])
        elif r.get("type") == "status" and r.get("target") in by_id:
            f = by_id[r["target"]]
            f["status"] = r.get("status") or f["status"]
            if r.get("note"):
                f["notes"].append(f"{r.get('status')}: {r['note']} (by {r.get('by', '')})")
    out = [by_id[i] for i in order]
    if not include_superseded:
        out = [f for f in out if f["status"] != "superseded"]
    return out


def add_fact(code: str, author: str, text: str, kind: str = "fact") -> Optional[str]:
    """Append an entry; skipped when an existing, non-superseded entry has the same (normalized) text."""
    text = (text or "").strip()
    if not code or not text:
        return None
    if any(_norm(f["text"]) == _norm(text) for f in facts(code)):
        return None
    fid = f"f-{uuid.uuid4().hex[:6]}"
    _append(code, {"type": "fact", "id": fid, "author": author, "text": text, "kind": kind})
    return fid


def set_status(code: str, fact_id: str, status: str, note: str = "", by: str = "") -> bool:
    if status not in ("verified", "disputed", "superseded"):
        return False
    if not any(f["id"] == fact_id for f in facts(code, include_superseded=True)):
        return False
    _append(code, {"type": "status", "target": fact_id, "status": status, "note": (note or "").strip(), "by": by})
    return True


def supersede(code: str, fact_id: str, new_text: str, by: str = "") -> Optional[str]:
    """Replace an entry with a new one: the old entry stays in the ledger and is only hidden from the view."""
    new_id = add_fact(code, by, new_text)
    if new_id:
        set_status(code, fact_id, "superseded", f"replaced by {new_id}", by)
    return new_id


def add_result(code: str, author: str, task: str, text: str) -> Optional[str]:
    text = (text or "").strip()
    if not code or not text:
        return None
    rid = f"r-{uuid.uuid4().hex[:6]}"
    _append(code, {"type": "result", "id": rid, "author": author, "task": (task or "").strip(), "text": text})
    return rid


def results(code: str, limit: int = 20) -> list[dict]:
    return [r for r in _read_records(code) if r.get("type") == "result"][-limit:]


def set_digest(code: str, author: str, text: str) -> None:
    text = (text or "").strip()
    if code and text:
        _append(code, {"type": "digest", "author": author, "text": text[:_DIGEST_MAX_CHARS]}, render=False)


def digest(code: str) -> str:
    for r in reversed(_read_records(code)):
        if r.get("type") == "digest":
            return r.get("text", "")
    return ""


def _render_board_unlocked(code: str) -> None:
    """Render info_<code>.txt (same format as the old blackboard); status and dispute reasons go into the text."""
    sep = "-" * 60
    lines = []
    for f in facts(code):
        note = f" ({'; '.join(f['notes'])})" if f["notes"] else ""
        lines.append(f"[{f['ts']}] session: {f['author']}\n"
                     f"info: {_STATUS_TAG.get(f['status'], '')}{f['id']} {f['text']}{note}\n{sep}\n")
    for r in results(code, limit=50):
        lines.append(f"[{r.get('ts', '')}] session: {r.get('author', '')}\n"
                     f"info: [task-result] {r.get('id')} {r.get('task', '')[:80]} -> {r.get('text', '')}\n{sep}\n")
    tmp = _board_path(code) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("".join(lines))
    os.replace(tmp, _board_path(code))


def context_text(code: str, budget: int = 3000) -> str:
    """Text injected at session start: the solve-state digest first, remaining budget for the newest entries."""
    parts = []
    d = digest(code)
    if d:
        parts.append(f"[Solve state (maintained by the watcher from the whole ledger)]\n{d}")
    rest = budget - sum(len(p) for p in parts)
    if rest > 300:
        recent: list[str] = []
        for f in reversed(facts(code)):
            item = f"- {_STATUS_TAG.get(f['status'], '')}{f['id']} {f['text']}"
            if sum(len(x) + 1 for x in recent) + len(item) > rest - 40:
                break
            recent.append(item)
        if recent:
            parts.append("[Newest ledger entries]\n" + "\n".join(reversed(recent)))
    return "\n\n".join(parts)


def session_get(code: str, slot: str) -> Optional[dict]:
    try:
        with open(_sessions_path(code), "r", encoding="utf-8") as f:
            return (json.load(f) or {}).get(slot)
    except Exception:
        return None


def _update_sessions(code: str, mutate) -> None:
    os.makedirs(_reports_dir(), exist_ok=True)
    path = _sessions_path(code)
    with open(path + ".lock", "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f) or {}
            except Exception:
                data = {}
            mutate(data)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def session_set(code: str, slot: str, engine: str, session_id: str) -> None:
    if code and slot and session_id:
        _update_sessions(code, lambda d: d.__setitem__(slot, {"engine": engine, "id": session_id, "ts": int(time.time())}))


def session_clear(code: str, slot: str) -> None:
    """Forget a slot's engine session (e.g. resume failed), so the next session starts fresh."""
    if code and slot:
        _update_sessions(code, lambda d: d.pop(slot, None))
