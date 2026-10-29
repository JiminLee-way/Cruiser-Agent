"""Each session slot's engine session id is kept in reports/sessions_<code>.json, so after a stage switch the
same slot continues its conversation instead of starting over.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import time
import uuid
from typing import Callable, Literal, Optional, TypedDict, TypeVar

from .flagshape import PLACEHOLDER, redact

Kind = Literal["fact", "flag_method", "result"]


class StatusChange(TypedDict):
    ts: str
    status: str
    note: str
    by: str


class _EntryBase(TypedDict):
    id: str
    ts: str
    author: str
    text: str
    history: list[StatusChange]


class FactEntry(_EntryBase):
    kind: Literal["fact", "flag_method"]


class ResultEntry(_EntryBase):
    kind: Literal["result"]
    task: str


Entry = FactEntry | ResultEntry


_NEXT: dict[str, frozenset[str]] = {
    "open": frozenset({"verified", "disputed", "superseded"}),
    "verified": frozenset({"disputed", "superseded"}),
    "disputed": frozenset({"verified", "superseded"}),
    "superseded": frozenset(),
}
_STATUSES = frozenset().union(*_NEXT.values())
_FROZEN_KINDS = frozenset({"flag_method"})
_FACT_KINDS = ("fact", "flag_method")
_KIND_TAG = {"fact": "", "flag_method": "[flag-method] ", "result": "[task-result] "}
_STATUS_TAG = {"verified": "[verified] ", "disputed": "[disputed] "}
_ID_PREFIX = {"fact": "f", "flag_method": "f", "result": "r"}
_TEXT_CAP = {"fact": 400, "flag_method": 400, "result": 1500}
_NOTE_CAP = 300
_TASK_CAP = 200
_DIGEST_CAP = 1800
_LINE_CAP = 400
_DIGEST_HEAD = "[Solve state (maintained by the watcher from the whole ledger)]\n"
_ENTRIES_HEAD = "[Newest ledger entries]\n"

T = TypeVar("T")


def _reports_dir() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "reports")


def _ledger_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"ledger_{code}.json")


def _board_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"info_{code}.txt")


def _sessions_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"sessions_{code}.json")


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _flatten(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _clean(text: str, cap: int) -> str:
    s = redact(text).strip()[:cap].strip()
    return s if re.sub(r"[\W_]+", "", s.replace(PLACEHOLDER, "")) else ""


def _flag_index(text: str) -> str:
    for pattern in (r"progress\s*(\d+)\s*/\s*\d+", r"(?:flag|FLAG)\s*(\d+)", r"第\s*(\d+)\s*[枚个份]"):
        m = re.search(pattern, text or "")
        if m:
            return m.group(1)
    return ""


def _status(e: Entry) -> str:
    return e["history"][-1]["status"] if e["history"] else "open"


def _notes(e: Entry) -> list[str]:
    return [f"{h['status']}: {h['note']}" + (f" (by {h['by']})" if h["by"] else "")
            for h in e["history"] if h["note"]]


class _Ledger:
    def __init__(self, entries: list[Entry], digest: Optional[dict]):
        self.entries = entries
        self.digest = digest

    def document(self) -> dict:
        return {"entries": self.entries, "digest": self.digest}

    def find(self, entry_id: str) -> Optional[Entry]:
        return next((e for e in self.entries if e["id"] == entry_id), None)

    def live(self, kinds: tuple[str, ...] = tuple(_KIND_TAG)) -> list[Entry]:
        return [e for e in self.entries if e["kind"] in kinds and _status(e) != "superseded"]

    def same_text(self, kind: Kind, text: str, task: str) -> Optional[Entry]:
        group = ("result",) if kind == "result" else _FACT_KINDS
        return next((e for e in self.live(group) if _norm(e["text"]) == _norm(text) and e.get("task", "") == task), None)

    def same_flag(self, text: str) -> bool:
        key = _flag_index(text)
        return bool(key) and any(_flag_index(e["text"]) == key for e in self.live(("flag_method",)))


class _Writer(_Ledger):
    def __init__(self, led: _Ledger):
        super().__init__(led.entries, led.digest)
        self.changed = False

    def add(self, author: str, kind: Kind, text: str, task: str = "") -> Optional[str]:
        text = _clean(text, _TEXT_CAP[kind])
        task = _clean(task, _TASK_CAP) if kind == "result" else ""
        if not text or self.same_text(kind, text, task) or (kind == "flag_method" and self.same_flag(text)):
            return None
        eid = ""
        while not eid or self.find(eid):
            eid = f"{_ID_PREFIX[kind]}-{uuid.uuid4().hex[:6]}"
        entry: Entry = {"id": eid, "ts": _now(), "author": author, "kind": kind, "text": text, "history": []}
        if kind == "result":
            entry["task"] = task
        self.entries.append(entry)
        self.changed = True
        return eid

    def allows(self, e: Entry, status: str, note: str) -> bool:
        cur = _status(e)
        if status not in _STATUSES or e["kind"] in _FROZEN_KINDS or not _NEXT[cur]:
            return False
        if status == cur:
            return bool(note) and all(h["note"] != note for h in e["history"])
        return status in _NEXT[cur]

    def move(self, entry_id: str, status: str, note: str, by: str) -> bool:
        e = self.find(entry_id)
        note = _clean(note, _NOTE_CAP)
        if e is None or not self.allows(e, status, note):
            return False
        e["history"].append({"ts": _now(), "status": status, "note": note, "by": by})
        self.changed = True
        return True

    def supersede(self, entry_id: str, new_text: str, by: str) -> Optional[str]:
        old = self.find(entry_id)
        if old is None or not self.allows(old, "superseded", ""):
            return None
        kind, task = old["kind"], old.get("task", "")
        text = _clean(new_text, _TEXT_CAP[kind])
        if not text:
            return None
        same = self.same_text(kind, text, task)
        if same is old:
            return old["id"]
        target = same["id"] if same else self.add(by, kind, text, task)
        self.move(old["id"], "superseded", f"replaced by {target}", by)
        return target

    def set_digest(self, author: str, text: str) -> bool:
        text = _clean(text, _DIGEST_CAP)
        if not text or (self.digest or {}).get("text") == text:
            return False
        self.digest = {"ts": _now(), "author": author, "text": text}
        self.changed = True
        return True


def _load_strict(code: str) -> _Ledger:
    try:
        with open(_ledger_path(code), "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return _Ledger([], None)
    return _Ledger(doc["entries"], doc.get("digest"))


def _load_or_empty(code: str) -> _Ledger:
    try:
        return _load_strict(code)
    except (ValueError, KeyError, TypeError) as e:
        print(f"[Ledger] cannot read {_ledger_path(code)} ({e}); continuing without shared state", flush=True)
        return _Ledger([], None)


def _write_atomic(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _view_line(e: Entry) -> str:
    body = f"{e['task'][:80]} -> {e['text']}" if e.get("task") else e["text"]
    notes = _notes(e)
    tail = f" ({'; '.join(notes)})" if notes else ""
    return _flatten(f"{_KIND_TAG[e['kind']]}{_STATUS_TAG.get(_status(e), '')}{e['id']} {body}{tail}")


def _render(led: _Ledger) -> str:
    sep = "-" * 60
    return "".join(f"[{e['ts']}] session: {e['author']}\ninfo: {_view_line(e)}\n{sep}\n" for e in led.live())


def _commit(code: str, change: Callable[[_Writer], T]) -> T:
    os.makedirs(_reports_dir(), exist_ok=True)
    with open(_ledger_path(code) + ".lock", "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        led = _Writer(_load_strict(code))
        result = change(led)
        if led.changed:
            _write_atomic(_ledger_path(code), json.dumps(led.document(), ensure_ascii=False))
            _write_atomic(_board_path(code), _render(led))
        return result


def _public(e: Entry) -> dict:
    out = {"id": e["id"], "ts": e["ts"], "author": e["author"], "kind": e["kind"], "text": e["text"],
           "status": _status(e), "notes": _notes(e)}
    if e["kind"] == "result":
        out["task"] = e["task"]
    return out


def _entries(code: str, kinds: tuple[str, ...], include_superseded: bool) -> list[dict]:
    led = _load_or_empty(code)
    rows = [e for e in led.entries if e["kind"] in kinds] if include_superseded else led.live(kinds)
    return [_public(e) for e in rows]


def facts(code: str, include_superseded: bool = False) -> list[dict]:
    return _entries(code, _FACT_KINDS, include_superseded)


def results(code: str, include_superseded: bool = False) -> list[dict]:
    return _entries(code, ("result",), include_superseded)


def add_fact(code: str, author: str, text: str, kind: Kind = "fact") -> Optional[str]:
    if not code:
        return None
    return _commit(code, lambda led: led.add(author, kind, text))


def add_result(code: str, author: str, task: str, text: str) -> Optional[str]:
    if not code:
        return None
    return _commit(code, lambda led: led.add(author, "result", text, task))


def has_result(code: str, author: str, task: str) -> bool:
    task = _clean(task, _TASK_CAP)
    return any(e["kind"] == "result" and e["author"] == author and e["task"] == task for e in _load_or_empty(code).entries)


def set_status(code: str, entry_id: str, status: str, note: str = "", by: str = "") -> bool:
    return _commit(code, lambda led: led.move(entry_id, status, note, by))


def supersede(code: str, entry_id: str, new_text: str, by: str = "") -> Optional[str]:
    return _commit(code, lambda led: led.supersede(entry_id, new_text, by))


def set_digest(code: str, author: str, text: str) -> bool:
    if not code:
        return False
    return _commit(code, lambda led: led.set_digest(author, text))


def digest(code: str) -> str:
    return (_load_or_empty(code).digest or {}).get("text", "")


def _fit_context(digest_text: str, lines: list[str], budget: int) -> str:
    lines = [ln[:_LINE_CAP] for ln in lines]
    gap = "\n\n"
    want = len(_ENTRIES_HEAD) + sum(len(ln) + 1 for ln in lines) - 1 if lines else 0
    reserve = min(want, budget // 3)
    digest_part = ""
    if digest_text:
        room = budget - reserve - (len(gap) if reserve else 0)
        if room > len(_DIGEST_HEAD):
            digest_part = (_DIGEST_HEAD + digest_text)[:room]
    room = budget - len(digest_part) - (len(gap) if digest_part else 0)
    picked: list[str] = []
    used = len(_ENTRIES_HEAD) - 1
    for ln in reversed(lines):
        if used + len(ln) + 1 > room:
            break
        used += len(ln) + 1
        picked.append(ln)
    parts = [digest_part] if digest_part else []
    if picked:
        parts.append(_ENTRIES_HEAD + "\n".join(reversed(picked)))
    return gap.join(parts)


def context_text(code: str, budget: int = 3000) -> str:
    led = _load_or_empty(code)
    lines = ["- " + _view_line(e) for e in led.live()]
    return _fit_context((led.digest or {}).get("text", ""), lines, budget)


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


def session_set(code: str, slot: str, engine: str, session_id: str, ws: str = "") -> None:
    if code and slot and session_id:
        _update_sessions(code, lambda d: d.__setitem__(
            slot, {"engine": engine, "id": session_id, "ws": ws, "ts": int(time.time())}))


def session_clear(code: str, slot: str) -> None:
    """Forget a slot's engine session (e.g. resume failed), so the next session starts fresh."""
    if code and slot:
        _update_sessions(code, lambda d: d.pop(slot, None))
