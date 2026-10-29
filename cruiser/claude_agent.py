"""Claude Code driven auto-scan engine (replaces the hand-written ReAct loop).

Runs an autonomous agent through the claude CLI's stream-json mode:
- every assistant event counts as one step and prints [COUNT] n (used by the main.py scheduler for step-threshold monitoring; semantics unchanged)
- the shared key-information blackboard mechanism is unchanged: the files, format and read/write timing of reports/info_<code>.txt and hint_<code>.txt
  are all defined by the prompts; Claude Code reads and writes them directly with its own file tools
- a flag must be confirmed through tools/submit_flag.py (local challenge platform cruiser/challenges.py) before the final JSON is output
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage

from .llm import get_claude_provider_env, get_watcher_llm
from .prompt import (
    CLAUDE_SOLVER_SYSTEM_PROMPT,
    CLAUDE_SOLVER_TASK_TEMPLATE,
    CLAUDE_SYSTEM_PROMPT,
    CLAUDE_TASK_TEMPLATE,
)

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except Exception:
        return default


# Watcher visibility window (covers about 20-24 turns by default; can be enlarged via environment variables)
_WATCHER_RECENT_MAX = max(12, _env_int("CRUISER_WATCHER_RECENT", 48))
_WATCHER_EVERY = max(1, _env_int("CRUISER_WATCHER_EVERY", 4))
_WATCHER_THOUGHT_CHARS = max(200, _env_int("CRUISER_WATCHER_THOUGHT_CHARS", 800))
_WATCHER_OBS_CHARS = max(400, _env_int("CRUISER_WATCHER_OBS_CHARS", 1600))
_WATCHER_ACTIVITY_CHARS = max(4000, _env_int("CRUISER_WATCHER_ACTIVITY_CHARS", 24000))
_WATCHER_BB_CHARS = max(4000, _env_int("CRUISER_WATCHER_BB_CHARS", 12000))
_WATCHER_TASKS_CHARS = 3000
_WATCHER_CLAIMED_CHARS = 2500
_WATCHER_DESC_CHARS = 2500
_WATCHER_HINT_CHARS = 2500
_WATCHER_FULL_ITEMS = 12  # this many most recent activity items keep their full text; older ones are compressed to short snippets to free up history window


# Maximum turns per Claude session (claude's "turn" count, passed via --max-turns; note turn != the log's [COUNT],
# [COUNT] counts every assistant event and is several times the turn count): <=0 means unlimited (--max-turns is not passed to claude),
# letting the scheduler's step threshold / flag confirmation / context limit bound it naturally. Override with CRUISER_MAX_TURNS (default 0 = unlimited).
def _max_turns_per_session() -> int:
    try:
        return int(os.environ.get("CRUISER_MAX_TURNS", "0") or "0")
    except Exception:
        return 0


# External confirmation markers of a successful flag submission (kept consistent with tools.submit_flag output)
_FLAG_OK_MARKERS = ("FLAG CORRECT", "ALREADY SUBMITTED")
# Only accept an actual "invocation" submit_flag.py CODE FLAG, not the file name merely appearing in a path (e.g. grep .../submit_flag.py)
_SUBMIT_INVOKE_RE = re.compile(
    r"""(?:^|[\s;|&])(?:\S*/)?submit_flag\.py\s+([A-Za-z0-9]+-\d+)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&><`]+))"""
)
# flag{...}-shaped candidate extraction
# Only extract "real-flag-like wrapper + content": reject snippets like startswith('flag{') in source code running to the next }
_FLAG_PATTERN_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_+\-./:=]{8,300}\}")


# More than this many flag{...} in one text blob is treated as brute-force/enumeration output and is never auto-submitted.
# Slightly above 2: in multi-flag challenges a single cat often prints 3-5 flags, which should not be skipped wholesale.
_AUTO_SUBMIT_MAX_PER_BLOB = 5
_PROGRESS_RE = re.compile(r"flag progress\s*(\d+)/(\d+)")


def _unique_flag_cands(text: str) -> list[str]:
    """Extract deduplicated valid flag candidates from a text, preserving order of appearance."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _FLAG_PATTERN_RE.findall(text or ""):
        if not _looks_like_flag(m) or m in seen:
            continue
        seen.add(m)
        out.append(m)
    return out


def _looks_like_flag(s: str) -> bool:
    """Hot-path static check (delegates to tools.looks_flaglike_static, no IO):
    shape + placeholders + HTML/CSS/JS blacklist. For submission decisions use tools.looks_flaglike (includes prefix learning)."""
    from .tools import looks_flaglike_static
    return looks_flaglike_static(s)


def _submit_flag_directly(code: str, flag: str):
    """Submit a flag programmatically and return a FlagSubmitOutcome.

    Only automatic submissions go through here; the charset restriction applies only at this layer and does not block the model calling submit_flag.py itself.
    """
    from .tools import FlagSubmitOutcome, looks_flaglike, submit_flag_outcome
    if not code or not flag or not looks_flaglike(flag):
        return FlagSubmitOutcome()
    try:
        return submit_flag_outcome(code, flag)
    except Exception:
        return FlagSubmitOutcome(definitive=False)


def _flags_all_collected(correct: int, total: int) -> bool:
    from .tools import flags_all_collected
    return flags_all_collected(correct, total)


def _progress_from_text(text: str) -> tuple[int, int]:
    m = _PROGRESS_RE.search(text or "")
    if not m:
        return 0, 0
    try:
        return int(m.group(1)), int(m.group(2))
    except Exception:
        return 0, 0


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Blackboard watcher: inside each worker process an LLM periodically reviews recent activity and the current blackboard,
# and appends new information worth sharing in the agreed format (guaranteed by the mechanism, not relying on Claude's own initiative).
# ---------------------------------------------------------------------------
_WATCHER_SYSTEM = (
    "You are the ledger keeper and integrator for CTF solving. The shared ledger is append-only, never deleted: you cannot delete any entry, "
    "you can only mark an entry's status (verified = confirmed / disputed = questionable / superseded = replaced by a newer entry). "
    "Duties: extract new concrete facts and leads from one session's recent activity; mark verified based on reproduction results, mark disputed based on counter-evidence and state the reason "
    "(the entry is kept together with the reason, for other sessions to re-check); rewrite the complete \"solving state\" digest based on the whole ledger and the task results; "
    "recommend exploration directions that correspond to the open items in the digest. "
    "Never write a concrete flag value into the ledger (there is a fallback auto-submission, so a wrong flag would be submitted again and again). "
    "Do not modify or question [flag-method] entries -- they are written separately by the submitting session on its first successful submission. "
    "Output only JSON, nothing else."
)

_WATCHER_PROMPT_TEMPLATE = (
    "[Ledger entries (id status author content)]\n{blackboard}\n\n"
    "[Directed task results]\n{results}\n\n"
    "[Exploration directions currently waiting to be claimed]\n{tasks}\n"
    "[Directions in progress (already claimed by other sessions)]\n{claimed_tasks}\n\n"
    "[Current solving-state digest]\n{digest}\n\n"
    "[This session's recent activity summary]\n{activity}\n\n"
    "Rules:\n"
    "1. add: new, reusable concrete facts or leads (addresses, constants, parameters, files, candidate values, verified methods, artifact file paths, etc.); "
    "write ones that have a concrete value but are not yet confirmed as \"lead: ...\"; at most 120 characters each, at most 3 per call; do not repeat what the ledger already has; "
    "do not record basic information such as server fingerprints or version numbers (unless tied to a specific vulnerability); do not hard-code concrete IP:port (it changes when the container restarts), write endpoints only as relative paths or logical names; "
    "[Never write concrete flag values] never write flag{{...}}, FLAG{{...}} or any other flag-like string;\n"
    "2. verify: ids of entries reproduced or confirmed by replay in the recent activity;\n"
    "3. dispute: entries refuted by the recent activity or considered not applicable [{{\"id\": \"f-...\", \"reason\": \"...\"}}]; "
    "entries are never deleted -- concrete values in a disputed entry may still be key leads, so state the basis of the reason clearly;\n"
    "4. supersede: entries whose content needs correcting or completing [{{\"id\": \"f-...\", \"new\": \"the complete corrected content\"}}];\n"
    "5. digest: rewrite the complete digest (not a delta) based on all ledger entries and task results, with fixed sections: "
    "goal and success criteria / verified conclusions / open leads (list every concrete-value lead and open question not yet conclusively refuted, including disputed entries)"
    " / key artifacts (file paths) / next integration actions (which known conclusions combined can advance to the flag); at most 2000 characters; "
    "return an empty string when there is no substantive change from the current digest;\n"
    "6. suggest_tasks: [{{\"text\": \"a one-sentence actionable direction\", \"basis\": \"the corresponding open lead or entry id\"}}]; "
    "do not publish directions unrelated to the open items in the digest; if the challenge hint gives ordered steps, a direction must map to one of those steps; "
    "do not repeat ones already pending or in progress; at most 2 per call;\n"
    "7. retire_tasks: ids (t-xxxxxx) of pending directions that are duplicates, already done, or unrelated to the open items;\n"
    "8. return empty for fields with no change.\n"
    'Output strictly JSON: {{"add": [], "verify": [], "dispute": [{{"id": "", "reason": ""}}], '
    '"supersede": [{{"id": "", "new": ""}}], "digest": "", '
    '"suggest_tasks": [{{"text": "", "basis": ""}}], "retire_tasks": []}}'
)

_WATCHER_LLM = None
_WATCHER_LLM_LOCK = threading.Lock()


def _get_watcher_llm():
    """Watcher-only LLM singleton (uses DeepSeek deepseek-v4-pro; can be overridden via WATCHER_MODEL)."""
    global _WATCHER_LLM
    if _WATCHER_LLM is None:
        with _WATCHER_LLM_LOCK:
            if _WATCHER_LLM is None:
                from . import engines
                eng = engines.current()
                if eng is not None:
                    llm, provider = eng.WatcherLLM(), f"{eng.NAME}:{eng.watcher_model()}"
                else:
                    llm, provider, _ = get_watcher_llm()
                _WATCHER_LLM = llm
                try:
                    print(f"[Watcher] backend model: {provider}", flush=True)
                except Exception:
                    pass
    return _WATCHER_LLM


def _strip_flag_literals(text: str) -> str:
    """Strip concrete flag strings so that, once written to the blackboard, they are not repeatedly sent to the platform by the fallback submission."""
    return _FLAG_PATTERN_RE.sub("<flag>", text or "")


def _format_watcher_activity(recent: deque[str] | list[str], budget: int = _WATCHER_ACTIVITY_CHARS) -> str:
    """Build the watcher activity window: the most recent items in full, older ones shortened (keeping a head and tail), all within budget."""
    items = [x for x in recent if x]
    if not items:
        return ""

    def _compress(x: str, n: int = 240) -> str:
        s = re.sub(r"\s+", " ", x).strip()
        if len(s) <= n:
            return s
        head = n // 2 - 2
        return s[:head] + "..." + s[-(n - head - 3):]

    keep = min(_WATCHER_FULL_ITEMS, len(items))
    if len(items) > keep:
        text = "\n".join([_compress(x) for x in items[:-keep]] + items[-keep:])
    else:
        text = "\n".join(items)
    return text[-budget:] if len(text) > budget else text


def _is_flag_method(info: str) -> bool:
    return (info or "").lstrip().startswith("[flag-method]")


def _flag_method_key(info: str) -> str:
    """Key of the method entry for one flag ('1', '2', ...). Empty string if it cannot be determined."""
    text = info or ""
    m = re.search(r"progress\s*(\d+)\s*/\s*\d+", text)
    if m:
        return m.group(1)
    m = re.search(r"(?:flag|FLAG)\s*(\d+)", text)
    if m:
        return m.group(1)
    m = re.search(r"第\s*(\d+)\s*[枚个份]", text)
    if m:
        return m.group(1)
    return ""


def _flag_method_dbg(msg: str) -> None:
    try:
        print(f"\x1b[96;1m[flag-method DEBUG]\x1b[0m {msg}", flush=True)
    except Exception:
        pass


def _append_blackboard_info(code: str, worker_id: str, info: str) -> bool:
    """Append an entry to the shared ledger ([flag-method] is written only once per progress key). Returns True if written."""
    from . import ledger
    info = (info or "").strip()
    if not code or not info:
        _flag_method_dbg(f"append rejected: code={code!r} info_empty={not info} worker={worker_id}")
        return False
    try:
        kind = "flag_method" if _is_flag_method(info) else "fact"
        if kind == "flag_method":
            key = _flag_method_key(info)
            if key and any(
                f["kind"] == "flag_method" and _flag_method_key(f["text"]) == key for f in ledger.facts(code)
            ):
                _flag_method_dbg(f"append skipped: a [flag-method] already exists for progress key={key}")
                return False
        fid = ledger.add_fact(code, worker_id, info, kind=kind)
        _flag_method_dbg(f"append result id={fid} worker={worker_id} kind={kind}")
        return fid is not None
    except Exception as e:
        _flag_method_dbg(f"append error err={type(e).__name__}: {e}")
        return False


_FLAG_METHOD_WRITER_PROMPT = (
    "Based on the activity summary below, from when the session just obtained the flag, write a method for obtaining it that other sessions can reproduce.\n"
    "Progress: {prog}\n"
    "Output only one line, no markdown, no concrete flag value:\n"
    "[flag-method] progress {prog}. vulnerable point + request/path/command + key steps (at most 200 characters)\n\n"
    "Activity summary:\n{activity}\n"
)

_FLAG_METHOD_SPAWNED: "set[str]" = set()
_FLAG_METHOD_SPAWNED_LOCK = threading.Lock()


def _compose_flag_method(prog: str, activity: str) -> str:
    """Condense the activity summary into one complete [flag-method] entry in a single call; falls back to a compressed summary when the LLM is unavailable."""
    activity = _strip_flag_literals(activity or "")
    llm = _get_watcher_llm()
    _flag_method_dbg(
        f"compose start prog={prog} llm={'yes' if llm is not None else 'None'} "
        f"activity_len={len(activity)}"
    )
    if llm is not None and activity.strip():
        try:
            prompt = (
                _FLAG_METHOD_WRITER_PROMPT
                .replace("{prog}", prog)
                .replace("{activity}", activity[-_WATCHER_ACTIVITY_CHARS:])
            )
            _flag_method_dbg(f"compose calling LLM prompt_len={len(prompt)}")
            resp = llm.invoke([
                SystemMessage(content="Output only one [flag-method] line, no flag value, nothing else."),
                HumanMessage(content=prompt),
            ])
            text = resp.content if isinstance(resp.content, str) else ""
            _flag_method_dbg(f"compose LLM returned type={type(resp.content).__name__} len={len(text or '')} head={(text or '')[:160]!r}")
            line = ""
            for raw in (text or "").splitlines():
                if "[flag-method]" in raw:
                    line = raw.strip()
                    break
            if not line and (text or "").strip():
                line = text.strip().splitlines()[0].strip()
            line = _strip_flag_literals(line)
            if line:
                if not _is_flag_method(line):
                    line = f"[flag-method] progress {prog}. {line}"
                _flag_method_dbg(f"compose LLM draft len={len(line[:400])}")
                return line[:400]
            _flag_method_dbg("compose LLM output unparseable, falling back to the summary")
        except Exception as e:
            _flag_method_dbg(f"compose LLM error {type(e).__name__}: {e}")
    snippet = re.sub(r"\s+", " ", activity).strip()[:800]
    if not snippet:
        _flag_method_dbg("compose failed: activity summary is empty and there is no LLM draft")
        return ""
    _flag_method_dbg(f"compose fallback summary len={len(snippet)}")
    return f"[flag-method] progress {prog}. {snippet}"


def _write_flag_method_once(code: str, worker_id: str, prog: str, activity: str) -> None:
    """Forked task: exits after writing one [flag-method] entry."""
    _flag_method_dbg(f"writer thread started worker={worker_id} prog={prog} activity_len={len(activity or '')} ident={threading.current_thread().name}")
    try:
        info = _compose_flag_method(prog, activity)
        if not info:
            _flag_method_dbg(f"writer exit: compose produced an empty draft worker={worker_id} prog={prog}")
            return
        ok = _append_blackboard_info(code, worker_id, info)
        _flag_method_dbg(f"writer append result ok={ok} worker={worker_id} prog={prog}")
        if ok:
            print(f"[flag-method] session {worker_id} written (progress {prog})", flush=True)
    except Exception as e:
        _flag_method_dbg(f"writer error worker={worker_id} prog={prog} {type(e).__name__}: {e}")


def _spawn_flag_method_writer(
    code: str, worker_id: str, correct: int, total: int, recent_items: list[str]
) -> Optional[threading.Thread]:
    """First successful submission: snapshot the activity and hand it to a one-shot thread that is discarded once done. Duplicate submissions never get here."""
    if not code:
        _flag_method_dbg(f"spawn rejected: no challenge code worker={worker_id}")
        return None
    prog = f"{correct}/{total}" if int(total or 0) >= 1 else (str(correct) if int(correct or 0) >= 1 else "?")
    key = f"{code}|{int(correct or 0)}|{int(total or 0)}"
    with _FLAG_METHOD_SPAWNED_LOCK:
        if key in _FLAG_METHOD_SPAWNED:
            _flag_method_dbg(f"spawn skipped: this process already forked key={key} worker={worker_id}")
            return None
        _FLAG_METHOD_SPAWNED.add(key)
    activity = _format_watcher_activity(recent_items)
    _flag_method_dbg(
        f"spawn starting thread worker={worker_id} key={key} prog={prog} "
        f"recent_n={len(recent_items)} activity_len={len(activity)}"
    )
    t = threading.Thread(
        target=_write_flag_method_once,
        args=(code, worker_id, prog, activity),
        daemon=True,
        name=f"flag-method-{worker_id}-{prog}",
    )
    t.start()
    _flag_method_dbg(f"spawn thread started alive={t.is_alive()} name={t.name}")
    return t


# Process-wide dedup of flags already attempted (prevents the watcher from resubmitting the same flag every time it fires)
_ATTEMPTED_FLAGS: "set[str]" = set()
_ATTEMPTED_FLAGS_LOCK = threading.Lock()


def _watcher_try_submit_flags(code: str, worker_id: str, *texts: str) -> Optional[str]:
    """Watcher fallback submission: extract flag{...} candidates from the given texts, dedupe within the process, and submit them programmatically.

    Submits every candidate in the batch (does not return just because the first one is correct); prints the final JSON only when platform progress is complete.
    Can be disabled with CRUISER_WATCHER_SUBMIT=0.
    """
    if os.environ.get("CRUISER_WATCHER_SUBMIT", "1") != "1" or not code:
        return None
    cands: "set[str]" = set()
    for t in texts:
        blob = _unique_flag_cands(t)
        # a pile of flags in one blob is brute-force output; do not auto-submit
        if len(blob) > _AUTO_SUBMIT_MAX_PER_BLOB:
            continue
        cands.update(blob)
    last_js: Optional[str] = None
    for cand in sorted(cands, key=len, reverse=True):
        key = f"{code}|{cand}"
        with _ATTEMPTED_FLAGS_LOCK:
            if key in _ATTEMPTED_FLAGS:
                continue
        outcome = _submit_flag_directly(code, cand)
        if outcome.definitive:
            with _ATTEMPTED_FLAGS_LOCK:
                _ATTEMPTED_FLAGS.add(key)
        if not outcome.ok:
            continue
        js = json.dumps({"flag": cand}, ensure_ascii=False)
        try:
            prog = f"{outcome.correct}/{outcome.total}" if outcome.total >= 1 else "?"
            print(
                f"\x1b[95;1m[WATCHER SUBMIT] session {worker_id} fallback submission accepted ({prog}): {cand}\x1b[0m",
                flush=True,
            )
        except Exception:
            pass
        if _flags_all_collected(outcome.correct, outcome.total):
            last_js = js
            try:
                print(js, flush=True)
            except Exception:
                pass
            return last_js
    return last_js


def _format_ledger_for_watcher(code: str) -> tuple[str, str]:
    """Watcher view of ledger entries and task results: (entries text, results text), keeping the newest part when over budget."""
    from . import ledger
    status_tag = {"verified": "verified", "disputed": "disputed", "open": "open"}
    rows = []
    for f in ledger.facts(code):
        note = f" ({'; '.join(f['notes'])})" if f["notes"] else ""
        rows.append(f"- {f['id']} [{status_tag.get(f['status'], f['status'])}] ({f['author']}) {f['text']}{note}")
    res = [f"- {r.get('id')} ({r.get('author')}) direction '{r.get('task', '')[:80]}' -> {r.get('text', '')[:400]}"
           for r in ledger.results(code, limit=12)]
    facts_text = "\n".join(rows) or "(empty)"
    return facts_text[-_WATCHER_BB_CHARS:], ("\n".join(res) or "(empty)")[-_WATCHER_TASKS_CHARS:]


def _watcher_curate_blackboard(code: str, worker_id: str, activity: str) -> None:
    """LLM reviews recent activity and the ledger: appends entries, marks statuses, rewrites the solving-state digest, publishes directions.

    The ledger is append-only (cruiser.ledger): entries are referenced by id, disputes/supersessions are recorded as statuses keeping the original text, with no fuzzy matching or deletion.
    Also: extracts flag candidates from recent activity + the blackboard view and submits them programmatically as a fallback (the watcher can submit flags too).
    """
    if not code or not activity.strip():
        return
    try:
        from . import ledger
        reports_dir = os.path.join(os.getcwd(), "reports")
        try:
            with open(os.path.join(reports_dir, f"info_{code}.txt"), "r", encoding="utf-8") as f:
                blackboard = f.read()
        except Exception:
            blackboard = ""
        # watcher fallback submission: runs before curation, so it can submit even without a usable watcher LLM
        _watcher_try_submit_flags(code, worker_id, activity, blackboard)
        llm = _get_watcher_llm()
        if llm is None:
            return
        facts_text, results_text = _format_ledger_for_watcher(code)
        from .taskboard import list_claimed, list_tasks, publish_task, retire_task
        pending_tasks = list_tasks(code)
        claimed_tasks = list_claimed(code)
        tasks_text = "\n".join(f"- [{t['id']}] {t['text']}" for t in pending_tasks) or "(empty)"
        claimed_text = "\n".join(f"- {c['text']} (in progress by session {c['worker']})" for c in claimed_tasks) or "(empty)"
        prompt = (
            _WATCHER_PROMPT_TEMPLATE
            .replace("{{", "{").replace("}}", "}")
            .replace("{activity}", activity[-_WATCHER_ACTIVITY_CHARS:])
            .replace("{blackboard}", facts_text)
            .replace("{results}", results_text)
            .replace("{digest}", ledger.digest(code) or "(none yet)")
            .replace("{tasks}", tasks_text[-_WATCHER_TASKS_CHARS:])
            .replace("{claimed_tasks}", claimed_text[-_WATCHER_CLAIMED_CHARS:])
        )
        # challenge description + hint (if fetched): lets the watcher use them to maintain the ledger and publish better-fitting exploration directions
        context_header = ""
        for name, label, limit in (("desc", "Challenge description", _WATCHER_DESC_CHARS), ("hint", "Challenge hint", _WATCHER_HINT_CHARS)):
            try:
                with open(os.path.join(reports_dir, f"{name}_{code}.txt"), "r", encoding="utf-8") as f:
                    body = f.read().strip()
                if body:
                    context_header += f"[{label}]\n{body[:limit]}\n\n"
            except Exception:
                pass
        resp = llm.invoke([
            SystemMessage(content=_WATCHER_SYSTEM),
            HumanMessage(content=context_header + prompt),
        ])
        text = resp.content if isinstance(resp.content, str) else json.dumps(resp.content, ensure_ascii=False)
        s, e = text.find("{"), text.rfind("}")
        if s == -1 or e == -1:
            return
        obj = json.loads(text[s: e + 1])

        def _items(key: str, n: int) -> list:
            v = obj.get(key) or []
            return v[:n] if isinstance(v, list) else []

        known = {f["id"]: f for f in ledger.facts(code, include_superseded=True)}
        editable = {i for i, f in known.items() if f["kind"] != "flag_method"}
        n_add = n_ver = n_dis = n_sup = 0
        for info in _items("add", 3):
            info = str(info).strip()
            if _FLAG_PATTERN_RE.search(info):
                continue  # an entry that is a flag-like literal carries no reusable fact
            if info and not _is_flag_method(info) and ledger.add_fact(code, worker_id, info):
                n_add += 1
        for fid in _items("verify", 5):
            if str(fid) in editable and ledger.set_status(code, str(fid), "verified", by=worker_id):
                n_ver += 1
        for d in _items("dispute", 3):
            if isinstance(d, dict) and str(d.get("id")) in editable and str(d.get("reason") or "").strip():
                if ledger.set_status(code, str(d["id"]), "disputed", _strip_flag_literals(str(d["reason"])), worker_id):
                    n_dis += 1
        for u in _items("supersede", 3):
            if isinstance(u, dict) and str(u.get("id")) in editable and str(u.get("new") or "").strip():
                if ledger.supersede(code, str(u["id"]), _strip_flag_literals(str(u["new"])), worker_id):
                    n_sup += 1
        new_digest = _strip_flag_literals(str(obj.get("digest") or "").strip())
        if new_digest:
            ledger.set_digest(code, worker_id, new_digest)

        published = retired = 0
        for t in _items("suggest_tasks", 2):
            t_text = str(t.get("text") if isinstance(t, dict) else t).strip()
            basis = str(t.get("basis") or "").strip() if isinstance(t, dict) else ""
            if not t_text:
                continue
            try:
                if publish_task(code, f"{t_text} (basis: {basis})" if basis else t_text):
                    published += 1
            except Exception:
                pass
        for r in _items("retire_tasks", 3):
            try:
                if retire_task(code, str(r).strip()):
                    retired += 1
            except Exception:
                pass
        try:
            if published or retired:
                print(f"[Watcher] session {worker_id} task board: published {published} / retired {retired}", flush=True)
            if n_add or n_ver or n_dis or n_sup or new_digest:
                print(f"[Watcher] session {worker_id} ledger: added {n_add} / verified {n_ver} / disputed {n_dis} / superseded {n_sup}"
                      f"{' / digest updated' if new_digest else ''}", flush=True)
        except Exception:
            pass
    except Exception:
        # a watcher failure does not affect the main flow
        pass


def _claude_env() -> dict:
    """Build the environment for the claude subprocess.

    LLM provider configuration (endpoint/key/model) is centralized in cruiser.llm.get_claude_provider_env;
    this only handles claude's own runtime switches (sandbox, context compaction window, reversing environment).
    """
    env = os.environ.copy()
    # provider configuration (ANTHROPIC_BASE_URL / AUTH_TOKEN / MODEL / SMALL_FAST_MODEL)
    # note: for single-session workers main.py presets ANTHROPIC_MODEL to pick each one's model, which is kept as-is here.
    env.update(get_claude_provider_env())
    env["IS_SANDBOX"] = "1"  # allow bypassPermissions when running as root
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    # When connecting through an Anthropic-compatible endpoint, Claude Code treats non-claude model IDs as unknown models and assumes
    # the wrong window size (200K by default), so auto-compact triggers at the wrong time (too late and it hits the real limit
    # and errors, too early and it wastes effort compacting often). The context window defaults per provider (DeepSeek 1M; GLM flagship
    # glm-5.2/5.3 also 1M); declaring the real window makes compaction happen at the matching threshold; explicit user settings take precedence.
    from .llm import get_context_defaults, get_solve_model, provider_for_model
    _model = get_solve_model()
    _max_ctx, _compact_win = get_context_defaults(_model)
    env.setdefault("CLAUDE_CODE_MAX_CONTEXT_TOKENS", str(_max_ctx))
    env.setdefault("CLAUDE_CODE_AUTO_COMPACT_WINDOW", str(_compact_win))
    # GLM-5.x (TokenHub) are always-thinking models: a bare Anthropic-protocol request without thinking is rejected by the gateway
    # (observed error: "this model always thinks; disabling thinking is not supported; use low, high or max"). claude CLI
    # 2.1.x default requests already pass; setdefault MAX_THINKING_TOKENS here explicitly as a defensive layer:
    # compatible with older CLIs that do not send thinking by default, and gives the thinking chain an explicit cap (the budget is a cap, not
    # actual consumption; billing is by actual tokens; 32000 has been verified to pass TokenHub validation and does not affect normal output).
    if provider_for_model(_model) == "glm":
        env.setdefault("MAX_THINKING_TOKENS", "32000")
    # PyGhidra runtime environment (Ghidra itself + JDK), for pyghidra scripts written by Claude to use directly
    env.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra_12.1.2_PUBLIC")
    env.setdefault("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64")
    return env


def _extract_text_and_tools(message: dict) -> tuple[str, list[str]]:
    """Extract text and tool-call summaries from an assistant event (for progress display)."""
    texts: list[str] = []
    tools: list[str] = []
    content = message.get("content")
    if isinstance(content, str):
        return content, tools
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                texts.append(str(block.get("text") or ""))
            elif btype == "tool_use":
                name = block.get("name") or "?"
                inp = block.get("input") or {}
                summary = ""
                if isinstance(inp, dict):
                    summary = inp.get("command") or inp.get("file_path") or inp.get("pattern") or ""
                tools.append(f"{name}: {str(summary)[:150]}")
    return "\n".join(texts), tools


def _iter_tool_result_texts(message: dict) -> list[str]:
    """Extract all text blocks from a user event (tool results)."""
    out: list[str] = []
    content = message.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                c = block.get("content")
                if isinstance(c, str):
                    out.append(c)
                elif isinstance(c, list):
                    for sub in c:
                        if isinstance(sub, dict) and sub.get("type") == "text":
                            out.append(str(sub.get("text") or ""))
    return out


def _write_hooks_settings(ws_dir: str) -> None:
    """Write .claude/settings.json in the working directory to register the blackboard injection hooks.

    SessionStart injects once at the start; PostToolUse injects the latest blackboard every 10 tool calls,
    physically entering the model context via additionalContext, without relying on the model to read it on its own.
    """
    try:
        claude_dir = os.path.join(ws_dir, ".claude")
        os.makedirs(claude_dir, exist_ok=True)
        hook_cmd = f'"{sys.executable}" {os.path.join(_project_root(), "blackboard_hook.py")}'
        settings = {
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": hook_cmd}]}],
                "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": hook_cmd}]}],
            }
        }
        with open(os.path.join(claude_dir, "settings.json"), "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _capture_submitted_flag(message: dict) -> Optional[str]:
    """If this assistant event invoked submit_flag.py, extract the flag argument from the command line."""
    content = message.get("content")
    if not isinstance(content, list):
        return None
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        inp = block.get("input") or {}
        cmdline = str(inp.get("command") or "") if isinstance(inp, dict) else ""
        m = _SUBMIT_INVOKE_RE.search(cmdline)
        if not m:
            continue
        flag = m.group(2) or m.group(3) or m.group(4) or ""
        if _looks_like_flag(flag):
            return flag
    return None


_LEAD_NOTE = (
    "\n\n[Your role: integration lead] You own the end-to-end solution of this challenge. "
    "Other sessions and solvers explore in parallel and report into the shared ledger. "
    "Re-read the solve-state digest and task results regularly, connect their findings, and keep driving "
    "the next integration step toward the flag; do not only widen the exploration.\n"
)

_RESUME_TEMPLATE = (
    "[Scheduler] This is the same conversation, continued in a new scheduling round. "
    "Your earlier work, files and conclusions are still valid. Current shared solve state:\n\n"
    "{context}\n\n"
    "Continue from where you left off. Follow the flag submission protocol given at the start."
)


def _run_one_session(target: str, hint: str, code: str, worker_id: str, ws_dir: str, quiet: bool, step_counter: list[int], solver_task: Optional[str] = None) -> Optional[str]:
    """Run one Claude session until all of this challenge's flags are confirmed / the turn limit is reached / it is killed externally.

    step_counter is a single-element list shared across sessions: the [COUNT] counter increases monotonically across sessions,
    ensuring the main.py scheduler's step threshold (which may exceed a single session's 100-turn limit) can trigger.
    Returns the confirmed flag JSON string (only when platform progress is complete); returns None if incomplete or unsolved, and the caller starts a new session to continue.
    """
    root = _project_root()
    reports_dir = os.path.join(os.getcwd(), "reports")
    tools_dir = os.path.join(root, "tools")
    submit_cmd = f'"{sys.executable}" {os.path.join(tools_dir, "submit_flag.py")}'
    dirsearch_cmd = f'"{sys.executable}" {os.path.join(tools_dir, "dirsearch_scan.py")}'
    decompile_script = os.path.join(tools_dir, "decompile.py")
    res_dir = os.path.join(root, "resource")
    if solver_task:
        # solver directed mode: work on a single direction, with the focused system prompt and task template
        system_prompt = CLAUDE_SOLVER_SYSTEM_PROMPT
        prompt = CLAUDE_SOLVER_TASK_TEMPLATE.format(
            target=target or "(not provided)",
            code=code or "unknown",
            task=solver_task,
            info_file=os.path.join(reports_dir, f"info_{code}.txt"),
            submit_cmd=submit_cmd,
            res_dir=res_dir,
            decompile_script=decompile_script,
            dirsearch_cmd=dirsearch_cmd,
        )
    else:
        system_prompt = CLAUDE_SYSTEM_PROMPT
        prompt = CLAUDE_TASK_TEMPLATE.format(
            target=target or "(not provided; get it from the blackboard and hint first)",
            code=code or "unknown",
            hint=hint or "none",
            info_file=os.path.join(reports_dir, f"info_{code}.txt"),
            hint_file=os.path.join(reports_dir, f"hint_{code}.txt"),
            submit_cmd=submit_cmd,
            res_dir=res_dir,
            decompile_script=decompile_script,
            dirsearch_cmd=dirsearch_cmd,
        )
    from . import engines, ledger
    from .opencode_engine import context_block
    eng = engines.current()
    eng_name = eng.NAME if eng is not None else "claude"
    # Explorer slots keep one engine conversation across sessions and stages; solvers always start fresh.
    slot = None if solver_task else worker_id
    lead = slot == "1"
    prior = ledger.session_get(code, slot) if slot else None
    resume_id = prior.get("id") if prior and prior.get("engine") == eng_name else None
    if lead:
        prompt += _LEAD_NOTE
    if resume_id:
        resume_prompt = _RESUME_TEMPLATE.format(context=context_block(reports_dir, code) or "(empty)")
        if lead:
            resume_prompt += _LEAD_NOTE
        if eng is not None:
            cmd = eng.resume_cmd(resume_id, resume_prompt, ws_dir=ws_dir, reports_dir=reports_dir)
        else:
            cmd = _claude_cmd(resume_prompt, system_prompt, ws_dir, resume_id=resume_id)
    elif eng is not None:
        cmd = eng.session_cmd(prompt, system_prompt, context_block(reports_dir, code),
                              ws_dir=ws_dir, reports_dir=reports_dir)
    else:
        cmd = _claude_cmd(prompt, system_prompt, ws_dir)
    # no start_new_session: claude and its children stay in this process group,
    # so the main.py scheduler can reap the whole group with killpg
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL if eng is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL if eng is not None else subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=ws_dir,
        env=os.environ.copy() if eng is not None else _claude_env(),
    )
    events = eng.claude_events(proc.stdout) if eng is not None else _claude_events(proc.stdout)
    session = {"slot": slot, "engine": eng_name, "last_text": "", "steps": 0}
    flag_json = _drive_session(proc, events, code, worker_id, quiet, step_counter, session)
    if resume_id and session["steps"] == 0 and not flag_json:
        ledger.session_clear(code, slot)  # resume produced nothing: start the next session fresh
    if solver_task and session["last_text"].strip():
        # The solver's closing message is its task result: it goes back to the ledger, not into thin air.
        ledger.add_result(code, worker_id, solver_task, _strip_flag_literals(session["last_text"].strip())[:1500])
    return flag_json


def _claude_events(stdout):
    for raw in stdout or []:
        line = raw.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def _claude_cmd(prompt: str, system_prompt: str, ws_dir: str, resume_id: Optional[str] = None) -> list[str]:
    claude_bin = shutil.which("claude")
    if not claude_bin:
        raise RuntimeError("claude CLI is not installed or not on PATH")
    _write_hooks_settings(ws_dir)

    cmd = [
        claude_bin,
        "-p", prompt,
        "--output-format", "stream-json",
        "--verbose",
        "--permission-mode", "bypassPermissions",
        "--append-system-prompt", system_prompt,
        # Online lookup is forbidden in CTF competitions: remove WebSearch/WebFetch from the toolset (in headless mode bypassPermissions would allow them automatically).
        "--disallowedTools", "WebSearch,WebFetch",
    ]
    # limit the per-session turns only when a positive turn limit is explicitly configured; unlimited by default.
    max_turns = _max_turns_per_session()
    if max_turns > 0:
        cmd += ["--max-turns", str(max_turns)]
    if resume_id:
        cmd += ["--resume", resume_id]
    return cmd


def _drive_session(proc: subprocess.Popen, events, code: str, worker_id: str, quiet: bool, step_counter: list[int],
                   session: Optional[dict] = None) -> Optional[str]:
    """Consume the engine event stream (claude stream-json shape): count steps, verify flags, trigger the watcher."""
    session_step = 0
    flag_json: Optional[str] = None
    last_submitted_flag = ""
    confirmed_flag: Optional[str] = None       # the flag most recently accepted by the platform
    flag_candidates: "set[str]" = set()        # valid flag candidates seen in the session (for authoritative verification)
    verified: "set[str]" = set()               # candidates with a definitive result (transient failures excluded so they can be retried)
    progress = {"correct": 0, "total": 0}      # platform progress; the session ends only when X>=Y
    # blackboard watcher state: rolling activity summary + single-watcher concurrency gate (while busy, park the latest snapshot so no cycle is lost)
    recent: deque[str] = deque(maxlen=_WATCHER_RECENT_MAX)
    watcher_state = {"busy": False, "pending": None}
    watcher_lock = threading.Lock()
    flag_method_threads: list[threading.Thread] = []

    def _challenge_done() -> bool:
        return _flags_all_collected(progress["correct"], progress["total"])

    def _note_flag_outcome(cand: str, outcome) -> None:
        if not outcome.ok:
            return
        nonlocal confirmed_flag
        confirmed_flag = cand
        if outcome.total >= 1:
            progress["correct"] = max(progress["correct"], outcome.correct)
            progress["total"] = max(progress["total"], outcome.total)
        elif code:
            from .tools import query_flag_progress
            qc, qt = query_flag_progress(code)
            if qt >= 1:
                progress["correct"] = max(progress["correct"], qc)
                progress["total"] = max(progress["total"], qt)
        prog = f"{progress['correct']}/{progress['total']}" if progress["total"] >= 1 else "?"
        try:
            if _challenge_done():
                print(f"\x1b[95;1m[FLAG] session {worker_id} all flags collected ({prog}): {cand}\x1b[0m", flush=True)
            else:
                print(f"\x1b[93;1m[FLAG PARTIAL] session {worker_id} progress {prog}, continuing: {cand}\x1b[0m", flush=True)
        except Exception:
            pass
        fresh = bool(getattr(outcome, "fresh", False))
        _flag_method_dbg(
            f"note_outcome worker={worker_id} fresh={fresh} ok={outcome.ok} "
            f"correct={getattr(outcome, 'correct', None)} total={getattr(outcome, 'total', None)} "
            f"progress={prog} has_fresh_attr={hasattr(outcome, 'fresh')} "
            f"recent_n={len(recent)} code={code!r}"
        )
        if fresh:
            t = _spawn_flag_method_writer(
                code, worker_id, progress["correct"], progress["total"], list(recent)
            )
            if t is not None:
                flag_method_threads.append(t)
        else:
            _flag_method_dbg(f"note_outcome no entry written: fresh=False worker={worker_id} prog={prog}")

    def _apply_outcome(cand: str, outcome) -> bool:
        """Apply one submission result. Returns True if and only if all of this challenge's flags are confirmed."""
        if outcome.definitive:
            verified.add(cand)
        if outcome.ok:
            _note_flag_outcome(cand, outcome)
        return _challenge_done()

    def _verify_flag(cand: str) -> bool:
        """Authoritative verification: the framework submits to the platform itself. True only means the challenge is complete, not "this one is correct"."""
        from .tools import looks_flaglike
        if not code or not cand or not looks_flaglike(cand):
            return _challenge_done()
        if cand in verified:
            return _challenge_done()
        return _apply_outcome(cand, _submit_flag_directly(code, cand))

    def _ingest_cands(cands: list[str]) -> bool:
        """Submit this batch of candidates in order. If the first is correct but the set is incomplete, keep submitting the rest; returns True only when complete."""
        seen: set[str] = set()
        for fm in cands:
            if not fm or fm in seen:
                continue
            seen.add(fm)
            flag_candidates.add(fm)
            if _verify_flag(fm):
                return True
        return _challenge_done()

    def _mark_done(cand: str) -> None:
        nonlocal flag_json, confirmed_flag
        confirmed_flag = cand or last_submitted_flag or confirmed_flag or "ok"
        flag_json = json.dumps({"flag": confirmed_flag}, ensure_ascii=False)

    def _absorb_tool_progress(text: str) -> None:
        """If the receipt of the model's own submit_flag.py call carries X/Y, sync it into progress (covers strings missed by the shape filter)."""
        if not any(marker in (text or "") for marker in _FLAG_OK_MARKERS):
            return
        c, t = _progress_from_text(text)
        if t >= 1:
            progress["correct"] = max(progress["correct"], c)
            progress["total"] = max(progress["total"], t)
        if "FLAG CORRECT" in (text or "") and "ALREADY SUBMITTED" not in (text or ""):
            _flag_method_dbg(
                f"absorb model submission correct worker={worker_id} progress={progress} "
                f"recent_n={len(recent)} text_head={(text or '')[:80]!r}"
            )
            t = _spawn_flag_method_writer(
                code, worker_id, progress["correct"], progress["total"], list(recent)
            )
            if t is not None:
                flag_method_threads.append(t)

    def _maybe_trigger_watcher() -> None:
        if not code:
            return
        snapshot = _format_watcher_activity(recent)
        start = False
        with watcher_lock:
            if watcher_state["busy"]:
                watcher_state["pending"] = snapshot
                return
            watcher_state["busy"] = True
            start = True
        if start:
            threading.Thread(target=_watcher_job, args=(snapshot,), daemon=True).start()

    def _watcher_job(snapshot: str) -> None:
        while True:
            try:
                _watcher_curate_blackboard(code, worker_id, snapshot)
            except Exception:
                pass
            with watcher_lock:
                snapshot = watcher_state["pending"]
                watcher_state["pending"] = None
                if snapshot is None:
                    watcher_state["busy"] = False
                    return

    try:
        for evt in events:
            etype = evt.get("type")
            if etype == "system" and evt.get("session_id") and session and session.get("slot"):
                from . import ledger
                ledger.session_set(code, session["slot"], session["engine"], str(evt["session_id"]))
            elif etype == "assistant":
                session_step += 1
                step_counter[0] += 1
                if session is not None:
                    session["steps"] = session_step
                print(f"[COUNT] {step_counter[0]}", flush=True)
                msg = evt.get("message") or {}
                text, tools = _extract_text_and_tools(msg)
                if session is not None and text.strip():
                    session["last_text"] = text
                if not quiet:
                    for t in tools:
                        print(f"[TOOL] {t}", flush=True)
                    if text.strip():
                        # collapse to one line so JSON inside a Thought is not misread line-by-line by the parent process as the final {"flag"}
                        preview = text.strip()[:300].replace("\n", " ").replace("\r", " ")
                        print(f"[Claude] {preview}", flush=True)
                digest_parts = []
                if text.strip():
                    digest_parts.append("Thought: " + text.strip()[:_WATCHER_THOUGHT_CHARS])
                digest_parts.extend("Action: " + t for t in tools)
                if digest_parts:
                    recent.append("\n".join(digest_parts))
                ingest: list[str] = []
                submitted = _capture_submitted_flag(msg)
                if submitted and _looks_like_flag(submitted):
                    last_submitted_flag = submitted
                    ingest.append(submitted)
                blob = _unique_flag_cands(text or "")
                if len(blob) <= _AUTO_SUBMIT_MAX_PER_BLOB:
                    ingest.extend(blob)
                if _ingest_cands(ingest):
                    _mark_done(confirmed_flag or last_submitted_flag or (ingest[-1] if ingest else "ok"))
                    break
                if session_step % _WATCHER_EVERY == 0:
                    _maybe_trigger_watcher()
            elif etype == "user":
                msg = evt.get("message") or {}
                ingest: list[str] = []
                for rt in _iter_tool_result_texts(msg):
                    blob = _unique_flag_cands(rt or "")
                    if len(blob) <= _AUTO_SUBMIT_MAX_PER_BLOB:
                        ingest.extend(blob)
                    if rt.strip():
                        recent.append("Observation: " + rt.strip()[:_WATCHER_OBS_CHARS])
                    _absorb_tool_progress(rt or "")
                if _ingest_cands(ingest) or _challenge_done():
                    _mark_done(confirmed_flag or last_submitted_flag or "ok")
                    break
            elif etype == "result":
                # session ended (success / error_max_turns / error_*)
                if not quiet:
                    subtype = evt.get("subtype") or ""
                    print(f"[Session] Claude session ended: {subtype}", flush=True)
                break
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        # let the [flag-method] fork from the first submission finish first, so the daemon is not dropped when the session exits
        for t in flag_method_threads:
            try:
                _flag_method_dbg(f"join waiting {t.name} alive={t.is_alive()}")
                t.join(timeout=25)
                _flag_method_dbg(f"join done {t.name} alive={t.is_alive()}")
            except Exception as e:
                _flag_method_dbg(f"join error {t.name} {type(e).__name__}: {e}")
        # wrap-up: when the session ends (flag found / turn limit reached / natural end), force one more collection,
        # to capture the trailing new findings between "after the last periodic watcher" and the end of the session (otherwise they would be missed).
        # run synchronously with a timeout: avoids losing it when the daemon watcher thread is killed before the subprocess exits, while preventing a hung LLM from blocking cleanup.
        if code and recent:
            snapshot = _format_watcher_activity(recent)
            try:
                ft = threading.Thread(
                    target=_watcher_curate_blackboard, args=(code, worker_id, snapshot), daemon=True
                )
                ft.start()
                ft.join(timeout=30)
            except Exception:
                pass

    if flag_json:
        return flag_json
    # session over: submit every candidate seen in this session (do not stop at the first correct one); return JSON only when platform progress is complete.
    if code:
        last_ok = confirmed_flag
        for cand in sorted((c for c in flag_candidates if _looks_like_flag(c)), key=len, reverse=True):
            if _verify_flag(cand):
                last_ok = cand
                break
            if cand in verified and progress["total"] >= 1:
                last_ok = last_ok or cand
        if _challenge_done():
            try:
                print(f"\x1b[95;1m[FLAG RECOVERED] programmatic submission after session end, progress complete: {last_ok}\x1b[0m", flush=True)
            except Exception:
                pass
            return json.dumps({"flag": last_ok or "ok"}, ensure_ascii=False)
    return None


def run_auto_scan(target: str, max_steps: int = 0, quiet: bool = False, hint: Optional[str] = None, challenge_code: Optional[str] = None, solver_task: Optional[str] = None) -> str:
    """Run the Claude Code auto scan until all of this challenge's flags are confirmed by the platform (or it is terminated by the external scheduler).

    - The return value is a JSON string with a flag field (only when platform progress is complete);
    - max_steps is not enforced here (the step threshold is enforced by the main.py scheduler monitoring [COUNT]);
    - When one flag is correct but the set is incomplete the session continues; after a session ends naturally, a new session builds on the blackboard to hunt the remaining flags.

    Solver mode (solver_task non-empty): runs a single session focused on that direction and returns, without looping into new sessions;
    the turn limit is controlled by the CRUISER_MAX_TURNS environment variable (main.py's solver driver sets it to 40).
    Note: this is claude's turn count, not the [COUNT] in the log ([COUNT] is roughly several times larger).
    """
    from . import engines
    eng = engines.current()
    engine_bin = eng.BINARY_NAME if eng is not None else "claude"
    if shutil.which(engine_bin) is None:
        return json.dumps({"flag": None, "error": f"{engine_bin} CLI is not installed"}, ensure_ascii=False)

    worker_id = os.environ.get("CRUISER_WORKER_ID", "single")
    code = challenge_code or os.environ.get("CRUISER_CHALLENGE_CODE") or ""
    ws_dir = os.environ.get("CRUISER_WORKSPACE_DIR") or ""
    if not ws_dir:
        base_ws = os.environ.get("CRUISER_WORKSPACE_BASE") or "/tmp/cruiser_workspaces"
        os.makedirs(base_ws, exist_ok=True)
        ws_dir = os.path.join(base_ws, f"ws_claude_{uuid.uuid4().hex[:8]}")
    os.makedirs(ws_dir, exist_ok=True)

    # solver directed mode: run only one session, return when done / turn limit reached, no loop
    if solver_task:
        try:
            flag_json = _run_one_session(
                target=target, hint="", code=code, worker_id=worker_id,
                ws_dir=ws_dir, quiet=quiet, step_counter=[0], solver_task=solver_task,
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            return json.dumps({"flag": None, "error": str(e)}, ensure_ascii=False)
        if flag_json:
            try:
                print(f"\x1b[95;1m[FOUND FLAG] {flag_json}\x1b[0m", flush=True)
            except Exception:
                pass
            return flag_json
        return json.dumps({"flag": None}, ensure_ascii=False)

    attempt = 0
    step_counter = [0]  # global step counter, monotonically increasing across sessions
    while True:
        attempt += 1
        try:
            flag_json = _run_one_session(
                target=target,
                hint=hint or "",
                code=code,
                worker_id=worker_id,
                ws_dir=ws_dir,
                quiet=quiet,
                step_counter=step_counter,
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            try:
                print(f"[Error] Claude session error: {e}", flush=True)
            except Exception:
                pass
            time.sleep(5)
            continue
        if flag_json:
            try:
                print(f"\x1b[95;1m[FOUND FLAG] {flag_json}\x1b[0m", flush=True)
            except Exception:
                pass
            return flag_json
        try:
            _mt = _max_turns_per_session()
            _limit_desc = f"{_mt}-turn limit" if _mt > 0 else "session ended naturally"
            print(f"[Session] session #{attempt} incomplete ({_limit_desc}), starting a new session from the blackboard results...", flush=True)
        except Exception:
            pass
