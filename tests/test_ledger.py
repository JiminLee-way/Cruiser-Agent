"""Shared ledger, engine resume commands and session-id events."""
from __future__ import annotations

import io
import json
import multiprocessing as mp

import pytest

from cruiser import codex_engine, ledger, opencode_engine, runtime


@pytest.fixture
def reports(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "_reports_dir", lambda: str(tmp_path))
    return tmp_path


def test_disputed_entry_keeps_text_and_reason(reports):
    fid = ledger.add_fact("T-1", "1", "lead: seed 0x1234 matches the known prefix")
    assert ledger.set_status("T-1", fid, "disputed", "not the seed of the solved grid", "w2")
    [f] = ledger.facts("T-1")
    assert f["status"] == "disputed"
    assert "seed 0x1234" in f["text"]
    assert any("not the seed of the solved grid" in n for n in f["notes"])
    board = (reports / "info_T-1.txt").read_text(encoding="utf-8")
    assert "[disputed]" in board and "seed 0x1234" in board


def test_supersede_hides_old_entry_but_keeps_it_in_ledger(reports):
    old = ledger.add_fact("T-1", "1", "key is 16 bytes")
    new = ledger.supersede("T-1", old, "key is 16 bytes, big-endian", "w")
    assert [f["id"] for f in ledger.facts("T-1")] == [new]
    assert {f["id"] for f in ledger.facts("T-1", include_superseded=True)} == {old, new}


def test_duplicates_and_unknown_ids_are_rejected(reports):
    assert ledger.add_fact("T-1", "1", "A  b") is not None
    assert ledger.add_fact("T-1", "2", "a b") is None
    assert not ledger.set_status("T-1", "f-nope00", "verified")
    assert not ledger.set_status("T-1", ledger.facts("T-1")[0]["id"], "deleted")


def test_one_flag_method_per_flag_number_and_text_duplicates_are_per_kind_group(reports):
    assert ledger.add_fact("T-1", "1", "progress 1/2. sqli on /login", kind="flag_method")
    assert ledger.add_fact("T-1", "2", "progress 1/2. ssti on /render", kind="flag_method") is None
    assert ledger.add_fact("T-1", "2", "progress 2/2. ssti on /render", kind="flag_method")
    assert ledger.add_fact("T-1", "3", "flag 1 came from sqli on /login")
    assert ledger.add_fact("T-1", "3", "PROGRESS 1/2.  sqli on /login") is None
    assert ledger.add_result("T-1", "s1", "check the cookie", "progress 1/2. sqli on /login")
    assert ledger.add_result("T-1", "s2", "check the cookie", "progress 1/2. sqli on /login") is None
    assert ledger.add_result("T-1", "s2", "check the login form", "progress 1/2. sqli on /login")
    assert [f["kind"] for f in ledger.facts("T-1")] == ["flag_method", "flag_method", "fact"]
    assert [r["task"] for r in ledger.results("T-1")] == ["check the cookie", "check the login form"]


def test_board_uses_parseable_header_format(reports):
    ledger.add_fact("T-1", "solver3", "fact one")
    ledger.add_result("T-1", "solver3", "check the table", "table is only a UI legend")
    lines = (reports / "info_T-1.txt").read_text(encoding="utf-8").splitlines()
    assert lines[0].endswith("session: solver3") and lines[1].startswith("info: ")
    assert any(ln.startswith("info: [task-result]") for ln in lines)


def test_context_text_puts_digest_first_and_respects_budget(reports):
    for i in range(200):
        ledger.add_fact("T-1", "1", f"entry number {i} " + "x" * 40)
    ledger.set_digest("T-1", "w", "GOAL: get DH{...}\nOPEN LEADS: seed candidate")
    text = ledger.context_text("T-1", budget=1500)
    assert text.startswith("[Solve state")
    assert len(text) <= 1500
    assert "entry number 199" in text and "entry number 0 " not in text


def _writer(path: str, n: int, tag: str) -> None:
    from cruiser import ledger as lg
    lg._reports_dir = lambda: path
    for i in range(n):
        lg.add_fact("T-1", tag, f"{tag} fact {i}")


def _run_all(procs: list) -> None:
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert [p.exitcode for p in procs] == [0] * len(procs)


def test_concurrent_writers_do_not_lose_entries(reports):
    _run_all([mp.Process(target=_writer, args=(str(reports), 15, f"w{k}")) for k in range(4)])
    assert len(ledger.facts("T-1")) == 60
    assert {f["text"] for f in ledger.facts("T-1")} == {f"w{k} fact {i}" for k in range(4) for i in range(15)}


def _same_text_writer(path: str, n: int) -> None:
    from cruiser import ledger as lg
    lg._reports_dir = lambda: path
    for i in range(n):
        lg.add_fact("T-1", "w", f"shared fact {i}")


def test_concurrent_writers_store_the_same_text_once(reports):
    _run_all([mp.Process(target=_same_text_writer, args=(str(reports), 20)) for _ in range(4)])
    assert sorted(f["text"] for f in ledger.facts("T-1")) == sorted(f"shared fact {i}" for i in range(20))


def _stored_bytes(d) -> int:
    return sum(p.stat().st_size for p in d.iterdir() if p.is_file())


def test_repeated_digests_do_not_grow_stored_state(reports):
    ledger.add_fact("T-1", "1", "fact one")
    ledger.set_digest("T-1", "1", "GOAL: 000")
    before = _stored_bytes(reports)
    for i in range(1, 50):
        ledger.set_digest("T-1", "1", f"GOAL: {i:03d}")
    assert ledger.digest("T-1") == "GOAL: 049"
    assert _stored_bytes(reports) == before


def test_dashboard_classifies_every_rendered_kind(reports):
    ledger.add_fact("T-1", "1", "plain fact")
    ledger.add_fact("T-1", "1", "progress 1/1. sqli on /login", kind="flag_method")
    rid = ledger.add_result("T-1", "solver1", "check the table", "the table is a UI legend")
    ledger.set_status("T-1", rid, "disputed", "the table seeds the PRNG", "2")
    entries = runtime.parse_blackboard((reports / "info_T-1.txt").read_text(encoding="utf-8"))
    assert [(e["worker"], e["kind"]) for e in entries] == [
        ("1", "fact"), ("1", "flag_method"), ("solver1", "task_report"),
    ]


def test_unreadable_ledger_still_starts_sessions_but_is_never_overwritten(reports, capsys):
    (reports / "desc_T-1.txt").write_text("find the admin panel", encoding="utf-8")
    path = reports / "ledger_T-1.json"
    path.write_text("{not json", encoding="utf-8")
    assert opencode_engine.context_block(str(reports), "T-1") == "[Challenge description]\nfind the admin panel"
    captured = capsys.readouterr()
    [warning] = [ln for ln in (captured.out + captured.err).splitlines() if ln.startswith("[Ledger]")]
    assert str(path) in warning
    with pytest.raises(ValueError):
        ledger.add_fact("T-1", "1", "a fact written after the corruption")
    assert path.read_text(encoding="utf-8") == "{not json"


def test_session_slots(reports):
    assert ledger.session_get("T-1", "1") is None
    ledger.session_set("T-1", "1", "codex", "thread-a")
    ledger.session_set("T-1", "2", "codex", "thread-b")
    assert ledger.session_get("T-1", "1")["id"] == "thread-a"
    ledger.session_clear("T-1", "1")
    assert ledger.session_get("T-1", "1") is None
    assert ledger.session_get("T-1", "2")["id"] == "thread-b"


def test_codex_resume_cmd(monkeypatch):
    monkeypatch.setattr(codex_engine, "binary", lambda: "codex")
    monkeypatch.setenv("CRUISER_CODEX_DAYBREAK", "1")
    monkeypatch.setenv("CRUISER_CODEX_SANDBOX", "danger-full-access")
    cmd = codex_engine.resume_cmd("tid", "go on", ws_dir="/w", reports_dir="/r", model="gpt-6-sol")
    assert cmd[:3] == ["codex", "exec", "resume"]
    assert "--dangerously-bypass-approvals-and-sandbox" in cmd and "daybreak=true" in cmd
    assert cmd[-2:] == ["tid", "go on"] and "-C" not in cmd
    monkeypatch.delenv("CRUISER_CODEX_SANDBOX")
    monkeypatch.setenv("CRUISER_CODEX_ROOT", "/root")
    cmd = codex_engine.resume_cmd("tid", "go on", ws_dir="/w", reports_dir="/r", model="m")
    roots = next(c for c in cmd if c.startswith("sandbox_workspace_write.writable_roots="))
    assert json.loads(roots.split("=", 1)[1]) == ["/root", "/r", "/w"]


def test_engines_announce_session_ids(monkeypatch):
    codex_out = io.StringIO('{"type":"thread.started","thread_id":"t-1"}\n{"type":"turn.completed"}\n')
    first = next(iter(codex_engine.claude_events(codex_out)))
    assert first == {"type": "system", "subtype": "init", "session_id": "t-1"}
    oc_out = io.StringIO('{"type":"text","sessionID":"ses_1","part":{"text":"hi"}}\n')
    evs = list(opencode_engine.claude_events(oc_out))
    assert evs[0]["session_id"] == "ses_1" and evs[1]["type"] == "assistant"
    monkeypatch.setattr(opencode_engine, "binary", lambda: "opencode")
    cmd = opencode_engine.resume_cmd("ses_1", "go on", model="m")
    assert cmd[cmd.index("--session") + 1] == "ses_1" and cmd[-1] == "go on"


def test_watcher_applies_statuses_by_id_and_never_deletes(reports, tmp_path, monkeypatch):
    from cruiser import claude_agent, taskboard
    monkeypatch.setattr(taskboard, "_reports_dir", lambda: str(reports))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    lead = ledger.add_fact("T-1", "solver11", "lead: seed 0xab5e313b gives the known prefix")
    keep = ledger.add_fact("T-1", "1", "bytecode is 2200 records of 8 bytes")
    reply = {
        "add": ["grid columns 0-3 are [1, 2, 3, 4]", "flag{should_never_be_stored_here}"],
        "verify": [keep, "f-unknwn"],
        "dispute": [{"id": lead, "reason": "not the seed of the solved grid"}],
        "supersede": [],
        "digest": "GOAL: DH{...}\nOPEN LEADS: f-lead seed",
        "suggest_tasks": [{"text": "derive the output from the seed lead", "basis": lead}],
        "retire_tasks": [],
    }

    class FakeLLM:
        def invoke(self, messages):
            class R:
                content = json.dumps(reply)
            return R()

    monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: FakeLLM())
    claude_agent._watcher_curate_blackboard("T-1", claude_agent.LEAD_SLOT, "Thought: tried things\nAction: shell: ls", str(cwd))
    by_id = {f["id"]: f for f in ledger.facts("T-1")}
    assert by_id[lead]["status"] == "disputed" and "0xab5e313b" in by_id[lead]["text"]
    assert by_id[keep]["status"] == "verified"
    texts = [f["text"] for f in by_id.values()]
    assert "grid columns 0-3 are [1, 2, 3, 4]" in texts
    assert not any("should_never_be_stored_here" in t for t in texts)
    assert ledger.digest("T-1").startswith("GOAL")
    assert any(lead in t["text"] for t in taskboard.list_tasks("T-1"))
