from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from cruiser import claude_agent, ledger, taskboard

CODE = "T-1"


@pytest.fixture
def reports(tmp_path, monkeypatch):
    d = tmp_path / "reports"
    d.mkdir()
    monkeypatch.setattr(ledger, "_reports_dir", lambda: str(d))
    monkeypatch.setattr(taskboard, "_reports_dir", lambda: str(d))
    return d


@pytest.fixture
def run_watcher(reports, tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    def _run(worker_id: str, reply: dict) -> None:
        class FakeLLM:
            def invoke(self, messages):
                return SimpleNamespace(content=json.dumps(reply))

        monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: FakeLLM())
        claude_agent._watcher_curate_blackboard(CODE, worker_id, "Thought: checked the table\nAction: shell: ls", str(cwd))

    return _run


def _board(reports) -> str:
    return (reports / f"info_{CODE}.txt").read_text(encoding="utf-8")


def _everything_stored(reports) -> str:
    return "".join(p.read_text(encoding="utf-8") for p in reports.iterdir() if p.is_file())


def test_task_result_never_stores_answer_literal(reports):
    assert taskboard.report_task(CODE, "solver3", "tried flag{abc12345xyz} wrong", task="check the cookie")
    assert "wrong" in _board(reports)
    assert "flag{abc12345xyz}" not in _everything_stored(reports)


def test_task_result_text_is_capped(reports):
    assert taskboard.report_task(CODE, "solver3", "Q" * 5000, task="dump the table")
    assert "Q" * 100 in _board(reports)
    assert "Q" * 1501 not in _everything_stored(reports)


def test_watcher_can_dispute_a_task_result(reports, run_watcher):
    rid = ledger.add_result(CODE, "solver3", "check the table", "the table is the seed source")
    run_watcher("2", {"dispute": [{"id": rid, "reason": "the table is only a UI legend"}]})
    board = _board(reports)
    [line] = [ln for ln in board.splitlines() if "the table is the seed source" in ln]
    assert "[disputed]" in line
    assert "the table is only a UI legend" in board


def test_superseded_entry_stays_hidden_after_a_later_status(reports):
    old = ledger.add_fact(CODE, "1", "key is 16 bytes")
    new = ledger.supersede(CODE, old, "key is 16 bytes, big-endian", "2")
    ledger.set_status(CODE, old, "verified", by="3")
    assert [f["id"] for f in ledger.facts(CODE)] == [new]
    assert old not in _board(reports)


def test_supersede_onto_existing_text_hides_old_and_returns_existing(reports):
    old = ledger.add_fact(CODE, "1", "key is 16 bytes")
    existing = ledger.add_fact(CODE, "2", "key is 16 bytes, big-endian")
    assert ledger.supersede(CODE, old, "key is 16 bytes, big-endian", "3") == existing
    assert [f["id"] for f in ledger.facts(CODE)] == [existing]
    [hidden] = [f for f in ledger.facts(CODE, include_superseded=True) if f["id"] == old]
    assert any(existing in n for n in hidden["notes"])


def test_context_text_includes_recent_task_results(reports):
    ledger.add_fact(CODE, "1", "bytecode is 2200 records of 8 bytes")
    assert taskboard.report_task(CODE, "solver3", "the table is only a UI legend", task="check the table")
    text = ledger.context_text(CODE)
    assert "bytecode is 2200 records of 8 bytes" in text
    assert "the table is only a UI legend" in text


@pytest.mark.parametrize("worker", ["2", "solver3"])
def test_only_the_lead_watcher_rewrites_the_digest(reports, run_watcher, worker):
    ledger.set_digest(CODE, "1", "GOAL: digest written by the lead")
    run_watcher(worker, {"add": [f"lead: fact seen by {worker}"], "digest": f"GOAL: rewritten by {worker}"})
    assert f"lead: fact seen by {worker}" in [f["text"] for f in ledger.facts(CODE)]
    assert ledger.digest(CODE) == "GOAL: digest written by the lead"
    run_watcher("1", {"digest": "GOAL: rewritten by the lead"})
    assert ledger.digest(CODE) == "GOAL: rewritten by the lead"


def test_watcher_add_items_carry_basis_ids_and_confidence(reports, run_watcher):
    known = ledger.add_fact(CODE, "1", "the grid is read from /static/grid.bin")
    run_watcher("2", {"add": [
        {"text": "grid is 9x9", "basis_ids": [known, "f-unknwn", 7, ""], "confidence": "inferred"},
        {"text": "the cookie is signed", "basis_ids": known, "confidence": ["inferred"]},
        {"text": "flag{never_stored_here}", "confidence": "observed"},
        {"basis_ids": [known]},
        {"text": "lead: seed 0x1234 gives the prefix", "confidence": "certain"},
    ]})
    rows = {f["text"]: (f["basis"], f["confidence"]) for f in ledger.facts(CODE) if f["id"] != known}
    assert rows == {
        "grid is 9x9": ([known], "inferred"),
        "the cookie is signed": ([], ""),
        "lead: seed 0x1234 gives the prefix": ([], ""),
    }


def test_published_direction_keeps_only_live_basis_ids(reports, run_watcher):
    lead = ledger.add_fact(CODE, "1", "lead: seed 0x1234 gives the prefix")
    run_watcher("2", {"suggest_tasks": [
        {"text": "derive the output from the seed", "basis_ids": [lead, "f-unknwn"]},
        {"text": "dump the session table", "basis_ids": "f-aaaaaa"},
    ]})
    tasks = {t["text"]: t["basis_ids"] for t in taskboard.list_tasks(CODE)}
    assert tasks == {f"derive the output from the seed (from {lead})": [lead], "dump the session table": []}


def test_watcher_view_shows_basis_and_inferred_tags(reports, run_watcher, monkeypatch):
    seen: list[str] = []
    known = ledger.add_fact(CODE, "1", "the grid is read from /static/grid.bin")
    fid = ledger.add_fact(CODE, "1", "grid is 9x9", basis=[known], confidence="inferred")
    rid = ledger.add_result(CODE, "solver3", "parse the grid", "rows are 9 bytes", basis=[fid])

    class FakeLLM:
        def invoke(self, messages):
            seen.append("\n".join(m.content for m in messages))
            return SimpleNamespace(content="{}")

    monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: FakeLLM())
    claude_agent._watcher_curate_blackboard(CODE, "2", "Thought: read the grid", str(reports))
    [prompt] = seen
    [fact_row] = [ln for ln in prompt.splitlines() if ln.startswith(f"- {fid} ")]
    [result_row] = [ln for ln in prompt.splitlines() if ln.startswith(f"- {rid} ")]
    assert "[inferred]" in fact_row and fact_row.endswith(f" (from {known})")
    assert result_row.endswith(f" (from {fid})")


def test_watcher_does_not_publish_a_task_without_text(reports, run_watcher):
    run_watcher("2", {"suggest_tasks": [
        {"basis_ids": ["f-aaaaaa"]},
        {"text": "derive the output from the seed", "basis_ids": ["f-bbbbbb"]},
    ]})
    tasks = [t["text"] for t in taskboard.list_tasks(CODE)]
    assert len(tasks) == 1 and tasks[0].startswith("derive the output from the seed"), tasks


def test_max_length_digest_leaves_room_for_newest_entries(reports):
    for i in range(5):
        ledger.add_fact(CODE, "1", f"entry number {i}")
    ledger.set_digest(CODE, "1", "D" * 10000)
    text = ledger.context_text(CODE, budget=3000)
    assert "[Newest ledger entries]" in text
    assert "entry number 4" in text
    assert len(text) <= 3000


def test_watcher_retires_a_direction_only_by_its_exact_id(reports, run_watcher):
    assert taskboard.publish_task(CODE, "brute force the admin login")
    assert taskboard.publish_task(CODE, "read the backup archive")
    by_text = {t["text"]: t["id"] for t in taskboard.list_tasks(CODE)}
    run_watcher("2", {"retire_tasks": ["brute force the admin login"]})
    assert set(t["id"] for t in taskboard.list_tasks(CODE)) == set(by_text.values())
    run_watcher("2", {"retire_tasks": [by_text["brute force the admin login"]]})
    assert [t["id"] for t in taskboard.list_tasks(CODE)] == [by_text["read the backup archive"]]


def test_report_cli_passes_basis_ids_to_the_ledger(repo_copy, monkeypatch):
    import subprocess
    import sys

    from conftest import subprocess_env
    monkeypatch.setattr(ledger, "_reports_dir", lambda: str(repo_copy / "reports"))
    known = ledger.add_fact(CODE, "1", "admin cookie is base64 json")
    out = subprocess.run(
        [sys.executable, "tools/task_board.py", "report", CODE, "solver1", "forged admin cookie accepted",
         "--basis", f"{known},f-unknwn"],
        cwd=repo_copy, env=subprocess_env(), capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    [r] = ledger.results(CODE)
    assert (r["text"], r["basis"]) == ("forged admin cookie accepted", [known])


@pytest.fixture
def watcher_prompt(reports, monkeypatch):
    def _prompt(worker_id: str) -> str:
        seen: list[str] = []

        class FakeLLM:
            def invoke(self, messages):
                seen.append("\n".join(m.content for m in messages))
                return SimpleNamespace(content="{}")

        monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: FakeLLM())
        claude_agent._watcher_curate_blackboard(CODE, worker_id, "Thought: read the grid", str(reports))
        [prompt] = seen
        return prompt
    return _prompt


def _rows(prompt: str, ids: list[str]) -> list[str]:
    return [i for ln in prompt.splitlines() for i in ids if ln.startswith(f"- {i} ")]


def test_lead_watcher_sees_entries_newer_than_the_digest_first(reports, watcher_prompt, monkeypatch):
    clock = ["2026-01-01 10:00:00"]
    monkeypatch.setattr(ledger, "_now", lambda: clock[0])
    old_fact = ledger.add_fact(CODE, "1", "the grid is read from /static/grid.bin")
    clock[0] = "2026-01-01 10:00:01"
    old_result = ledger.add_result(CODE, "solver3", "parse the grid", "rows are 9 bytes")
    clock[0] = "2026-01-01 10:00:02"
    ledger.set_digest(CODE, "1", "GOAL: read the grid")
    clock[0] = "2026-01-01 10:00:03"
    new_result = ledger.add_result(CODE, "solver4", "seed the PRNG", "seed 0x1234 reproduces row 0")
    clock[0] = "2026-01-01 10:00:04"
    new_fact = ledger.add_fact(CODE, "2", "row 1 is the key schedule")
    ids = [old_fact, old_result, new_result, new_fact]

    owner = watcher_prompt(claude_agent.LEAD_SLOT)
    head, rest = owner.split("[Ledger entries", 1)
    assert "New since the last digest (2026-01-01 10:00:02)" in head
    assert _rows(head, ids) == [new_result, new_fact]
    assert sorted(_rows(rest, ids)) == sorted([old_fact, old_result])
    assert "ids it rests on" in owner

    other = watcher_prompt("2")
    assert "New since the last digest" not in other and "ids it rests on" not in other
    assert _rows(other, ids) == [old_fact, new_fact, old_result, new_result]
