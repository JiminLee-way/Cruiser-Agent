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


def test_watcher_does_not_store_a_dict_add_item(reports, run_watcher):
    run_watcher("2", {"add": [{"text": "grid is 9x9"}, "lead: seed 0x1234 gives the prefix"]})
    assert [f["text"] for f in ledger.facts(CODE)] == ["lead: seed 0x1234 gives the prefix"]


def test_watcher_does_not_publish_a_task_without_text(reports, run_watcher):
    run_watcher("2", {"suggest_tasks": [
        {"basis": "f-aaaaaa"},
        {"text": "derive the output from the seed", "basis": "f-bbbbbb"},
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
