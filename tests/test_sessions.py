from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from types import SimpleNamespace

import pytest

from cruiser import claude_agent, engines, ledger, taskboard


def test_child_started_with_child_env_sees_its_cwd_as_pwd(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    out = subprocess.run(
        [sys.executable, "-c", "import os; print(os.environ['PWD'])"],
        cwd=ws, env=engines.child_env(str(ws)), capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert out == str(ws)


def test_explorer_slots_keep_their_workspace_within_a_run_and_solvers_get_fresh_ones(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUISER_WORKSPACE_BASE", str(tmp_path))
    monkeypatch.setenv("CRUISER_RUN_ID", "run-a")
    first = claude_agent.workspace_dir("T-1", "1", resumable=True)
    assert claude_agent.workspace_dir("T-1", "1", resumable=True) == first
    assert claude_agent.workspace_dir("T-1", "2", resumable=True) != first
    solvers = {claude_agent.workspace_dir("T-1", "solver1", resumable=False) for _ in range(2)}
    assert len(solvers) == 2
    assert all(os.path.isdir(p) for p in solvers | {first})


def test_a_new_run_never_reuses_an_earlier_runs_explorer_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUISER_WORKSPACE_BASE", str(tmp_path))
    monkeypatch.setenv("CRUISER_RUN_ID", "run-a")
    earlier = claude_agent.workspace_dir("T-1", "1", resumable=True)
    monkeypatch.setenv("CRUISER_RUN_ID", "run-b")
    assert claude_agent.workspace_dir("T-1", "1", resumable=True) != earlier


STUB = textwrap.dedent('''\
    import json, re, subprocess, sys
    prompt = sys.argv[1]
    if {report!r}:
        report = re.search(r'("[^"]+" \\S+task_board\\.py report \\S+ \\S+)', prompt).group(1)
        subprocess.run(report + " 'the cookie is signed with HS256'", shell=True, check=True)
    print(json.dumps({{"type": "assistant", "message": {{"content": [{{"type": "text", "text": "done, stopping now"}}]}}}}))
    print(json.dumps({{"type": "result", "subtype": "success"}}))
''')


@pytest.mark.parametrize("reports_itself, expected", [
    (True, ["the cookie is signed with HS256"]),
    (False, ["done, stopping now"]),
])
def test_solver_closing_message_is_recorded_only_when_it_did_not_report(
        repo_copy, tmp_path, monkeypatch, reports_itself, expected):
    reports = repo_copy / "reports"
    monkeypatch.setattr(ledger, "_reports_dir", lambda: str(reports))
    monkeypatch.setattr(taskboard, "_reports_dir", lambda: str(reports))
    monkeypatch.setattr(claude_agent, "_project_root", lambda: str(repo_copy))
    monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: None)
    monkeypatch.chdir(repo_copy)
    stub = tmp_path / "engine_stub.py"
    stub.write_text(STUB.format(report=reports_itself))
    fake = SimpleNamespace(
        NAME="stub", BINARY_NAME=sys.executable,
        session_cmd=lambda prompt, *a, **kw: [sys.executable, str(stub), prompt],
        claude_events=claude_agent._claude_events,
    )
    monkeypatch.setattr(engines, "current", lambda: fake)
    monkeypatch.setenv("CRUISER_WATCHER_SUBMIT", "0")
    monkeypatch.setenv("CRUISER_WORKER_ID", "solver3")
    monkeypatch.setenv("CRUISER_WORKSPACE_DIR", str(tmp_path / "ws"))

    assert taskboard.publish_task("T-1", "check how the session cookie is signed")
    task = taskboard.claim_task("T-1", "solver3")["text"]
    claude_agent.run_auto_scan("http://t", quiet=True, challenge_code="T-1", solver_task=task)

    results = ledger.results("T-1")
    assert [r["text"] for r in results] == expected
    assert [r["task"] for r in results] == [task]
