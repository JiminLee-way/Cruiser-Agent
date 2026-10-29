from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from types import SimpleNamespace

import pytest

from cruiser import claude_agent, engines, ledger, taskboard, tools

CODE = "T-1"
FLAG = "flag{7f3a9c2e1b4d4e8a}"


@pytest.fixture
def worker(repo_copy, tmp_path, monkeypatch):
    reports = repo_copy / "reports"
    monkeypatch.setattr(ledger, "_reports_dir", lambda: str(reports))
    monkeypatch.setattr(taskboard, "_reports_dir", lambda: str(reports))
    monkeypatch.setattr(tools, "_flagstore_paths",
                        lambda: (str(reports / "_flagstore.json"), str(reports / "_flagstore.lock")))
    monkeypatch.setattr(claude_agent, "_project_root", lambda: str(repo_copy))
    monkeypatch.chdir(repo_copy)
    monkeypatch.setenv("CRUISER_WORKER_ID", "solver3")
    monkeypatch.setenv("CRUISER_RUN_ID", "run-a")
    monkeypatch.setenv("CRUISER_WORKSPACE_BASE", str(tmp_path / "workspaces"))
    monkeypatch.setenv("CRUISER_WORKSPACE_DIR", "")
    monkeypatch.delenv("CRUISER_WORKSPACE_DIR")
    return SimpleNamespace(reports=reports, tmp=tmp_path)


SESSION_STUB = textwrap.dedent('''\
    import json, os, sys, time
    marker = {marker!r}
    def say(text):
        print(json.dumps({{"type": "assistant", "message": {{"content": [{{"type": "text", "text": text}}]}}}}), flush=True)
    say("the login form echoes {flag}")
    for i in range({steps} - 1):
        say(f"probing step {{i}}")
    for _ in range(200):
        if os.path.exists(marker):
            break
        time.sleep(0.05)
    print(json.dumps({{"type": "result", "subtype": "success"}}), flush=True)
''')


@pytest.mark.parametrize("submit, expected", [
    ("1", ["submit", "submit", "curate", "submit", "curate", "submit"]),
    ("0", ["submit", "curate", "curate", "submit"]),
])
def test_each_watcher_cycle_submits_candidates_before_curating(worker, monkeypatch, submit, expected):
    events: list[str] = []
    marker = worker.tmp / "periodic_watcher_ran"

    def fake_submit(code, flag):
        assert (code, flag) == (CODE, FLAG)
        events.append("submit")
        return tools.FlagSubmitOutcome(definitive=False)

    class FakeLLM:
        def invoke(self, messages):
            events.append("curate")
            marker.touch()
            return SimpleNamespace(content=json.dumps({"add": ["lead: /login echoes its input"]}))

    stub = worker.tmp / "engine_stub.py"
    stub.write_text(SESSION_STUB.format(marker=str(marker), flag=FLAG, steps=claude_agent._WATCHER_EVERY))
    fake_engine = SimpleNamespace(
        NAME="stub", BINARY_NAME=sys.executable,
        session_cmd=lambda prompt, *a, **kw: [sys.executable, str(stub)],
        claude_events=claude_agent._claude_events,
    )
    monkeypatch.setattr(engines, "current", lambda: fake_engine)
    monkeypatch.setattr(tools, "submit_flag_outcome", fake_submit)
    monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: FakeLLM())
    monkeypatch.setenv("CRUISER_WATCHER_SUBMIT", submit)

    claude_agent.run_auto_scan("http://t", quiet=True, challenge_code=CODE, solver_task="probe the login form")

    assert events == expected
    assert [f["text"] for f in ledger.facts(CODE)] == ["lead: /login echoes its input"]


ENGINE_CLI_STUB = textwrap.dedent('''\
    #!{python}
    import json, os, sys
    engine = os.path.basename(sys.argv[0])
    args = sys.argv[1:]
    watcher = "read-only" in args if engine == "codex" else "--auto" not in args
    record = {{
        "role": "watcher" if watcher else "session",
        "dir": os.path.realpath(args[args.index("-C") + 1] if "-C" in args else os.getcwd()),
        "cwd": os.path.realpath(os.getcwd()),
        "env_ws": os.environ.get("CRUISER_WORKSPACE_DIR"),
    }}
    with open({log!r}, "a") as f:
        f.write(json.dumps(record) + "\\n")
    reply = json.dumps({{"add": ["lead: the stub engine ran"]}})
    text = reply if watcher else "looked around, stopping now"
    if engine == "codex":
        print(json.dumps({{"type": "item.completed", "item": {{"type": "agent_message", "text": text}}}}))
        if not watcher:
            print(json.dumps({{"type": "turn.completed"}}))
    else:
        print(json.dumps({{"type": "text", "part": {{"text": text}}}}))
''')


@pytest.mark.parametrize("engine", ["opencode", "codex"])
def test_engine_children_run_in_the_workspace_the_worker_chose_without_exporting_it(worker, monkeypatch, engine):
    log = worker.tmp / "children.jsonl"
    bin_dir = worker.tmp / "bin"
    bin_dir.mkdir()
    cli = bin_dir / engine
    cli.write_text(ENGINE_CLI_STUB.format(python=sys.executable, log=str(log)))
    cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("CRUISER_ENGINE", engine)
    monkeypatch.setenv("CRUISER_WATCHER_SUBMIT", "0")

    claude_agent.run_auto_scan("http://t", quiet=True, challenge_code=CODE, solver_task="look around")

    session, watcher = [json.loads(ln) for ln in log.read_text().splitlines()]
    workspace = session["dir"]
    assert session["role"] == "session" and watcher["role"] == "watcher"
    assert os.path.dirname(workspace) == os.path.realpath(worker.tmp / "workspaces")
    assert session["cwd"] == workspace and os.path.realpath(session["env_ws"]) == workspace
    assert watcher["dir"] == workspace
    assert "CRUISER_WORKSPACE_DIR" not in os.environ
    assert [f["text"] for f in ledger.facts(CODE)] == ["lead: the stub engine ran"]
