from __future__ import annotations

import os
import sys
import textwrap
from types import SimpleNamespace

import pytest

from cruiser import claude_agent, codex_engine, ledger, prompt, taskboard

CODE = "T-1"
ROLE_WORKERS = {"explorer": "2", "lead": claude_agent.LEAD_SLOT, "solver": "solver1"}
DIRECTION = "check how the session cookie is signed"
OLD_COMPETITION_TEXT = ("/root/Cruiser", "sqlmap", "dirsearch", "XSS", "SQL injection", "ysoserial", "CTF Web", "/24")


@pytest.fixture
def run_session(tmp_path, monkeypatch):
    """Run one session through the codex engine against a stub binary and return the message it was given."""
    cwd = tmp_path / "cwd"
    (cwd / "reports").mkdir(parents=True)
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(ledger, "_reports_dir", lambda: str(cwd / "reports"))
    monkeypatch.setattr(taskboard, "_reports_dir", lambda: str(cwd / "reports"))
    monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: None)
    monkeypatch.setenv("CRUISER_ENGINE", "codex")
    monkeypatch.setenv("CRUISER_WATCHER_SUBMIT", "0")
    seen = tmp_path / "message.txt"
    stub = tmp_path / "codex_stub.py"
    stub.write_text(textwrap.dedent(f'''\
        #!{sys.executable}
        import sys
        open({str(seen)!r}, "w", encoding="utf-8").write(sys.argv[-1])
        print('{{"type": "turn.completed"}}')
    '''))
    stub.chmod(0o755)
    monkeypatch.setattr(codex_engine, "binary", lambda: str(stub))

    def _run(role: str, root=None, hint: str = "") -> str:
        worker = ROLE_WORKERS[role]
        ws = tmp_path / f"ws_{role}"
        ws.mkdir(exist_ok=True)
        if root is not None:
            monkeypatch.setenv("CRUISER_CODEX_ROOT", str(root))
        claude_agent._run_one_session("http://t", hint, CODE, worker, str(ws), True, [0],
                                      solver_task=DIRECTION if role == "solver" else None)
        return seen.read_text(encoding="utf-8")

    return _run


def _first_line(part: str) -> str:
    return part.split("\n", 1)[0]


@pytest.mark.parametrize("role", list(ROLE_WORKERS))
def test_each_role_is_assembled_from_its_parts_in_the_table(run_session, role):
    message = run_session(role)
    for name, part in prompt.PARTS.items():
        expected = name in prompt.ROLES[role].parts
        assert (_first_line(part) in message) == expected, name


@pytest.mark.parametrize("role", list(ROLE_WORKERS))
def test_every_role_is_told_how_to_submit_and_report(run_session, role):
    message = run_session(role)
    worker = ROLE_WORKERS[role]
    assert f"submit_flag.py {CODE} '<" in message
    assert "FLAG CORRECT" in message and "flag progress X/Y" in message
    assert f"task_board.py report {CODE} {worker} '<" in message and "--basis" in message
    assert os.path.join("reports", f"info_{CODE}.txt") in message


def test_solver_gets_its_direction_and_explorer_gets_the_hint(run_session):
    assert DIRECTION in run_session("solver")
    explorer = run_session("explorer", hint="the name parameter reaches the file path")
    assert "the name parameter reaches the file path" in explorer
    assert DIRECTION not in explorer


@pytest.mark.parametrize("role", list(ROLE_WORKERS))
def test_skills_pointer_appears_only_when_the_working_root_has_skills(run_session, tmp_path, role):
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    entry = os.path.join(str(root), "skills", "solve-challenge", "SKILL.md")
    assert entry not in run_session(role, root=root)
    (root / "skills").mkdir()
    assert entry in run_session(role, root=root)


@pytest.mark.parametrize("role", list(ROLE_WORKERS))
def test_session_prompts_require_english(run_session, role):
    assert "english" in run_session(role).lower()


@pytest.mark.parametrize("role", list(ROLE_WORKERS))
def test_session_prompts_carry_no_old_competition_text(run_session, role):
    message = run_session(role)
    for text in OLD_COMPETITION_TEXT:
        assert text not in message, text


def test_prompt_module_carries_no_old_competition_text():
    texts = [v for v in vars(prompt).values() if isinstance(v, str)] + list(prompt.PARTS.values())
    for text in OLD_COMPETITION_TEXT:
        assert not any(text in t for t in texts), text


@pytest.fixture
def watcher_system(tmp_path, monkeypatch):
    """Return the system message of every watcher LLM call made while running fn."""
    monkeypatch.setattr(ledger, "_reports_dir", lambda: str(tmp_path))
    monkeypatch.setattr(taskboard, "_reports_dir", lambda: str(tmp_path))
    monkeypatch.chdir(tmp_path)
    seen: list[str] = []

    class FakeLLM:
        def invoke(self, messages):
            seen.append(messages[0].content)
            return SimpleNamespace(content="{}")

    monkeypatch.setattr(claude_agent, "_get_watcher_llm", lambda ws_dir: FakeLLM())

    def _calls(fn) -> list[str]:
        seen.clear()
        fn()
        return list(seen)

    return _calls


def test_watcher_prompts_require_english(watcher_system, tmp_path):
    curate = watcher_system(lambda: claude_agent._watcher_curate_blackboard(
        CODE, "2", "Thought: read the grid", str(tmp_path)))
    method = watcher_system(lambda: claude_agent._compose_flag_method(
        "1/1", "Thought: read the grid\nAction: shell: cat grid", str(tmp_path)))
    assert curate and method
    assert all("english" in s.lower() for s in curate + method)
