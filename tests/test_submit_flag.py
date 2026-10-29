from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest

from conftest import subprocess_env

YAML = f"""
    challenges:
      - code: WEB-1
        flags:
          - flag{{first_of_two}}
          - sha256:{hashlib.sha256(b"flag{second_of_two}").hexdigest()}
        target: http://127.0.0.1:1
      - code: WEB-2
        flags: ["flag{{single_flag_x}}"]
        target: http://127.0.0.1:2
"""


@pytest.fixture
def tools(write_yaml, platform_env):
    platform_env(write_yaml(YAML))
    import cruiser.tools as tools
    return tools


def test_outcome_multi_flag_progress(tools):
    out = tools.submit_flag_outcome("WEB-1", "flag{first_of_two}")
    assert (out.ok, out.fresh, out.definitive, out.correct, out.total) == (True, True, True, 1, 2)
    assert "FLAG CORRECT" in out.output and "flag progress 1/2" in out.output
    assert "This challenge still has 1 flag(s) not submitted" in out.output
    assert not tools.flags_all_collected(out.correct, out.total)

    out = tools.submit_flag_outcome("WEB-1", "flag{second_of_two}")
    assert (out.ok, out.fresh, out.correct, out.total) == (True, True, 2, 2)
    assert "flag progress 2/2" in out.output and "not submitted" not in out.output
    assert tools.flags_all_collected(out.correct, out.total)
    assert tools.query_flag_progress("WEB-1") == (2, 2)


def test_outcome_duplicate_and_wrong(tools):
    tools.submit_flag_outcome("WEB-1", "flag{first_of_two}")
    dup = tools.submit_flag_outcome("WEB-1", "flag{first_of_two}")
    assert (dup.ok, dup.fresh, dup.correct, dup.total) == (True, False, 1, 2)
    assert "ALREADY SUBMITTED" in dup.output and "flag progress 1/2" in dup.output

    wrong = tools.submit_flag_outcome("WEB-1", "flag{definitely_wrong}")
    assert (wrong.ok, wrong.definitive) == (False, True) and "wrong flag" in wrong.output
    again = tools.submit_flag_outcome("WEB-1", "flag{definitely_wrong}")
    assert not again.ok and "a known wrong flag" in again.output

    # an accepted flag submitted for another challenge: the flagstore rejects it outright
    cross = tools.submit_flag_outcome("WEB-2", "flag{first_of_two}")
    assert not cross.ok and "another challenge" in cross.output


def test_outcome_duplicate_when_flagstore_missed_it(tools, tmp_path):
    """The platform has it recorded as correct but the local flagstore does not (e.g. the flagstore was cleared): takes the platform duplicate branch."""
    import cruiser.challenges as challenges
    challenges.get_platform().submit("WEB-2", "flag{single_flag_x}")
    out = tools.submit_flag_outcome("WEB-2", "flag{single_flag_x}")
    assert (out.ok, out.fresh, out.correct, out.total) == (True, False, 1, 1)
    assert "ALREADY SUBMITTED" in out.output


def test_outcome_unknown_challenge(tools):
    out = tools.submit_flag_outcome("NOPE-1", "flag{whatever_value}")
    assert (out.ok, out.definitive) == (False, True) and "unknown challenge" in out.output


def test_langchain_tool_wrapper(tools):
    text = tools.submit_flag.invoke({"challenge_code": "WEB-2", "flag": "flag{single_flag_x}"})
    assert "FLAG CORRECT" in text and "flag progress 1/1" in text


def test_progress_text_is_parsed_by_agent(tools):
    from cruiser.claude_agent import _FLAG_OK_MARKERS, _progress_from_text
    out = tools.submit_flag_outcome("WEB-1", "flag{first_of_two}")
    assert any(m in out.output for m in _FLAG_OK_MARKERS)
    assert _progress_from_text(out.output) == (1, 2)


def _run_cli(repo, yaml_path, code, flag):
    proc = subprocess.run(
        [sys.executable, str(repo / "tools" / "submit_flag.py"), code, flag],
        cwd=str(repo.parent),  # the Agent calls it from its workspace: cwd is not the project root
        env=subprocess_env(CRUISER_CHALLENGES=str(yaml_path)),
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_submit_flag_cli_end_to_end(repo_copy, write_yaml):
    yaml_path = write_yaml(YAML)
    assert "wrong flag" in _run_cli(repo_copy, yaml_path, "WEB-1", "flag{nope_nope_nope}")
    out = _run_cli(repo_copy, yaml_path, "WEB-1", "flag{first_of_two}")
    assert "FLAG CORRECT" in out and "flag progress 1/2" in out
    out = _run_cli(repo_copy, yaml_path, "WEB-1", "flag{first_of_two}")
    assert "ALREADY SUBMITTED" in out and "flag progress 1/2" in out
    out = _run_cli(repo_copy, yaml_path, "WEB-1", "flag{second_of_two}")
    assert "FLAG CORRECT" in out and "flag progress 2/2" in out

    state = json.loads((repo_copy / "reports" / "_platform_state.json").read_text())
    assert state["challenges"]["WEB-1"]["solved"] == [0, 1]
    store = json.loads((repo_copy / "reports" / "_flagstore.json").read_text())
    assert store["correct"] == {"flag{first_of_two}": "WEB-1", "flag{second_of_two}": "WEB-1"}
