from __future__ import annotations

import hashlib
import json
import multiprocessing
import random

import pytest

from cruiser.challenges import Platform, UnknownChallenge

MULTI_FLAGS = [f"flag{{part_{i:02d}_of_twenty}}" for i in range(20)]


@pytest.fixture
def plat(write_yaml, tmp_path):
    sha = hashlib.sha256(b"flag{hashed_secret}").hexdigest()
    flags = "\n".join(f"              - {f}" for f in MULTI_FLAGS)
    path = write_yaml(f"""
        challenges:
          - code: WEB-1
            flags:
              - flag{{plain_text_one}}
              - sha256:{sha}
            target: http://127.0.0.1:1
            hint: look at robots.txt
          - code: WEB-2
            flags: ["flag{{only_flag_here}}"]
            target: http://127.0.0.1:2
          - code: MULTI-1
            flags:
{flags}
            target: http://127.0.0.1:3
    """)
    return Platform(str(path), str(tmp_path / "reports" / "_platform_state.json"))


def test_plaintext_and_sha256_progress(plat):
    assert plat.progress("WEB-1") == (0, 2)

    r = plat.submit("WEB-1", "flag{wrong_guess_here}")
    assert (r.correct, r.duplicate, r.correct_count, r.total) == (False, False, 0, 2)

    r = plat.submit("WEB-1", "  flag{plain_text_one}\n")  # leading/trailing whitespace does not matter
    assert (r.correct, r.duplicate, r.correct_count, r.total) == (True, False, 1, 2)
    assert not {s.code: s for s in plat.list_challenges()}["WEB-1"].completed

    r = plat.submit("WEB-1", "flag{hashed_secret}")
    assert (r.correct, r.duplicate, r.correct_count, r.total) == (True, False, 2, 2)
    assert {s.code: s for s in plat.list_challenges()}["WEB-1"].completed

    # the sha256 spec itself is not a valid submission
    assert not plat.submit("WEB-1", "sha256:" + hashlib.sha256(b"flag{hashed_secret}").hexdigest()).correct


def test_duplicate_submission_is_idempotent(plat):
    assert plat.submit("WEB-2", "flag{only_flag_here}").duplicate is False
    r = plat.submit("WEB-2", "flag{only_flag_here}")
    assert (r.correct, r.duplicate, r.correct_count, r.total) == (True, True, 1, 1)


def test_flags_are_case_sensitive_and_scoped_per_challenge(plat):
    assert not plat.submit("WEB-2", "FLAG{ONLY_FLAG_HERE}").correct
    assert not plat.submit("WEB-2", "flag{plain_text_one}").correct
    assert plat.progress("WEB-1") == (0, 2)


def test_unknown_challenge(plat):
    with pytest.raises(UnknownChallenge):
        plat.submit("NOPE-1", "flag{x}")
    with pytest.raises(UnknownChallenge):
        plat.progress("NOPE-1")


def test_hint(plat):
    assert plat.hint("WEB-1") == "look at robots.txt"
    assert plat.hint("WEB-2") == ""


def test_state_persists_across_instances_and_reset(plat):
    plat.submit("WEB-1", "flag{plain_text_one}")
    plat.submit("WEB-2", "flag{only_flag_here}")
    other = Platform(plat.challenges_file, plat.state_file)
    assert other.progress("WEB-1") == (1, 2)
    assert json.load(open(plat.state_file))["challenges"]["WEB-1"]["solved"] == [0]

    other.reset(["WEB-1"])
    assert plat.progress("WEB-1") == (0, 2) and plat.progress("WEB-2") == (1, 1)
    other.reset()
    assert plat.progress("WEB-2") == (0, 1)


def test_corrupt_state_file_recovers(plat):
    import os
    os.makedirs(os.path.dirname(plat.state_file), exist_ok=True)
    with open(plat.state_file, "w") as f:
        f.write("{not json")
    assert plat.progress("WEB-1") == (0, 2)
    assert plat.submit("WEB-1", "flag{plain_text_one}").correct_count == 1
    assert plat.progress("WEB-1") == (1, 2)


def test_cli_reset(plat, monkeypatch, capsys):
    import cruiser.challenges as challenges
    plat.submit("WEB-2", "flag{only_flag_here}")
    monkeypatch.setattr(challenges, "_PLATFORM", plat)
    monkeypatch.setenv(challenges.CHALLENGES_ENV, plat.challenges_file)
    assert challenges._cli(["reset", "WEB-2"]) == 0
    assert plat.progress("WEB-2") == (0, 1)
    assert challenges._cli(["list"]) == 0
    assert "MULTI-1" in capsys.readouterr().out


def _submit_many(args):
    """Subprocess: submit every flag (mixed with wrong values) twice in random order; return the list of flags judged correct the first time."""
    challenges_file, state_file, seed = args
    plat = Platform(challenges_file, state_file)
    rnd = random.Random(seed)
    attempts = MULTI_FLAGS * 2 + [f"flag{{wrong_{seed}_{i}}}" for i in range(10)]
    rnd.shuffle(attempts)
    fresh = []
    for flag in attempts:
        r = plat.submit("MULTI-1", flag)
        assert 0 <= r.correct_count <= r.total == len(MULTI_FLAGS)
        if r.correct and not r.duplicate:
            fresh.append(flag)
    return fresh


def test_concurrent_submissions_from_processes(plat):
    plat.challenges()  # validate the YAML first
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(8) as pool:
        results = pool.map(_submit_many, [(plat.challenges_file, plat.state_file, s) for s in range(8)])
    fresh = [f for chunk in results for f in chunk]
    # each flag is judged "correct for the first time" exactly once, with nothing lost or double-counted
    assert sorted(fresh) == sorted(MULTI_FLAGS)
    assert plat.progress("MULTI-1") == (20, 20)
    state = json.load(open(plat.state_file))
    assert state["challenges"]["MULTI-1"]["solved"] == list(range(20))
