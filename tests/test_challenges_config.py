from __future__ import annotations

import hashlib

import pytest

from cruiser.challenges import ConfigError, Platform, load_challenges, target_host_port


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_parse_full_document(write_yaml, tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "docker-compose.yml").write_text("services: {}\n")
    path = write_yaml(f"""
        challenges:
          - code: WEB-1
            difficulty: Medium
            description: "  login page  "
            hint: try admin
            flags: ["flag{{one}}", "sha256:{_sha('flag{two}').upper()}"]
            target: 127.0.0.1:8080
          - code: WEB-2
            flags: flag{{solo}}
            compose: web/docker-compose.yml
            addresses: ["127.0.0.1:8081", "tcp://127.0.0.1:9001"]
    """)
    a, b = load_challenges(str(path))

    assert a.code == "WEB-1" and a.difficulty == "medium"
    assert a.description == "login page" and a.hint == "try admin"
    assert a.flags == ("flag{one}", "sha256:" + _sha("flag{two}"))
    assert a.targets == ("http://127.0.0.1:8080",) and a.compose_file is None

    assert b.difficulty == "easy" and b.hint == "" and b.flags == ("flag{solo}",)
    assert b.compose_file == str(tmp_path / "web" / "docker-compose.yml")
    assert b.targets == ("http://127.0.0.1:8081", "tcp://127.0.0.1:9001")
    assert b.compose_project == "cruiser_web-2"


def test_top_level_list_form(write_yaml):
    path = write_yaml("""
        - code: PWN-7
          difficulty: hard
          flags: ["flag{x}"]
          target: [http://10.0.0.1:1, http://10.0.0.2:2]
    """)
    (ch,) = load_challenges(str(path))
    assert ch.targets == ("http://10.0.0.1:1", "http://10.0.0.2:2")


@pytest.mark.parametrize("body, message", [
    ("- {difficulty: easy, flags: [f], target: http://x:1}", "missing `code`"),
    ("- {code: web_one, flags: [f], target: http://x:1}", "must look like"),
    ("- {code: WEB-1, difficulty: insane, flags: [f], target: http://x:1}", "difficulty"),
    ("- {code: WEB-1, target: http://x:1}", "missing `flags`"),
    ("- {code: WEB-1, flags: [], target: http://x:1}", "`flags`"),
    ("- {code: WEB-1, flags: ['sha256:abc'], target: http://x:1}", "64-digit hex"),
    ("- {code: WEB-1, flags: [f]}", "exactly one of"),
    ("- {code: WEB-1, flags: [f], target: http://x:1, compose: a.yml}", "exactly one of"),
    ("- {code: WEB-1, flags: [f], target: http://x:1, addresses: [a:1]}", "`addresses` is only for"),
    ("- {code: WEB-1, flags: [f], compose: missing.yml, addresses: [a:1]}", "compose file does not exist"),
    ("- {code: WEB-1, flags: [f], target: http://x:1, flag: typo}", "unknown fields"),
    ("- {code: WEB-1, flags: [f], target: http://x:1}\n- {code: WEB-1, flags: [g], target: http://y:1}", "duplicate"),
    ("challenges: []", "no challenges defined"),
    ("other: 1", "top level only allows"),
    ("challenges: [unclosed", "YAML syntax error"),
    ("- {code: WEB-1, flags: [flag{x}], target: http://x:1}", "must be quoted"),
])
def test_validation_errors(write_yaml, body, message):
    path = write_yaml(body + "\n")
    with pytest.raises(ConfigError, match=message):
        load_challenges(str(path))


def test_compose_requires_addresses(write_yaml, tmp_path):
    (tmp_path / "dc.yml").write_text("services: {}\n")
    path = write_yaml("- {code: WEB-1, flags: [f], compose: dc.yml}\n")
    with pytest.raises(ConfigError, match="must set `addresses`"):
        load_challenges(str(path))


def test_missing_file_message(tmp_path):
    with pytest.raises(ConfigError, match="challenges.example.yaml"):
        load_challenges(str(tmp_path / "nope.yaml"))


def test_platform_reloads_when_file_changes(write_yaml, tmp_path):
    path = write_yaml("- {code: WEB-1, flags: [f], target: http://x:1}\n")
    plat = Platform(str(path), str(tmp_path / "state.json"))
    assert [c.code for c in plat.challenges()] == ["WEB-1"]
    path.write_text("- {code: WEB-1, flags: [f], target: http://x:1}\n- {code: WEB-2, flags: [g], target: http://y:1}\n")
    import os
    os.utime(path, (1, 1))  # make sure the mtime changes
    assert [c.code for c in plat.challenges()] == ["WEB-1", "WEB-2"]


def test_example_yaml_is_valid():
    from conftest import REPO_ROOT
    (ch,) = [c for c in load_challenges(str(REPO_ROOT / "challenges.example.yaml"))]
    assert ch.code == "DEMO-1" and ch.compose_file.endswith("examples/web-demo/docker-compose.yml")
    assert ch.matching_indices("flag{cruiser_local_demo_path_traversal}") == [0]


@pytest.mark.parametrize("url, expected", [
    ("http://127.0.0.1:8080", ("127.0.0.1", 8080)),
    ("127.0.0.1:9000", ("127.0.0.1", 9000)),
    ("https://example.com/path", ("example.com", 443)),
    ("http://example.com", ("example.com", 80)),
    ("tcp://10.0.0.1:31337", ("10.0.0.1", 31337)),
    ("tcp://10.0.0.1", None),
])
def test_target_host_port(url, expected):
    assert target_host_port(url) == expected
