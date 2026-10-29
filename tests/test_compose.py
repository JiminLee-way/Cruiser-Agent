from __future__ import annotations

import json
import subprocess

import pytest

import cruiser.challenges as challenges
from cruiser.challenges import Platform, PlatformError, StartError


class FakeRunner:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "", exc: Exception | None = None):
        self.calls: list[list[str]] = []
        self.returncode, self.stdout, self.stderr, self.exc = returncode, stdout, stderr, exc

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        assert kwargs.get("capture_output") and kwargs.get("text")
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def yaml_path(write_yaml, tmp_path):
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "docker-compose.yml").write_text("services: {}\n")
    return write_yaml("""
        challenges:
          - code: Web-12
            flags: ["flag{x}"]
            compose: demo/docker-compose.yml
            addresses: ["127.0.0.1:8081"]
          - code: WEB-2
            flags: ["flag{y}"]
            target: http://127.0.0.1:9999
    """)


def _platform(yaml_path, tmp_path, runner):
    return Platform(str(yaml_path), str(tmp_path / "state.json"), runner=runner)


def test_compose_start_and_close(yaml_path, tmp_path):
    runner = FakeRunner()
    plat = _platform(yaml_path, tmp_path, runner)
    compose_file = str(tmp_path / "demo" / "docker-compose.yml")

    assert plat.start("Web-12") == ["http://127.0.0.1:8081"]
    plat.close("Web-12")
    assert runner.calls == [
        ["docker", "compose", "-p", "cruiser_web-12", "-f", compose_file, "up", "-d"],
        ["docker", "compose", "-p", "cruiser_web-12", "-f", compose_file, "down", "-v"],
    ]


def test_static_target_start_close_are_noops(yaml_path, tmp_path):
    runner = FakeRunner()
    plat = _platform(yaml_path, tmp_path, runner)
    assert plat.start("WEB-2") == ["http://127.0.0.1:9999"]
    plat.close("WEB-2")
    assert runner.calls == []


def test_compose_up_failure_raises(yaml_path, tmp_path):
    plat = _platform(yaml_path, tmp_path, FakeRunner(returncode=1, stderr="port is already allocated"))
    with pytest.raises(StartError, match="port is already allocated"):
        plat.start("Web-12")
    plat_down = _platform(yaml_path, tmp_path, FakeRunner(returncode=1, stderr="boom"))
    with pytest.raises(PlatformError, match="boom"):
        plat_down.close("Web-12")


def test_docker_missing_raises_start_error(yaml_path, tmp_path):
    plat = _platform(yaml_path, tmp_path, FakeRunner(exc=FileNotFoundError("docker")))
    with pytest.raises(StartError, match="docker command not found"):
        plat.start("Web-12")


def test_default_runner_is_subprocess_run(yaml_path, tmp_path, monkeypatch):
    runner = FakeRunner()
    monkeypatch.setattr(subprocess, "run", runner)
    plat = Platform(str(yaml_path), str(tmp_path / "state.json"))
    plat.start("Web-12")
    assert runner.calls[0][:4] == ["docker", "compose", "-p", "cruiser_web-12"]


def test_down_leftovers(yaml_path, tmp_path, monkeypatch):
    cfg = tmp_path / "demo" / "docker-compose.yml"
    listing = json.dumps([
        {"Name": "cruiser_web-12", "Status": "running(1)", "ConfigFiles": str(cfg)},
        {"Name": "cruiser_old-1", "Status": "exited(1)", "ConfigFiles": "/gone/docker-compose.yml"},
        {"Name": "someone_else", "Status": "running(2)", "ConfigFiles": str(cfg)},
    ])
    runner = FakeRunner(stdout=listing)
    monkeypatch.setattr(challenges.shutil, "which", lambda name: "/usr/bin/docker")
    plat = _platform(yaml_path, tmp_path, runner)

    assert plat.down_leftovers() == ["cruiser_web-12", "cruiser_old-1"]
    assert runner.calls == [
        ["docker", "compose", "ls", "-a", "--format", "json"],
        ["docker", "compose", "-p", "cruiser_web-12", "-f", str(cfg), "down", "-v"],
        ["docker", "compose", "-p", "cruiser_old-1", "down", "-v"],
    ]


def test_down_leftovers_without_docker(yaml_path, tmp_path, monkeypatch):
    runner = FakeRunner()
    monkeypatch.setattr(challenges.shutil, "which", lambda name: None)
    assert _platform(yaml_path, tmp_path, runner).down_leftovers() == []
    assert runner.calls == []
    # docker present but the compose plugin missing: silently skipped when ls fails
    monkeypatch.setattr(challenges.shutil, "which", lambda name: "/usr/bin/docker")
    failing = FakeRunner(returncode=125, stderr="unknown command: docker compose")
    assert _platform(yaml_path, tmp_path, failing).down_leftovers() == []
