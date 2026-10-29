from __future__ import annotations

import os
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# 运行 main.py / tools/*.py 所需的最小项目文件（不含 kb/、reports/ 运行态等）
_COPY_ITEMS = ("main.py", "blackboard_hook.py", "cruiser", "tools", "resource", "frontend")


@pytest.fixture
def write_yaml(tmp_path):
    def _write(text: str, name: str = "challenges.yaml") -> Path:
        path = tmp_path / name
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        return path
    return _write


@pytest.fixture
def platform_env(tmp_path, monkeypatch):
    """隔离的平台单例 + flagstore：所有读写都落在 tmp_path，不碰仓库的 reports/。"""
    import cruiser.challenges as challenges
    import cruiser.tools as tools

    def _setup(yaml_path: Path) -> "challenges.Platform":
        monkeypatch.setenv(challenges.CHALLENGES_ENV, str(yaml_path))
        plat = challenges.Platform(str(yaml_path), str(tmp_path / "state" / "_platform_state.json"))
        monkeypatch.setattr(challenges, "_PLATFORM", plat)
        reports = tmp_path / "reports"
        reports.mkdir(exist_ok=True)
        monkeypatch.setattr(
            tools, "_flagstore_paths",
            lambda: (str(reports / "_flagstore.json"), str(reports / "_flagstore.lock")),
        )
        return plat
    return _setup


@pytest.fixture
def repo_copy(tmp_path) -> Path:
    """把项目复制到临时目录：子进程（main.py / submit_flag.py）写的 reports/ 与仓库隔离。"""
    dst = tmp_path / "repo"
    dst.mkdir()
    for item in _COPY_ITEMS:
        src = REPO_ROOT / item
        if src.is_dir():
            shutil.copytree(src, dst / item, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dst / item)
    (dst / "reports").mkdir()
    return dst


def subprocess_env(**extra: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("CRUISER_")}
    env.update(extra)
    return env
