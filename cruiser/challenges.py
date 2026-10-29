"""本地题目平台：从 YAML 读取题目定义，管理靶场生命周期、提示与 flag 校验进度。

调度器（main.py）、worker 与 Agent 调用的 tools/submit_flag.py 都是独立进程，
因此解题进度落盘在 reports/_platform_state.json，以 fcntl 文件锁 + 临时文件
os.replace 原子重写保证并发安全（与 taskboard / _FlagStore 相同的文件总线模式）。

题目定义文件：环境变量 CRUISER_CHALLENGES 指定（相对路径按当前目录解析），
默认项目根目录下的 challenges.yaml。格式见 challenges.example.yaml：

    challenges:
      - code: WEB-1                # 必填，形如 <字母数字>-<数字>
        difficulty: easy           # easy / medium / hard（默认 easy）
        description: 题目描述
        hint: 可选提示（三级起才下发给 Agent）
        flags:                     # 至少一个；明文或 sha256:<hex>
          - flag{plain_text}
          - sha256:9f86d0...
        target: http://127.0.0.1:8080          # 二选一：已在运行的服务
        # compose: path/to/docker-compose.yml  # 二选一：docker compose 拉起
        # addresses: ["127.0.0.1:8081"]        # compose 必填：交给 Agent 的地址

命令行：
    python -m cruiser.challenges list            # 查看题目与进度
    python -m cruiser.challenges reset [CODE…]   # 清空进度（不带参数清空全部）
    python -m cruiser.challenges down            # docker compose down 所有 cruiser_* 项目
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHALLENGES_ENV = "CRUISER_CHALLENGES"
DEFAULT_CHALLENGES_FILE = os.path.join(PROJECT_ROOT, "challenges.yaml")
DEFAULT_STATE_FILE = os.path.join(PROJECT_ROOT, "reports", "_platform_state.json")

DIFFICULTIES = ("easy", "medium", "hard")
# 题目代码形如 WEB-1 / pwn-03：Agent 侧捕获 `submit_flag.py <code> <flag>` 调用的正则依赖此形态
CODE_RE = re.compile(r"^[A-Za-z0-9]+-\d+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_KEYS = {"code", "difficulty", "description", "hint", "flags", "target", "compose", "addresses"}
COMPOSE_PREFIX = "cruiser_"
_COMPOSE_TIMEOUT_S = 600


class PlatformError(Exception):
    """本地平台错误基类。"""


class ConfigError(PlatformError):
    """题目定义文件缺失或格式非法。"""


class UnknownChallenge(PlatformError):
    """题目代码不在定义文件中。"""


class StartError(PlatformError):
    """靶场启动失败（docker compose 报错 / 未安装）。"""


@dataclass(frozen=True)
class Challenge:
    code: str
    difficulty: str
    description: str
    hint: str
    flags: tuple[str, ...]
    targets: tuple[str, ...]          # 交给 Agent 的地址（URL）
    compose_file: Optional[str] = None  # 绝对路径；None 表示静态目标

    @property
    def flag_count(self) -> int:
        return len(self.flags)

    @property
    def compose_project(self) -> str:
        return COMPOSE_PREFIX + re.sub(r"[^a-z0-9_-]", "_", self.code.lower())

    def matching_indices(self, flag: str) -> list[int]:
        """返回与提交值匹配的 flag 下标（明文精确匹配，或 sha256:<hex> 哈希匹配）。"""
        value = (flag or "").strip()
        if not value:
            return []
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        out = []
        for i, spec in enumerate(self.flags):
            if spec.startswith("sha256:"):
                if spec[len("sha256:"):] == digest:
                    out.append(i)
            elif spec == value:
                out.append(i)
        return out


@dataclass(frozen=True)
class ChallengeStatus:
    """题目 + 解题进度（list_challenges 返回）。"""
    challenge: Challenge
    correct: int

    @property
    def code(self) -> str:
        return self.challenge.code

    @property
    def total(self) -> int:
        return self.challenge.flag_count

    @property
    def completed(self) -> bool:
        return self.total >= 1 and self.correct >= self.total


@dataclass(frozen=True)
class SubmitResult:
    correct: bool          # 本次提交的值是否为本题的某个 flag
    duplicate: bool        # 该 flag 之前已被交对（幂等）
    correct_count: int     # 本题已交对的 flag 数
    total: int             # 本题 flag 总数


# ---------------------------------------------------------------------------
# YAML 解析与校验
# ---------------------------------------------------------------------------
def _str_list(value: Any, field: str, where: str) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where}: `{field}` 必须是非空字符串或字符串列表")
    out = []
    for item in value:
        if not isinstance(item, (str, int, float)) or isinstance(item, bool) or not str(item).strip():
            raise ConfigError(f"{where}: `{field}` 含有非法项 {item!r}")
        out.append(str(item).strip())
    return out


def _as_url(addr: str) -> str:
    """`host:port` 补成 `http://host:port`；已带协议头的原样保留。"""
    return addr if "://" in addr else f"http://{addr}"


def _parse_flag(spec: str, where: str) -> str:
    if spec.startswith("sha256:"):
        digest = spec[len("sha256:"):].strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise ConfigError(f"{where}: `sha256:` 后必须是 64 位十六进制摘要")
        return "sha256:" + digest
    return spec


def _parse_challenge(raw: Any, index: int, base_dir: str) -> Challenge:
    where = f"challenges[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: 每道题必须是一个映射（key: value）")
    code = str(raw.get("code") or "").strip()
    if code:
        where = f"challenges[{index}] ({code})"
    unknown = set(raw) - _ALLOWED_KEYS
    if unknown:
        raise ConfigError(f"{where}: 未知字段 {sorted(unknown)}；允许字段 {sorted(_ALLOWED_KEYS)}")
    if not code:
        raise ConfigError(f"{where}: 缺少 `code`")
    if not CODE_RE.fullmatch(code):
        raise ConfigError(f"{where}: `code` 必须形如 <字母数字>-<数字>（如 WEB-1），实际为 {code!r}")

    difficulty = str(raw.get("difficulty") or "easy").strip().lower()
    if difficulty not in DIFFICULTIES:
        raise ConfigError(f"{where}: `difficulty` 必须是 {'/'.join(DIFFICULTIES)} 之一，实际为 {difficulty!r}")

    if "flags" not in raw:
        raise ConfigError(f"{where}: 缺少 `flags`")
    flags = tuple(_parse_flag(f, where) for f in _str_list(raw["flags"], "flags", where))

    has_target = raw.get("target") is not None
    has_compose = raw.get("compose") is not None
    if has_target == has_compose:
        raise ConfigError(f"{where}: `target` 与 `compose` 必须且只能填写一个")
    compose_file = None
    if has_target:
        if raw.get("addresses") is not None:
            raise ConfigError(f"{where}: `addresses` 只用于 compose 题目；静态目标直接写在 `target`")
        targets = tuple(_as_url(t) for t in _str_list(raw["target"], "target", where))
    else:
        compose = str(raw["compose"]).strip()
        compose_file = compose if os.path.isabs(compose) else os.path.normpath(os.path.join(base_dir, compose))
        if not os.path.isfile(compose_file):
            raise ConfigError(f"{where}: compose 文件不存在: {compose_file}")
        if raw.get("addresses") is None:
            raise ConfigError(f"{where}: compose 题目必须填写 `addresses`（交给 Agent 的 host:port 列表）")
        targets = tuple(_as_url(a) for a in _str_list(raw["addresses"], "addresses", where))

    return Challenge(
        code=code,
        difficulty=difficulty,
        description=str(raw.get("description") or "").strip(),
        hint=str(raw.get("hint") or "").strip(),
        flags=flags,
        targets=targets,
        compose_file=compose_file,
    )


def load_challenges(path: str) -> list[Challenge]:
    """解析并校验题目定义文件。顶层可以是 `challenges:` 映射，也可以直接是列表。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigError(
            f"题目定义文件不存在: {path}（复制 challenges.example.yaml 为 challenges.yaml，"
            f"或用 {CHALLENGES_ENV} 指定路径）"
        ) from None
    except yaml.YAMLError as e:
        raise ConfigError(
            f"题目定义文件 YAML 语法错误: {path}: {e}\n"
            "提示：flag 含花括号，写在行内列表 [...] 里时必须加引号，如 flags: [\"flag{x}\"]"
        ) from None
    if isinstance(doc, dict):
        extra = set(doc) - {"challenges"}
        if extra:
            raise ConfigError(f"{path}: 顶层只允许 `challenges` 字段，发现 {sorted(extra)}")
        doc = doc.get("challenges")
    if not isinstance(doc, list) or not doc:
        raise ConfigError(f"{path}: 未定义任何题目（需要 `challenges:` 列表）")
    base_dir = os.path.dirname(os.path.abspath(path))
    challenges = [_parse_challenge(raw, i, base_dir) for i, raw in enumerate(doc)]
    seen: set[str] = set()
    for ch in challenges:
        if ch.code in seen:
            raise ConfigError(f"{path}: 题目代码重复: {ch.code}")
        seen.add(ch.code)
    return challenges


def challenges_path() -> str:
    raw = (os.environ.get(CHALLENGES_ENV) or "").strip()
    return os.path.abspath(raw) if raw else DEFAULT_CHALLENGES_FILE


def target_host_port(url: str) -> Optional[tuple[str, int]]:
    """从目标 URL 解析 (host, port)，供端口就绪探测；无法解析返回 None。"""
    try:
        parts = urlsplit(_as_url(url))
        if not parts.hostname:
            return None
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
        return (parts.hostname, int(port)) if port else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 平台
# ---------------------------------------------------------------------------
Runner = Callable[..., subprocess.CompletedProcess]


class Platform:
    """本地题目平台。线程/进程安全：进度读写全程持有 state 文件锁。"""

    def __init__(self, challenges_file: Optional[str] = None, state_file: Optional[str] = None,
                 runner: Optional[Runner] = None):
        self.challenges_file = os.path.abspath(challenges_file) if challenges_file else challenges_path()
        self.state_file = os.path.abspath(state_file) if state_file else DEFAULT_STATE_FILE
        self._run = runner or subprocess.run
        self._cache_lock = threading.Lock()
        self._cache: tuple[float, list[Challenge]] | None = None

    # -- 题目定义（按 mtime 缓存，文件改动后自动重读） --------------------------
    def challenges(self) -> list[Challenge]:
        try:
            mtime = os.path.getmtime(self.challenges_file)
        except OSError:
            mtime = -1.0
        with self._cache_lock:
            if self._cache is None or self._cache[0] != mtime:
                self._cache = (mtime, load_challenges(self.challenges_file))
            return list(self._cache[1])

    def get(self, code: str) -> Challenge:
        for ch in self.challenges():
            if ch.code == code:
                return ch
        raise UnknownChallenge(f"未知题目: {code}（不在 {self.challenges_file} 中）")

    # -- 进度状态 --------------------------------------------------------------
    def _locked_state(self, write: bool):
        return _StateFile(self.state_file, write=write)

    @staticmethod
    def _solved_indices(state: dict, ch: Challenge) -> set[int]:
        entry = (state.get("challenges") or {}).get(ch.code) or {}
        return {i for i in entry.get("solved") or [] if isinstance(i, int) and 0 <= i < ch.flag_count}

    def list_challenges(self) -> list[ChallengeStatus]:
        challenges = self.challenges()
        with self._locked_state(write=False) as st:
            return [ChallengeStatus(ch, len(self._solved_indices(st.data, ch))) for ch in challenges]

    def progress(self, code: str) -> tuple[int, int]:
        ch = self.get(code)
        with self._locked_state(write=False) as st:
            return len(self._solved_indices(st.data, ch)), ch.flag_count

    def submit(self, code: str, flag: str) -> SubmitResult:
        ch = self.get(code)
        matches = ch.matching_indices(flag)
        with self._locked_state(write=True) as st:
            solved = self._solved_indices(st.data, ch)
            if not matches:
                return SubmitResult(False, False, len(solved), ch.flag_count)
            fresh = [i for i in matches if i not in solved]
            if not fresh:
                return SubmitResult(True, True, len(solved), ch.flag_count)
            solved.add(fresh[0])
            st.data.setdefault("challenges", {})[ch.code] = {"solved": sorted(solved)}
            st.dirty = True
            return SubmitResult(True, False, len(solved), ch.flag_count)

    def reset(self, codes: Optional[list[str]] = None) -> None:
        with self._locked_state(write=True) as st:
            if codes:
                for code in codes:
                    (st.data.get("challenges") or {}).pop(code, None)
            else:
                st.data = {"challenges": {}}
            st.dirty = True

    def hint(self, code: str) -> str:
        return self.get(code).hint

    # -- 靶场生命周期 ----------------------------------------------------------
    def _compose(self, ch: Challenge, *args: str) -> subprocess.CompletedProcess:
        cmd = ["docker", "compose", "-p", ch.compose_project, "-f", ch.compose_file, *args]
        try:
            return self._run(cmd, capture_output=True, text=True, timeout=_COMPOSE_TIMEOUT_S)
        except FileNotFoundError:
            raise StartError("未找到 docker 命令：compose 题目需要安装 Docker（含 compose 插件）") from None
        except subprocess.TimeoutExpired:
            raise StartError(f"`{' '.join(cmd)}` 超时（{_COMPOSE_TIMEOUT_S}s）") from None

    def start(self, code: str) -> list[str]:
        """启动靶场并返回交给 Agent 的目标 URL 列表。静态目标直接返回，不做任何操作。"""
        ch = self.get(code)
        if ch.compose_file:
            res = self._compose(ch, "up", "-d")
            if res.returncode != 0:
                tail = ((res.stderr or "") + (res.stdout or "")).strip()[-800:]
                raise StartError(f"docker compose up 失败（{ch.compose_project}）: {tail}")
        return list(ch.targets)

    def close(self, code: str) -> None:
        """关闭靶场（docker compose down -v）。静态目标为空操作。"""
        ch = self.get(code)
        if ch.compose_file:
            res = self._compose(ch, "down", "-v")
            if res.returncode != 0:
                tail = ((res.stderr or "") + (res.stdout or "")).strip()[-800:]
                raise PlatformError(f"docker compose down 失败（{ch.compose_project}）: {tail}")

    def down_leftovers(self) -> list[str]:
        """docker compose down 所有残留的 cruiser_* 项目（上次异常退出遗留），返回已处理的项目名。

        未安装 docker / compose 时静默返回空列表。
        """
        if shutil.which("docker") is None:
            return []
        try:
            res = self._run(["docker", "compose", "ls", "-a", "--format", "json"],
                            capture_output=True, text=True, timeout=60)
        except Exception:
            return []
        if res.returncode != 0:
            return []
        try:
            projects = json.loads(res.stdout or "[]") or []
        except Exception:
            return []
        done = []
        for proj in projects:
            name = str((proj or {}).get("Name") or "")
            if not name.startswith(COMPOSE_PREFIX):
                continue
            cmd = ["docker", "compose", "-p", name]
            for cfg in str(proj.get("ConfigFiles") or "").split(","):
                if cfg.strip() and os.path.isfile(cfg.strip()):
                    cmd += ["-f", cfg.strip()]
            cmd += ["down", "-v"]
            try:
                self._run(cmd, capture_output=True, text=True, timeout=_COMPOSE_TIMEOUT_S)
                done.append(name)
            except Exception:
                pass
        return done


class _StateFile:
    """flock 保护下读（改写）_platform_state.json；写回走临时文件 + os.replace。"""

    def __init__(self, path: str, write: bool):
        self.path = path
        self.write = write
        self.data: dict = {}
        self.dirty = False
        self._lf = None

    def __enter__(self) -> "_StateFile":
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._lf = open(self.path + ".lock", "a+")
        fcntl.flock(self._lf, fcntl.LOCK_EX if self.write else fcntl.LOCK_SH)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.data = {}
        except Exception:
            # 损坏的状态文件不应让平台不可用：保留一份备份后从空状态继续
            if self.write:
                try:
                    os.replace(self.path, self.path + ".corrupt")
                except OSError:
                    pass
            self.data = {}
        if not isinstance(self.data, dict):
            self.data = {}
        self.data.setdefault("challenges", {})
        return self

    def __exit__(self, exc_type, *exc) -> None:
        try:
            if self.write and self.dirty and exc_type is None:
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), prefix=".platform_state.")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self.data, f, ensure_ascii=False, indent=2)
                os.replace(tmp, self.path)
        finally:
            fcntl.flock(self._lf, fcntl.LOCK_UN)
            self._lf.close()


_PLATFORM: Optional[Platform] = None
_PLATFORM_LOCK = threading.Lock()


def get_platform() -> Platform:
    """进程级单例（题目定义路径取自 CRUISER_CHALLENGES）。"""
    global _PLATFORM
    with _PLATFORM_LOCK:
        if _PLATFORM is None or _PLATFORM.challenges_file != challenges_path():
            _PLATFORM = Platform()
        return _PLATFORM


# ---------------------------------------------------------------------------
# 命令行
# ---------------------------------------------------------------------------
def _cli(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m cruiser.challenges", description="Cruiser 本地题目平台")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="列出题目与 flag 进度")
    p_reset = sub.add_parser("reset", help="清空解题进度")
    p_reset.add_argument("codes", nargs="*", help="只清空这些题（默认全部）")
    sub.add_parser("down", help="docker compose down 所有 cruiser_* 项目")
    args = parser.parse_args(argv)

    plat = get_platform()
    try:
        if args.cmd == "list":
            print(f"# {plat.challenges_file}")
            for st in plat.list_challenges():
                ch = st.challenge
                kind = "compose" if ch.compose_file else "target"
                mark = "✓" if st.completed else " "
                print(f"[{mark}] {ch.code:<12} {ch.difficulty:<6} {st.correct}/{st.total}  "
                      f"{kind}: {', '.join(ch.targets)}")
        elif args.cmd == "reset":
            plat.reset(args.codes or None)
            print("已清空进度: " + (", ".join(args.codes) if args.codes else "全部题目"))
        elif args.cmd == "down":
            names = plat.down_leftovers()
            print("已关闭: " + (", ".join(names) if names else "（无 cruiser_* 项目）"))
    except PlatformError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
