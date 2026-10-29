"""Local challenge platform: reads challenge definitions from YAML and manages target lifecycle, hints and flag verification progress.

The scheduler (main.py), the workers and the tools/submit_flag.py the Agent calls are all separate processes,
so solving progress is persisted to reports/_platform_state.json, with an fcntl file lock + temp file
os.replace atomic rewrite for concurrency safety (the same file-bus pattern as taskboard / _FlagStore).

Challenge definition file: set by the CRUISER_CHALLENGES environment variable (relative paths resolve against the current directory),
defaulting to challenges.yaml in the project root. See challenges.example.yaml for the format:

    challenges:
      - code: WEB-1                # required, of the form <alphanumeric>-<digits>
        difficulty: easy           # easy / medium / hard (default easy)
        description: challenge description
        hint: optional hint (only given to the Agent from tier 3 on)
        flags:                     # at least one; plaintext or sha256:<hex>
          - flag{plain_text}
          - sha256:9f86d0...
        target: http://127.0.0.1:8080          # one of two: an already running service
        # compose: path/to/docker-compose.yml  # one of two: brought up with docker compose
        # addresses: ["127.0.0.1:8081"]        # required for compose: the addresses given to the Agent

Command line:
    python -m cruiser.challenges list            # show challenges and progress
    python -m cruiser.challenges reset [CODE…]   # clear progress (no arguments clears everything)
    python -m cruiser.challenges down            # docker compose down all cruiser_* projects
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
# Challenge codes look like WEB-1 / pwn-03: the regex that captures Agent-side `submit_flag.py <code> <flag>` calls relies on this shape
CODE_RE = re.compile(r"^[A-Za-z0-9]+-\d+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_KEYS = {"code", "difficulty", "description", "hint", "flags", "target", "compose", "addresses"}
COMPOSE_PREFIX = "cruiser_"
_COMPOSE_TIMEOUT_S = 600


class PlatformError(Exception):
    """Base class for local platform errors."""


class ConfigError(PlatformError):
    """The challenge definition file is missing or malformed."""


class UnknownChallenge(PlatformError):
    """The challenge code is not in the definition file."""


class StartError(PlatformError):
    """Failed to start the target (docker compose error / not installed)."""


@dataclass(frozen=True)
class Challenge:
    code: str
    difficulty: str
    description: str
    hint: str
    flags: tuple[str, ...]
    targets: tuple[str, ...]          # addresses (URLs) given to the Agent
    compose_file: Optional[str] = None  # absolute path; None means a static target

    @property
    def flag_count(self) -> int:
        return len(self.flags)

    @property
    def compose_project(self) -> str:
        return COMPOSE_PREFIX + re.sub(r"[^a-z0-9_-]", "_", self.code.lower())

    def matching_indices(self, flag: str) -> list[int]:
        """Return the index of the flag matching the submitted value (exact plaintext match, or sha256:<hex> hash match)."""
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
    """Challenge + solving progress (returned by list_challenges)."""
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
    correct: bool          # whether the submitted value is one of this challenge's flags
    duplicate: bool        # this flag was already accepted before (idempotent)
    correct_count: int     # number of accepted flags for this challenge
    total: int             # total number of flags for this challenge


# ---------------------------------------------------------------------------
# YAML parsing and validation
# ---------------------------------------------------------------------------
def _str_list(value: Any, field: str, where: str) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where}: `{field}` must be a non-empty string or list of strings")
    out = []
    for item in value:
        if not isinstance(item, (str, int, float)) or isinstance(item, bool) or not str(item).strip():
            raise ConfigError(f"{where}: `{field}` contains an invalid item {item!r}")
        out.append(str(item).strip())
    return out


def _as_url(addr: str) -> str:
    """Expand `host:port` to `http://host:port`; values that already have a scheme are kept as is."""
    return addr if "://" in addr else f"http://{addr}"


def _parse_flag(spec: str, where: str) -> str:
    if spec.startswith("sha256:"):
        digest = spec[len("sha256:"):].strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise ConfigError(f"{where}: `sha256:` must be followed by a 64-digit hex digest")
        return "sha256:" + digest
    return spec


def _parse_challenge(raw: Any, index: int, base_dir: str) -> Challenge:
    where = f"challenges[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: each challenge must be a mapping (key: value)")
    code = str(raw.get("code") or "").strip()
    if code:
        where = f"challenges[{index}] ({code})"
    unknown = set(raw) - _ALLOWED_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown fields {sorted(unknown)}; allowed fields {sorted(_ALLOWED_KEYS)}")
    if not code:
        raise ConfigError(f"{where}: missing `code`")
    if not CODE_RE.fullmatch(code):
        raise ConfigError(f"{where}: `code` must look like <alphanumeric>-<digits> (e.g. WEB-1), got {code!r}")

    difficulty = str(raw.get("difficulty") or "easy").strip().lower()
    if difficulty not in DIFFICULTIES:
        raise ConfigError(f"{where}: `difficulty` must be one of {'/'.join(DIFFICULTIES)}, got {difficulty!r}")

    if "flags" not in raw:
        raise ConfigError(f"{where}: missing `flags`")
    flags = tuple(_parse_flag(f, where) for f in _str_list(raw["flags"], "flags", where))

    has_target = raw.get("target") is not None
    has_compose = raw.get("compose") is not None
    if has_target == has_compose:
        raise ConfigError(f"{where}: exactly one of `target` and `compose` must be set")
    compose_file = None
    if has_target:
        if raw.get("addresses") is not None:
            raise ConfigError(f"{where}: `addresses` is only for compose challenges; put static targets directly in `target`")
        targets = tuple(_as_url(t) for t in _str_list(raw["target"], "target", where))
    else:
        compose = str(raw["compose"]).strip()
        compose_file = compose if os.path.isabs(compose) else os.path.normpath(os.path.join(base_dir, compose))
        if not os.path.isfile(compose_file):
            raise ConfigError(f"{where}: compose file does not exist: {compose_file}")
        if raw.get("addresses") is None:
            raise ConfigError(f"{where}: compose challenges must set `addresses` (the host:port list given to the Agent)")
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
    """Parse and validate the challenge definition file. The top level may be a `challenges:` mapping or a bare list."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigError(
            f"challenge definition file does not exist: {path} (copy challenges.example.yaml to challenges.yaml, "
            f"or set the path with {CHALLENGES_ENV})"
        ) from None
    except yaml.YAMLError as e:
        raise ConfigError(
            f"YAML syntax error in challenge definition file: {path}: {e}\n"
            "hint: flags contain braces and must be quoted inside an inline list [...], e.g. flags: [\"flag{x}\"]"
        ) from None
    if isinstance(doc, dict):
        extra = set(doc) - {"challenges"}
        if extra:
            raise ConfigError(f"{path}: the top level only allows the `challenges` field, found {sorted(extra)}")
        doc = doc.get("challenges")
    if not isinstance(doc, list) or not doc:
        raise ConfigError(f"{path}: no challenges defined (a `challenges:` list is required)")
    base_dir = os.path.dirname(os.path.abspath(path))
    challenges = [_parse_challenge(raw, i, base_dir) for i, raw in enumerate(doc)]
    seen: set[str] = set()
    for ch in challenges:
        if ch.code in seen:
            raise ConfigError(f"{path}: duplicate challenge code: {ch.code}")
        seen.add(ch.code)
    return challenges


def challenges_path() -> str:
    raw = (os.environ.get(CHALLENGES_ENV) or "").strip()
    return os.path.abspath(raw) if raw else DEFAULT_CHALLENGES_FILE


def target_host_port(url: str) -> Optional[tuple[str, int]]:
    """Parse (host, port) from the target URL for port readiness probing; returns None if it cannot be parsed."""
    try:
        parts = urlsplit(_as_url(url))
        if not parts.hostname:
            return None
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
        return (parts.hostname, int(port)) if port else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------
Runner = Callable[..., subprocess.CompletedProcess]


class Platform:
    """Local challenge platform. Thread/process safe: progress reads and writes hold the state file lock throughout."""

    def __init__(self, challenges_file: Optional[str] = None, state_file: Optional[str] = None,
                 runner: Optional[Runner] = None):
        self.challenges_file = os.path.abspath(challenges_file) if challenges_file else challenges_path()
        self.state_file = os.path.abspath(state_file) if state_file else DEFAULT_STATE_FILE
        self._run = runner or subprocess.run
        self._cache_lock = threading.Lock()
        self._cache: tuple[float, list[Challenge]] | None = None

    # -- challenge definitions (cached by mtime, reloaded automatically when the file changes) --
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
        raise UnknownChallenge(f"unknown challenge: {code} (not in {self.challenges_file})")

    # -- progress state ---------------------------------------------------------
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

    # -- target lifecycle -------------------------------------------------------
    def _compose(self, ch: Challenge, *args: str) -> subprocess.CompletedProcess:
        cmd = ["docker", "compose", "-p", ch.compose_project, "-f", ch.compose_file, *args]
        try:
            return self._run(cmd, capture_output=True, text=True, timeout=_COMPOSE_TIMEOUT_S)
        except FileNotFoundError:
            raise StartError("docker command not found: compose challenges require Docker (with the compose plugin)") from None
        except subprocess.TimeoutExpired:
            raise StartError(f"`{' '.join(cmd)}` timed out ({_COMPOSE_TIMEOUT_S}s)") from None

    def start(self, code: str) -> list[str]:
        """Start the target and return the list of target URLs given to the Agent. Static targets are returned directly without doing anything."""
        ch = self.get(code)
        if ch.compose_file:
            res = self._compose(ch, "up", "-d")
            if res.returncode != 0:
                tail = ((res.stderr or "") + (res.stdout or "")).strip()[-800:]
                raise StartError(f"docker compose up failed ({ch.compose_project}): {tail}")
        return list(ch.targets)

    def close(self, code: str) -> None:
        """Shut down the target (docker compose down -v). A no-op for static targets."""
        ch = self.get(code)
        if ch.compose_file:
            res = self._compose(ch, "down", "-v")
            if res.returncode != 0:
                tail = ((res.stderr or "") + (res.stdout or "")).strip()[-800:]
                raise PlatformError(f"docker compose down failed ({ch.compose_project}): {tail}")

    def down_leftovers(self) -> list[str]:
        """docker compose down all leftover cruiser_* projects (left behind by an abnormal exit last time); returns the names of the projects handled.

        Silently returns an empty list when docker / compose is not installed.
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
    """Read (and rewrite) _platform_state.json under flock protection; writes go through a temp file + os.replace."""

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
            # a corrupt state file must not make the platform unusable: keep a backup and continue from an empty state
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
    """Process-wide singleton (the challenge definition path comes from CRUISER_CHALLENGES)."""
    global _PLATFORM
    with _PLATFORM_LOCK:
        if _PLATFORM is None or _PLATFORM.challenges_file != challenges_path():
            _PLATFORM = Platform()
        return _PLATFORM


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def _cli(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m cruiser.challenges", description="Cruiser local challenge platform")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list challenges and flag progress")
    p_reset = sub.add_parser("reset", help="clear solving progress")
    p_reset.add_argument("codes", nargs="*", help="clear only these challenges (default: all)")
    sub.add_parser("down", help="docker compose down all cruiser_* projects")
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
            print("progress cleared: " + (", ".join(args.codes) if args.codes else "all challenges"))
        elif args.cmd == "down":
            names = plat.down_leftovers()
            print("shut down: " + (", ".join(names) if names else "(no cruiser_* projects)"))
    except PlatformError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
