from __future__ import annotations

import os
import platform
import shlex
import subprocess
import sys
import tempfile
import fcntl
from pathlib import Path
import json
from typing import Optional, Literal, List, Dict, Any, Union
import shutil
import hashlib
import time

from dataclasses import dataclass
from pydantic import BaseModel, Field
from langchain.tools import tool
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

import requests

from .challenges import PlatformError, UnknownChallenge, get_platform

# Green console printing (Windows-compatible where possible)
_COLORAMA_READY = False


def _ensure_color():
    global _COLORAMA_READY
    if _COLORAMA_READY:
        return
    try:  # try to enable ANSI support on Windows
        import colorama  # type: ignore

        colorama.just_fix_windows_console()  # automatically enable/fix console colors
        _COLORAMA_READY = True
    except Exception:
        # colorama not installed or not needed; use ANSI codes directly
        _COLORAMA_READY = True


def _print_green(msg: str) -> None:
    # Quiet mode: suppress intermediate output via an environment variable during auto scans
    if os.environ.get("CRUISER_QUIET") == "1":
        return
    to_stderr = os.environ.get("CRUISER_DEBUG_STDERR") == "1"
    try:
        _ensure_color()
        colored = f"\x1b[32m{msg}\x1b[0m"
        if to_stderr:
            print(colored, file=sys.stderr, flush=True)
        else:
            print(colored, flush=True)
    except Exception:
        if to_stderr:
            print(msg, file=sys.stderr, flush=True)
        else:
            print(msg, flush=True)

def _print_color(msg: str, color_code: str) -> None:
    """Print a highlighted message in the given ANSI color (honors CRUISER_QUIET and CRUISER_DEBUG_STDERR)."""
    if os.environ.get("CRUISER_QUIET") == "1":
        return
    to_stderr = os.environ.get("CRUISER_DEBUG_STDERR") == "1"
    try:
        _ensure_color()
        colored = f"\x1b[{color_code}m{msg}\x1b[0m"
        if to_stderr:
            print(colored, file=sys.stderr, flush=True)
        else:
            print(colored, flush=True)
    except Exception:
        if to_stderr:
            print(msg, file=sys.stderr, flush=True)
        else:
            print(msg, flush=True)


# ===============
# Basic path helpers
# ===============
def get_workspace_root() -> Path:
    """Get the current workspace root path (the process working directory).

    Kept as a thin wrapper so access can later be restricted inside a container/sandbox.
    Current implementation: returns the resolved absolute path of os.getcwd().
    """
    try:
        return Path(os.getcwd()).resolve()
    except Exception:
        return Path(".").resolve()


class ReadFileInput(BaseModel):
    path: str = Field(..., description="Path of the file to read (relative or absolute)")
    encoding: str = Field("utf-8", description="Encoding used to decode the file; defaults to utf-8")
    max_bytes: int = Field(0, ge=0, description="Optional: when >0, read only the first max_bytes bytes; 0 means no limit")


@tool("read_file", args_schema=ReadFileInput, return_direct=False)
def read_file_tool(path: str, encoding: str = "utf-8", max_bytes: int = 0) -> str:
    """Read the contents of a local text file.

    Notes:
    - Supports relative/absolute paths; relative paths are resolved against the current working directory.
    - For large files, max_bytes limits the number of raw bytes read (set 0 for no truncation).
    - Returns plain text (undecodable parts are kept as replacement characters).
    - Errors are always prefixed with [ERROR].
    """
    _print_green("[TOOL] read_file" + path)
    try:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = get_workspace_root() / p
        p = p.resolve()
    except Exception as e:
        return f"[ERROR] failed to resolve path: {e}"

    if not p.exists():
        return f"[ERROR] file does not exist: {p}"
    if p.is_dir():
        return f"[ERROR] target is a directory: {p}"
    try:
        raw = p.read_bytes()
        if max_bytes and max_bytes > 0:
            raw = raw[:max_bytes]
        text = raw.decode(encoding, errors="replace")
        return text
    except Exception as e:
        return f"[ERROR] read failed: {e}"


class RunCommandInput(BaseModel):
    command: str = Field(..., description="Command to execute (string)")
    shell: Literal["none", "powershell", "cmd", "bash"] = Field(
        "powershell",
        description="Execution shell: none=run directly; powershell=PowerShell; cmd=cmd.exe; bash=/bin/bash -lc",
    )
    cwd: Optional[str] = Field(None, description="Optional working directory (any directory; an error is returned if it does not exist)")
    # Timeout and max-output parameters are no longer supported; keep the tool simple, synchronous, and return full output


@tool("run_command", args_schema=RunCommandInput, return_direct=False)
def run_command_tool(
    command: str,
    shell: Literal["none", "powershell", "cmd", "bash"] = "powershell",
    cwd: Optional[str] = None,
) -> str:
    """Execute a command locally and return the result (local machine only; no timeout by default; output not truncated by default).

    Note: this tool executes arbitrary commands; use it only in a trusted environment;
    - Any cwd is now allowed (an error is returned if it does not exist).
    - Defaults to PowerShell (more convenient on Windows), can be switched to cmd/none; on Linux it switches to bash by default.
    - No timeout or max-output parameters; always waits synchronously for completion and returns the full output.
    Return format: text containing the exit_code/stdout/stderr/timed_out fields.
    """
    _print_green("[TOOL] run_command" + command)
    # Resolve the working directory (any directory allowed)
    workspace_root = get_workspace_root()
    run_cwd = workspace_root
    if cwd:
        try:
            rp = Path(cwd)
            rp = rp if rp.is_absolute() else (workspace_root / rp)
            rp = rp.resolve()
            if not rp.exists() or not rp.is_dir():
                return f"[ERROR] working directory does not exist or is not a directory: {cwd}"
            run_cwd = rp
        except Exception as e:  # noqa: BLE001
            return f"[ERROR] invalid working directory: {cwd} ({e})"

    system = platform.system().lower()

    # On non-Windows platforms, switch the default powershell to bash, which fits common environments better
    if not system.startswith("win") and shell == "powershell":
        shell = "bash"

    if shell == "powershell":
        if system.startswith("win"):
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ]
        else:
            # try pwsh on non-Windows
            cmd = [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ]
    elif shell == "cmd":
        if system.startswith("win"):
            cmd = ["cmd.exe", "/C", command]
        else:
            return "[ERROR] cmd.exe mode is not supported on this system"
    elif shell == "bash":
        if system.startswith("win"):
            return "[ERROR] bash mode is not supported on Windows (use powershell or cmd)"
        cmd = ["/bin/bash", "-lc", command]
    else:  # none
        # avoid shell=True where possible; do a simple split
        try:
            cmd = shlex.split(command, posix=not system.startswith("win"))
        except Exception as e:  # noqa: BLE001
            return f"[ERROR] failed to parse command: {e}"
        if not cmd:
            return "[ERROR] empty command"

    try:
        run_kwargs = dict(cwd=str(run_cwd), capture_output=True, text=True)
        # no timeout; always wait for the command to finish
        proc = subprocess.run(
            cmd,
            **run_kwargs,  # type: ignore[arg-type]
        )
        stdout = (proc.stdout or "")
        stderr = (proc.stderr or "")
        out = stdout + ("\n" if stdout and stderr else "") + stderr
        # If dirsearch was called: return the file path of its "built-in report" (extracted from the Output File: ... line)
        try:
            if isinstance(command, str) and ("dirsearch" in command.lower()):
                import re
                m = re.search(r"Output File:\s*(\S+)", out)
                if not m:
                    m = re.search(r"^Output File:\s*(.+)$", out, flags=re.MULTILINE)
                if m:
                    out = m.group(1).strip()
                else:
                    out = out
        except Exception:
            pass
        truncated = False
        return (
            f"exit_code={proc.returncode}\n"
            f"timed_out=false\n"
            f"truncated={'true' if truncated else 'false'}\n"
            f"cwd={run_cwd}\n"
            f"output=\n{out}"
        )
    except Exception as e:  # noqa: BLE001
        return f"[ERROR] execution failed: {e}"


class RunPythonInput(BaseModel):
    code: str = Field(..., description="Python code to execute (multi-line string)")
    timeout: int = Field(
        0,
        ge=0,
        le=7200,
        description="Timeout in seconds; 0 means unlimited (not passed to the subprocess); >0 uses this value as the timeout",
    )
    cwd: Optional[str] = Field(None, description="Optional working directory (any directory; an error is returned if it does not exist)")
    max_output: int = Field(0, ge=0, description="Output is not truncated by default; >0 truncates at this limit")


@tool("run_python", args_schema=RunPythonInput, return_direct=False)
def run_python_tool(
    code: str,
    timeout: int = 0,
    cwd: Optional[str] = None,
    max_output: int = 0,
) -> str:
    """Execute a snippet of Python code and return the result (subprocess; no timeout by default; output not truncated by default).

    - Runs in a subprocess with the same Python interpreter as the current process (sys.executable);
    - The code is carried in a temporary script file to avoid -c quoting issues;
    - A working directory can be specified;
    - Timeout policy matches run_command: unlimited when timeout<=0; >0 uses this value as the timeout;
    - Return format: text containing exit_code/stdout/stderr/timed_out and similar fields.
    """
    _print_green("[TOOL] run_python")

    # timeout: 0/None means unlimited

    # Resolve the working directory (any directory allowed)
    workspace_root = get_workspace_root()
    run_cwd = workspace_root
    if cwd:
        try:
            rp = Path(cwd)
            rp = rp if rp.is_absolute() else (workspace_root / rp)
            rp = rp.resolve()
            if not rp.exists() or not rp.is_dir():
                return f"[ERROR] working directory does not exist or is not a directory: {cwd}"
            run_cwd = rp
        except Exception as e:  # noqa: BLE001
            return f"[ERROR] invalid working directory: {cwd} ({e})"

    # write the code to a temporary script
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
            tf.write(code)
            tmp_path = Path(tf.name)

        cmd = [sys.executable, str(tmp_path)]
        run_kwargs = dict(cwd=str(run_cwd), capture_output=True, text=True)
        if timeout and timeout > 0:
            run_kwargs["timeout"] = timeout  # type: ignore[index]
        proc = subprocess.run(
            cmd,
            **run_kwargs,  # type: ignore[arg-type]
        )
        stdout = (proc.stdout or "")
        stderr = (proc.stderr or "")
        out = stdout + ("\n" if stdout and stderr else "") + stderr
        truncated = False
        if max_output and max_output > 0 and len(out) > max_output:
            out = out[:max_output] + f"\n[TRUNCATED] output exceeded {max_output} characters and was truncated."
            truncated = True
        return (
            f"exit_code={proc.returncode}\n"
            f"timed_out=false\n"
            f"truncated={'true' if truncated else 'false'}\n"
            f"cwd={run_cwd}\n"
            f"output=\n{out}"
        )
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "") + ("\n" if e.stdout and e.stderr else "") + (e.stderr or "")
        if max_output and max_output > 0 and len(partial) > max_output:
            partial = partial[:max_output] + f"\n[TRUNCATED] output exceeded {max_output} characters and was truncated."
        return (
            f"exit_code=-1\n"
            f"timed_out=true\n"
            f"truncated=false\n"
            f"cwd={run_cwd}\n"
            f"output=\n{partial}"
        )
    except Exception as e:  # noqa: BLE001
        return f"[ERROR] execution failed: {e}"
    finally:
        # clean up the temporary file
        try:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass


ALL_TOOLS = [
    read_file_tool,
    run_command_tool,
    run_python_tool,
]


# =========================
# Security tools: enumeration and invocation
# =========================


def _known_security_tools() -> list[dict]:
    """Declare the known command-line security tools. More entries can be added here."""
    return [
        {
            "name": "dirsearch",
            "command": "dirsearch",
            "description": "Web directory/file brute-forcing tool. Keep only common valid status codes: use -i 200,301,302 to avoid oversized output.",
        },
        {
            "name": "sqlmap",
            "command": "sqlmap",
            "description": "Automated SQL injection and database takeover tool",
        },
        {
            "name":"fenjing",
            "command":"fenjing",
            "description":"Template injection tool for `python` web frameworks",
        },
        {
            "name": "pwntools",
            "command": "pwn",
            "description": "Binary exploitation framework (CTF pwn challenges): process interaction, ELF parsing, checksec, cyclic, etc.",
        },
    ]


class ListSecurityToolsInput(BaseModel):
    only_available: bool = Field(
        True, description="When true, return only tools available in the current environment (found on PATH)"
    )
    with_version: bool = Field(
        True, description="Try to read the tool version (runs --version; set False to speed up)"
    )


@tool("list_security_tools", args_schema=ListSecurityToolsInput, return_direct=False)
def list_security_tools_tool(only_available: bool = True, with_version: bool = True) -> str:
    """List known security tools and mark which ones are available in the current environment. Returns a JSON string."""
    _print_green("[TOOL] list_security_tools")
    tools = _known_security_tools()
    result: list[dict] = []
    for t in tools:
        cmd = t.get("command")
        path = shutil.which(cmd) if isinstance(cmd, str) else None
        available = path is not None
        if only_available and not available:
            continue
        item = dict(t)
        item.update({"available": available})
        if available and with_version:
            version: Optional[str] = None
            try:
                p = subprocess.run(
                        [cmd, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=2,
                )
                if p.returncode == 0:
                        out = (p.stdout or p.stderr or "").strip().splitlines()
                        version = out[0] if out else None
                else:
                        # fall back to -V (some tools print their version with -V)
                        p2 = subprocess.run(
                            [cmd, "-V"],
                            capture_output=True,
                            text=True,
                            timeout=2,
                        )
                        if p2.returncode == 0:
                            out2 = (p2.stdout or p2.stderr or "").strip().splitlines()
                            version = out2[0] if out2 else None
            except Exception:
                version = None
            item["version"] = version
        result.append(item)
    try:
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception:
        return json.dumps(result, ensure_ascii=False)


# Register list_security_tools in the tool list
ALL_TOOLS.append(list_security_tools_tool)

class SubmitFlagInput(BaseModel):
    challenge_code: str = Field(..., description="Challenge code")
    flag: str = Field(..., description="The flag to submit")


# ---------------------------------------------------------------------------
# Cross-process flag store: all worker/solver subprocesses share one on-disk state (JSON + flock).
#   - correct: {flag value: owning challenge code} -- once a flag is accepted for one challenge, submitting the same flag for another challenge is rejected outright
#     (a common mistake is submitting another challenge's flag); resubmitting for the same challenge is not blocked.
#   - wrong:   {challenge code: [wrong flag,...]} -- each challenge keeps its own wrong-flag list (a flag wrong for A may be right for B,
#     hence per-challenge isolation); known wrong flags are rejected directly without hitting the platform, avoiding repeated useless submissions.
# ---------------------------------------------------------------------------
def _flagstore_paths() -> tuple[str, str]:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports = os.path.join(root, "reports")
    try:
        os.makedirs(reports, exist_ok=True)
    except Exception:
        pass
    return os.path.join(reports, "_flagstore.json"), os.path.join(reports, "_flagstore.lock")


def _flag_norm(flag: str) -> str:
    """Normalize a flag for comparison: strip leading/trailing whitespace."""
    return (flag or "").strip()


# ---------------------------------------------------------------------------
# Flag shape checks (prevent mis-submission of non-flag text such as CSS/code snippets)
#
# Three layers of defense:
#   1. shape regex + placeholder blacklist (basic shape);
#   2. prefix/body blacklist: HTML tags, CSS/JS keyword prefixes (div{...}, h1{...}),
#      and bodies that look like CSS property:value / semicolon-separated declarations (opacity:0.8, font-size:1.5em);
#   3. prefix learning: once the flagstore holds platform-confirmed correct flags, a new candidate's prefix must match
#      the set of confirmed prefixes (this platform uses uniform prefixes, e.g. flag{/FLAG{); a confirmed prefix is exempt from the blacklist.
# ---------------------------------------------------------------------------
_FLAG_FULL_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_+\-./:=]{8,300}\}")

# Common template placeholders (lowercase): the model sometimes echoes the flag format examples from the prompt verbatim
_PLACEHOLDER_FLAGS = {
    "flag{...}", "flag{flag}", "flag{xxx}", "flag{your_flag_here}", "flag{flag_content}",
    "flag{实际flag内容}", "flag{实际内容}", "实际flag内容", "flag_content",
}

# Non-flag prefix blacklist (lowercase): HTML tags / CSS selectors / JS/CSS keywords
_NON_FLAG_PREFIXES = {
    "div", "span", "body", "html", "head", "title", "style", "script", "link", "meta",
    "p", "a", "img", "input", "button", "form", "table", "tr", "td", "th",
    "ul", "ol", "li", "nav", "header", "footer", "section", "article", "aside", "main",
    "h1", "h2", "h3", "h4", "h5", "h6", "figure", "video", "audio", "canvas", "svg",
    "select", "option", "textarea", "label", "iframe", "pre", "code", "blockquote",
    "function", "if", "else", "for", "while", "return", "class", "import", "var",
    "let", "const", "new", "media", "keyframes", "font-face", "supports", "root",
    "hover", "active", "focus", "before", "after", "not", "checked", "disabled",
}

# Non-flag body blacklist patterns: CSS "property:value" (opacity:0.8 / font-size:1.5em / margin:0) and declaration lists (;)
_NON_FLAG_BODY_RES = [
    re.compile(r"^[a-zA-Z-]+\s*:\s*[0-9.]+%?(px|em|rem|vh|vw|s|deg)?;?$"),
    re.compile(r";"),
    re.compile(
        r"^[a-z-]+\s*:\s*(auto|none|block|inline|inline-block|hidden|visible|absolute|relative|"
        r"fixed|sticky|solid|dashed|bold|normal|center|left|right|both|cover|contain|inherit|"
        r"initial|unset|nowrap|wrap|flex|grid|pointer|default)$",
        re.IGNORECASE,
    ),
]

# Default trusted prefixes (lowercase): the most common CTF flag prefixes, exempt from "prefix-learning tightening"
# (always allowed even if absent from / different from the confirmed prefix set; still subject to the shape and blacklist rules).
_TRUSTED_PREFIXES = {"flag"}


def _flag_shape_ok(s: str) -> bool:
    """Basic shape: PREFIX{body} charset + not a placeholder."""
    if not _FLAG_FULL_RE.fullmatch(s):
        return False
    return s.lower() not in _PLACEHOLDER_FLAGS


def _flag_prefix_blacklisted(prefix: str) -> bool:
    """Prefix blacklist: HTML tags / CSS selectors / JS/CSS keywords."""
    return prefix in _NON_FLAG_PREFIXES


def _flag_body_blacklisted(s: str) -> bool:
    """Body blacklist: looks like a CSS declaration (property:value / contains semicolons). No prefix is exempt."""
    body = s.split("{", 1)[1][:-1]
    return any(r.search(body) for r in _NON_FLAG_BODY_RES)


def known_flag_prefixes() -> set[str]:
    """Learn the set of confirmed-correct flag prefixes for this platform from the flagstore (lowercase, global across challenges).

    Returns an empty set when there are no confirmed records (cold start; prefix learning is inactive).
    """
    try:
        with _FlagStore() as st:
            return {
                f.split("{", 1)[0].lower()
                for f in st.data.get("correct", {})
                if isinstance(f, str) and "{" in f
            }
    except Exception:
        return set()


def looks_flaglike_static(s: str) -> bool:
    """IO-free static check (for the stream-parsing hot path): shape + placeholders + blacklists, no prefix learning."""
    s = (s or "").strip()
    if not _flag_shape_ok(s):
        return False
    prefix = s.split("{", 1)[0].lower()
    return not _flag_prefix_blacklisted(prefix) and not _flag_body_blacklisted(s)


def looks_flaglike(s: str) -> bool:
    """Full check (for the submission path): static rules + flagstore prefix learning.

    Order of checks:
    1. the body CSS-pattern blacklist always applies (no prefix is exempt -- flag{display:none} is still junk);
    2. prefix in the confirmed set: exempt from the prefix blacklist and learning tightening (evidence beats rules);
    3. the prefix blacklist (HTML/CSS/JS keywords) blocks;
    4. prefix-learning tightening: once confirmed prefixes exist, unknown prefixes are never trusted --
       but _TRUSTED_PREFIXES (flag/FLAG) are allowed by default and not subject to this.
    """
    s = (s or "").strip()
    if not _flag_shape_ok(s):
        return False
    if _flag_body_blacklisted(s):
        return False
    prefix = s.split("{", 1)[0].lower()
    known = known_flag_prefixes()
    if known and prefix in known:
        return True
    if _flag_prefix_blacklisted(prefix):
        return False
    if known and prefix not in _TRUSTED_PREFIXES:
        return False
    return True


class _FlagStore:
    """Read-modify-write _flagstore.json under flock protection."""

    def __init__(self):
        self.store_path, self.lock_path = _flagstore_paths()
        self._lf = None

    def __enter__(self):
        self._lf = open(self.lock_path, "a+")
        fcntl.flock(self._lf, fcntl.LOCK_EX)
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except Exception:
            self.data = {}
        self.data.setdefault("correct", {})
        self.data.setdefault("wrong", {})
        return self

    def save(self):
        tmp = self.store_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.store_path)
        except Exception:
            pass

    def __exit__(self, *exc):
        try:
            if self._lf is not None:
                fcntl.flock(self._lf, fcntl.LOCK_UN)
                self._lf.close()
        except Exception:
            pass


def _flagstore_precheck(code: str, flag: str) -> Optional[str]:
    """Check the store before submitting: a non-None return means short-circuit (do not hit the platform); the string is returned to the caller."""
    f = _flag_norm(flag)
    if not f:
        return None
    try:
        with _FlagStore() as st:
            owner = st.data["correct"].get(f)
            if owner is not None and owner != code:
                _print_color(
                    f"[SUBMIT_FLAG][REJECTED] this flag belongs to another challenge {owner}, not {code}; submission refused", "91;1")
                return (
                    f"chanllege_code:{code} submission refused: this flag was already accepted for another challenge ({owner}) "
                    f"and does not belong to this challenge; do not submit it again, keep looking for this challenge's correct flag."
                )
            if owner == code:
                _print_color(f"[SUBMIT_FLAG][ALREADY SOLVED] this flag was already submitted for this challenge (local record)", "93;1")
                return f"chanllege_code:{code} ALREADY SUBMITTED"
            if f in (st.data["wrong"].get(code) or []):
                _print_color(f"[SUBMIT_FLAG][KNOWN WRONG] known wrong flag for this challenge, skipping submission", "91;1")
                return f"chanllege_code:{code} wrong flag (a known wrong flag for this challenge; do not resubmit it, try another direction)"
    except Exception:
        return None
    return None


def _flagstore_record_correct(code: str, flag: str) -> None:
    f = _flag_norm(flag)
    if not f:
        return
    try:
        with _FlagStore() as st:
            st.data["correct"][f] = code
            # if it was previously recorded as wrong for this challenge, correct that
            wl = st.data["wrong"].get(code)
            if wl and f in wl:
                st.data["wrong"][code] = [x for x in wl if x != f]
            st.save()
    except Exception:
        pass


def _flagstore_record_wrong(code: str, flag: str) -> None:
    f = _flag_norm(flag)
    if not f:
        return
    try:
        with _FlagStore() as st:
            # a flag already accepted for any challenge is never recorded as wrong
            if st.data["correct"].get(f):
                return
            wl = st.data["wrong"].setdefault(code, [])
            if f not in wl:
                wl.append(f)
            st.save()
    except Exception:
        pass


@dataclass(frozen=True)
class FlagSubmitOutcome:
    """Structured result of one flag submission.

    ok: the string was accepted by the platform (correct, or DuplicateSubmit / already accepted locally).
    fresh: True only when the platform judged it correct for the first time (not a duplicate / not already accepted locally).
    definitive: False means a transient failure; the caller must not record the candidate as verified (so it can be retried later).
    """
    ok: bool = False
    output: str = ""
    correct: int = 0
    total: int = 0
    definitive: bool = True
    fresh: bool = False


def flags_all_collected(correct: int, total: int) -> bool:
    """True only when the platform reports a total and all flags are in. Never treated as done when the total is unknown (so multi-flag challenges are not stopped by the first flag)."""
    try:
        c, t = int(correct or 0), int(total or 0)
    except Exception:
        return False
    return t >= 1 and c >= t


def query_flag_progress(code: str) -> tuple[int, int]:
    """Read (accepted flag count, total flag count) for this challenge from the local platform; returns (0, 0) on failure."""
    if not code:
        return 0, 0
    try:
        return get_platform().progress(code)
    except Exception:
        return 0, 0


def _progress_clause(correct: int, total: int) -> str:
    """Build the progress and "not all flags yet, do not stop" note appended to the submission receipt; returns an empty string when the total is unknown."""
    try:
        correct_i, total_i = int(correct or 0), int(total or 0)
    except Exception:
        return ""
    if total_i < 1:
        return ""
    remain = total_i - correct_i
    clause = f"flag progress {correct_i}/{total_i}"
    if remain > 0:
        clause += (
            f". This challenge still has {remain} flag(s) not submitted; do not stop, keep hunting for the remaining flags"
            f" (multiple flags are often at different locations/privileges/endpoints under the same foothold); finish only after all {total_i} flags are obtained."
        )
    return clause


def _with_progress(base: str, correct: int, total: int) -> str:
    clause = _progress_clause(correct, total)
    if not clause or "flag progress" in (base or ""):
        return base
    return f"{base}, {clause}"


def submit_flag_outcome(challenge_code: str, flag: str) -> FlagSubmitOutcome:
    """Submit a flag and return a structured result (including platform progress X/Y). Shared by the framework's automatic verification and the LangChain tool."""
    flag = (flag or "").strip()
    _print_color(f"[SUBMIT_FLAG] challenge_code={challenge_code} flag={flag}", "95;1")  # bright magenta
    # Note: this tool is the "model-initiated submission" channel and does no shape filtering -- the LLM may submit whatever it wants,
    # and the platform judges it and records the wrong list. The looks_flaglike rules only block framework-side automatic submissions
    # (_verify_flag on regex-extracted candidates / the watcher fallback), see claude_agent.py.
    pre = _flagstore_precheck(challenge_code, flag)
    if pre is not None:
        if "ALREADY SUBMITTED" in pre:
            c, t = query_flag_progress(challenge_code)
            out = _with_progress(pre, c, t)
            return FlagSubmitOutcome(ok=True, output=out, correct=c, total=t, definitive=True)
        return FlagSubmitOutcome(ok=False, output=pre, definitive=True)
    try:
        res = get_platform().submit(challenge_code, flag)
    except UnknownChallenge as e:
        _print_color(f"[SUBMIT_FLAG][ERROR] {e}", "91;1")
        return FlagSubmitOutcome(ok=False, output=f"[ERROR] flag submission failed: {e}", definitive=True)
    except (PlatformError, OSError) as e:
        # broken challenge definition / unwritable state file, etc.: do not record as verified, leave for a later retry
        _print_color(f"[SUBMIT_FLAG][ERROR] platform error: {e}", "91;1")
        return FlagSubmitOutcome(
            ok=False,
            output=f"chanllege_code:{challenge_code} submission failed, please try again later: {e}",
            definitive=False,
        )
    if not res.correct:
        _print_color("[SUBMIT_FLAG][INCORRECT] wrong flag", "91;1")  # bright red
        _flagstore_record_wrong(challenge_code, flag)  # record in this challenge's wrong list
        return FlagSubmitOutcome(
            ok=False,
            output=f"chanllege_code:{challenge_code} wrong flag",
            definitive=True,
        )
    # record in the global correct table (owned by this challenge); duplicates are recorded too (idempotent)
    _flagstore_record_correct(challenge_code, flag)
    correct, total = res.correct_count, res.total
    if res.duplicate:
        base = _with_progress(f"chanllege_code:{challenge_code} ALREADY SUBMITTED", correct, total)
        _print_color(f"[SUBMIT_FLAG][ALREADY SOLVED] this flag was already accepted, progress {correct}/{total}", "93;1")
        return FlagSubmitOutcome(ok=True, output=base, correct=correct, total=total, definitive=True)
    _print_color(f"[SUBMIT_FLAG][OK] submission correct, flag progress {correct}/{total}", "95;1")
    base = f"chanllege_code:{challenge_code} FLAG CORRECT (flag progress {correct}/{total})"
    remain = total - correct
    if remain > 0:
        base += (
            f". This challenge still has {remain} flag(s) not submitted; do not stop, keep hunting for the remaining flags"
            f" (multiple flags are often at different locations/privileges/endpoints under the same foothold); finish only after all {total} flags are obtained."
        )
    return FlagSubmitOutcome(ok=True, output=base, correct=correct, total=total, definitive=True, fresh=True)


@tool("submit_flag", args_schema=SubmitFlagInput, return_direct=False)
def submit_flag(challenge_code: str, flag: str) -> str:
    """Given challenge_code and flag, submit the current CTF challenge flag to the local challenge platform.
    Returns the submission result or an error message.
    """
    return submit_flag_outcome(challenge_code, flag).output

ALL_TOOLS.append(submit_flag)


class FindResourceInput(BaseModel):
    name_pattern: str = Field(..., description="Name or pattern of the resource to find (partial match supported, not a regex)")
    search_paths: Optional[List[str]] = Field(
        None,
        description="Optional list of paths, searched in order; when empty, default common locations and the workspace root are used",
    )
    extensions: Optional[List[str]] = Field(None, description="Optional list of extensions (e.g. ['.txt','.lst']) to narrow the search")
    max_results: int = Field(20, ge=1, description="Maximum number of results to return, default 20")


@tool("find_resource", args_schema=FindResourceInput, return_direct=False)
def find_resource(name_pattern: str, search_paths: Optional[List[str]] = None, extensions: Optional[List[str]] = None, max_results: int = 20) -> str:
    """Find local file resources (e.g. password dictionaries, brute-force wordlists).

    - name_pattern: partial match (no regex), substring match against the file name (not the path)
    - search_paths: optional list of paths (absolute or relative); when empty, some common directories and the current workspace are used
    - extensions: optional extension filter (lowercase match), e.g. ['.txt', '.lst']
    - Returns a JSON list (array of strings) in discovery order, at most max_results entries
    """
    # Simplified implementation: return matching file paths from a predefined resource map
    _print_green(f"[TOOL] find_resource pattern={name_pattern} (predefined lookup)")
    # locate the resource directory relative to this module file, so deployment path changes do not cause drift
    resource_dir = Path(__file__).resolve().parent.parent / "resource"
    resources = {
        # add or modify predefined resource mappings here
        "common password brute-force dictionary": str(resource_dir / "password.txt"),
        "common username brute-force dictionary": str(resource_dir / "username.txt"),
        "XSS payload dictionary": str(resource_dir / "xss.txt"),

    }

    pattern = name_pattern.lower()
    matches: List[str] = []
    for k, path in resources.items():
        if pattern in k.lower() or pattern in str(path).lower():
            matches.append(path)
            if len(matches) >= max_results:
                break

    # if nothing matches, return an empty list (JSON)
    try:
        return json.dumps(matches, ensure_ascii=False)
    except Exception:
        return str(matches)


# Register find_resource
ALL_TOOLS.append(find_resource)

class DirsearchScanInput(BaseModel):
    url: str = Field(..., description="Target address, e.g. http://127.0.0.1:8080 or http://host:port")


@tool("dirsearch_scan", args_schema=DirsearchScanInput, return_direct=False)
def dirsearch_scan(url: str) -> str:
    """Run a one-off directory scan against a single URL (cached).

    - The same URL (after normalization) is scanned only once; later calls return the cached result directly
    - Default arguments: -i 200,301,302 --format=plain
    - The report is written to the session workspace (CRUISER_WORKSPACE_DIR) and also to the shared cache directory /tmp/cruiser_dirsearch_cache
    - Return value: the plain-text report; if the tool produced no report, a placeholder report file is created and "no valid results found or report not generated" is returned
    """
    _print_green(f"[TOOL] dirsearch_scan {url}")
    try:
        url_norm = (url or "").strip().rstrip("/")
        if not url_norm.lower().startswith(("http://", "https://")):
            return "[ERROR] invalid URL (must start with http:// or https://)"
        key = hashlib.sha256(url_norm.encode("utf-8")).hexdigest()[:16]
        cache_root = Path("/tmp/cruiser_dirsearch_cache").resolve()
        cache_dir = cache_root / key
        report_cache = cache_dir / "report.txt"
        lock_path = cache_dir / "lock"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # cache hit
        if report_cache.exists():
            try:
                return report_cache.read_text("utf-8", errors="replace")
            except Exception as e:
                return f"[ERROR] failed to read cache: {e}"

        # race for the lock: run the scan exclusively once
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("utf-8", errors="ignore"))
            os.close(fd)
            fd = None
            # prepare the workspace and output file
            ws = os.environ.get("CRUISER_WORKSPACE_DIR")
            if not ws:
                base_ws = os.environ.get("CRUISER_WORKSPACE_BASE") or "/tmp/cruiser_workspaces"
                os.makedirs(base_ws, exist_ok=True)
                ws = os.path.join(base_ws, f"ws_dirsearch_{key}")
                os.makedirs(ws, exist_ok=True)
            out_file = os.path.join(ws, f"dirsearch_{key}.txt")
            # run dirsearch (write a plain-text report to avoid the progress bar)
            cmd = [
                "dirsearch",
                "-u",
                url_norm,
                "-i",
                "200,301,302",
                "--format=plain",
                "-o",
                out_file,
            ]
            p = subprocess.run(cmd, capture_output=True, text=True)
            # prefer reading the report file; if it was not generated, create an "empty report" at the expected location
            if os.path.exists(out_file):
                try:
                    content = Path(out_file).read_text("utf-8", errors="replace")
                except Exception:
                    content = ""
                try:
                    report_cache.write_text(content, encoding="utf-8")
                except Exception:
                    pass
                return content
            else:
                # do not fall back to stdout/stderr; generate an explicit "no results found" report file
                content = "This scan found no valid results\n"
                try:
                    Path(out_file).write_text(content, encoding="utf-8")
                except Exception:
                    pass
                try:
                    report_cache.write_text(content, encoding="utf-8")
                except Exception:
                    pass
                return content
        except FileExistsError:
            # another process is scanning: wait for the cached result
            for _ in range(600):  # wait at most 5 minutes
                if report_cache.exists():
                    try:
                        return report_cache.read_text("utf-8", errors="replace")
                    except Exception as e:
                        return f"[ERROR] failed to read cache: {e}"
                time.sleep(0.5)
            return "[ERROR] timed out waiting for the dirsearch scan result"
        finally:
            try:
                if lock_path.exists():
                    # normally removed by the lock holder only after the report is on disk; if we get here without a report, clear the lock anyway to avoid deadlock
                    if report_cache.exists():
                        os.unlink(lock_path)
            except Exception:
                pass
    except Exception as e:
        return f"[ERROR] dirsearch execution error: {e}"

# Register dirsearch_scan
ALL_TOOLS.append(dirsearch_scan)



class FuzzXssInput(BaseModel):
    url: str = Field(..., description="Target URL, e.g. http://127.0.0.1:8080/page")
    get_params: Optional[Union[str, List[str]]] = Field(
        None,
        description="GET parameter name or list of names; payloads are filled into these parameters automatically",
    )
    post_params: Optional[Union[str, List[str]]] = Field(
        None,
        description="POST parameter name or list of names; if empty, only GET requests are sent",
    )
    prefix: str = Field("", description="Prefix string added to every payload")
    thread_count: int = Field(20, ge=1, description="Number of concurrent threads, default 20")
    timeout: float = Field(10, gt=0, description="Per-request timeout (seconds), default 10")
    flag_pattern: str = Field(
        r"flag\{.*?\}",
        description="Regular expression used to match the flag, default flag{...}",
    )
    payload_file: Optional[str] = Field(
        None,
        description="Path of the payload dictionary file, default xss.txt in the project root",
    )
    show_progress: bool = Field(
        False, description="Whether to print progress information (off by default)"
    )
    progress_interval: int = Field(
        500, ge=1, description="Progress print interval (number of requests), default 500"
    )


def _load_fuzz_xss_payloads(path: Optional[str]) -> List[str]:
    default_path = Path(__file__).resolve().parent.parent / "resource" / "xss.txt"
    payload_path = Path(path).expanduser() if path else default_path
    if not payload_path.exists():
        raise FileNotFoundError(f"payload file does not exist: {payload_path}")
    payloads: List[str] = []
    with payload_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            text = line.strip()
            if not text or text.startswith("<!--"):
                continue
            payloads.append(text)
    if not payloads:
        raise ValueError("no valid payload found in the payload file")
    return payloads


def _normalize_param_names(
    names: Optional[Union[str, List[str]]]
) -> Optional[List[str]]:
    if names is None:
        return None
    if isinstance(names, str):
        return [names]
    try:
        return [str(item) for item in names]
    except Exception:
        return [str(names)]


def _render_fuzz_progress(count: int, total: int) -> str:
    if total <= 0:
        return "progress: 0/0 (0.0%)"
    percent = count / total * 100
    return f"progress: {count}/{total} ({percent:5.1f}%)"


@tool("fuzz_xss", args_schema=FuzzXssInput, return_direct=False)
def fuzz_xss_tool(
    url: str,
    get_params: Optional[Union[str, List[str]]] = None,
    post_params: Optional[Union[str, List[str]]] = None,
    prefix: str = "",
    thread_count: int = 20,
    timeout: float = 10.0,
    flag_pattern: str = r"flag\{.*?\}",
    payload_file: Optional[str] = None,
    show_progress: bool = False,
    progress_interval: int = 500,
) -> str:
    """Run concurrent XSS tests against the target using a payload dictionary; returns the flag and payload on a hit."""
    _print_green("[TOOL] fuzz_xss")
    try:
        payloads = _load_fuzz_xss_payloads(payload_file)
    except Exception as exc:
        return f"[ERROR] failed to load payloads: {exc}"

    total = len(payloads)
    get_param_names = _normalize_param_names(get_params)
    post_param_names = _normalize_param_names(post_params)
    method = "POST" if post_param_names else "GET"
    flag_regex = re.compile(flag_pattern, re.IGNORECASE)

    payload_path = str(
        (Path(payload_file).expanduser() if payload_file else Path(__file__).resolve().parent.parent / "resource" / "xss.txt").resolve()
    )
    cache_input = {
        "url": url,
        "get": sorted(get_param_names or []),
        "post": sorted(post_param_names or []),
        "prefix": prefix,
        "payload_file": payload_path,
    }
    try:
        cache_key = hashlib.sha256(
            json.dumps(cache_input, sort_keys=True, ensure_ascii=False).encode("utf-8", errors="ignore")
        ).hexdigest()[:16]
    except Exception as exc:
        return f"[ERROR] failed to build cache key: {exc}"

    cache_root = Path("/tmp/cruiser_fuzz_xss_cache").resolve()
    cache_dir = cache_root / cache_key
    cache_result = cache_dir / "result.txt"
    lock_path = cache_dir / "lock"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if cache_result.exists():
        try:
            cached = cache_result.read_text("utf-8", errors="replace")
            return cached.splitlines()[0] if cached else "flag not obtained"
        except Exception as exc:
            return f"[ERROR] failed to read cache: {exc}"

    locked = False
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode("utf-8", errors="ignore"))
        os.close(fd)
        fd = None
        locked = True

        success_event = threading.Event()
        success_value = {"result": ""}
        processed = 0
        interval = progress_interval if progress_interval > 0 else 1
        quiet_mode = os.environ.get("CRUISER_QUIET") == "1"

        if show_progress and not quiet_mode:
            print(f"{total} payloads in total, starting tests...", flush=True)

        def worker(payload: str) -> None:
            if success_event.is_set():
                return
            full_payload = f"{prefix}{payload}"
            params = {name: full_payload for name in get_param_names} if get_param_names else None
            post_data = {name: full_payload for name in post_param_names} if post_param_names else None
            try:
                if method == "POST":
                    resp = requests.post(url, params=params, data=post_data, timeout=timeout)
                else:
                    resp = requests.get(url, params=params, timeout=timeout)
                text = resp.text or ""
                match = flag_regex.search(text)
                if match and not success_event.is_set():
                    success_event.set()
                    success_value["result"] = f"{match.group(0)} {full_payload}"
            except Exception:
                pass

        executor = ThreadPoolExecutor(max_workers=max(1, thread_count))
        try:
            futures = {executor.submit(worker, payload): payload for payload in payloads}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
                processed += 1
                if show_progress and not quiet_mode and (
                    processed == total or processed % interval == 0
                ):
                    print(_render_fuzz_progress(processed, total), flush=True)
                if success_event.is_set():
                    break
        except KeyboardInterrupt:
            success_event.set()
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        if show_progress and not quiet_mode and processed % interval != 0 and processed != total:
            print(_render_fuzz_progress(processed, total), flush=True)

        result_text = success_value["result"] or "flag not obtained"
        try:
            cache_result.write_text(result_text, encoding="utf-8")
        except Exception:
            pass
        return result_text
    except FileExistsError:
        for _ in range(600):
            if cache_result.exists():
                try:
                    cached = cache_result.read_text("utf-8", errors="replace")
                    return cached.splitlines()[0] if cached else "flag not obtained"
                except Exception as exc:
                    return f"[ERROR] failed to read cache: {exc}"
            time.sleep(0.5)
        return "[ERROR] timed out waiting for the fuzz_xss cached result"
    finally:
        if locked:
            try:
                if lock_path.exists():
                    os.unlink(lock_path)
            except Exception:
                pass


ALL_TOOLS.append(fuzz_xss_tool)
