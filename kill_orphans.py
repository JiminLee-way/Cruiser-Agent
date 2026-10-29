#!/usr/bin/env python
"""Clean up dangling processes: worker and claude processes whose parent scheduler/worker has died (killed as whole process groups).

Detection logic:
- claude process: walk up the PPID chain; no live main.py ancestor -> dangling
- worker process (main.py --sessions 1 with CRUISER_WORKER_ID):
  the parent scheduler (another main.py process) no longer exists -> dangling
- single-challenge mode run directly by the user in a terminal (main.py --challenge-code, no WORKER_ID) is not affected

Usage:
    python kill_orphans.py          # actually clean up
    python kill_orphans.py --dry    # only list, do not kill
"""
from __future__ import annotations

import os
import signal
import sys


def _read_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _read_ppid(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 1


def _read_environ(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _has_live_main_ancestor(pid: int) -> bool:
    """Walk up the parent-process chain looking for a live main.py process (excluding self)."""
    seen = set()
    p = _read_ppid(pid)
    while p > 1 and p not in seen:
        seen.add(p)
        if "main.py" in _read_cmdline(p):
            return True
        p = _read_ppid(p)
    return False


def main() -> int:
    dry = "--dry" in sys.argv
    self_pid = os.getpid()
    dangling: list[tuple[int, str, str]] = []  # (pid, kind, cmdline summary)

    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == self_pid:
            continue
        cmd = _read_cmdline(pid)
        if not cmd:
            continue
        # Use argv[0] to identify the real executable, to avoid matching shell wrapper processes whose
        # cmdline text contains "claude -p"/"main.py" (e.g. bash -c '...')
        argv0 = cmd.split()[0] if cmd.split() else ""
        kind = None
        if (argv0 == "claude" or argv0.endswith("/claude")) and " -p " in cmd:
            kind = "claude"
        elif (
            "python" in os.path.basename(argv0)
            and "main.py" in cmd
            and "--sessions 1" in cmd
            and "CRUISER_WORKER_ID" in _read_environ(pid)
        ):
            kind = "worker"
        if kind is None:
            continue
        if not _has_live_main_ancestor(pid):
            dangling.append((pid, kind, cmd[:100]))

    if not dangling:
        print("No dangling processes")
        return 0

    killed_groups = set()
    for pid, kind, cmd in dangling:
        try:
            pgid = os.getpgid(pid)
        except Exception:
            pgid = pid
        summary = f"{kind} pid={pid} pgid={pgid} cmd={cmd}"
        if dry:
            print(f"[DRY] Would clean up: {summary}")
            continue
        if pgid in killed_groups:
            continue
        killed_groups.add(pgid)
        try:
            os.killpg(pgid, signal.SIGKILL)  # kill the whole group, including claude's bash tool child processes
            print(f"Cleaned up: {summary}")
        except ProcessLookupError:
            pass
        except Exception as e:
            print(f"Failed to clean up pid={pid}: {e}")
    if not dry:
        print(f"Cleaned up {len(killed_groups)} dangling process group(s) in total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
