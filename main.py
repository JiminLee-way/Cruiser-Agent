from cruiser.claude_agent import SINGLE_WORKER_ID, run_auto_scan, workspace_dir
import argparse
import atexit
import json
import os
import subprocess
import sys
import threading
import time
import re
import signal
from cruiser.challenges import CHALLENGES_ENV, PlatformError, get_platform, target_host_port
from cruiser.taskboard import claim_task
from cruiser import runtime
from cruiser.dashboard import start_dashboard


def main():
    """Start in non-interactive scan mode (auto when --target missing) or multi-session."""
    parser = argparse.ArgumentParser(description="Cruiser - CTF Web agent")
    parser.add_argument("--target", type=str, default=None, help="Scan target address (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--max-steps", type=int, default=0, help="Maximum AI scan steps (0=unlimited)")
    parser.add_argument("--quiet", action="store_true", help="Suppress intermediate output, keep only the final JSON")
    parser.add_argument("--sessions", type=int, default=1, help="Number of concurrent worker sessions (>=1)")
    parser.add_argument("--default-timeout", type=int, default=0, help="Default run_command timeout (seconds), 0=use the built-in default")
    parser.add_argument("--max-timeout", type=int, default=0, help="run_command timeout cap (seconds), 0=use the built-in cap")
    parser.add_argument("--hint", type=str, default=None, help="Challenge hint (optional, assists AI reasoning)")
    parser.add_argument("--challenge-code", type=str, default=None, help="Challenge code (assigned by the scheduler)")
    parser.add_argument(
        "--worker-models",
        type=str,
        default=None,
        help="Comma-separated list of per-worker models, e.g. 'deepseek-v4-flash,deepseek-v4-flash,deepseek-v4-pro'; "
             "when given, the number of workers = list length (overrides --sessions), and worker i uses model i",
    )
    parser.add_argument(
        "--solver-task",
        type=str,
        default=None,
        help="(internal) solver only: focus this run on this single exploration direction, without exploring the whole challenge",
    )
    args = parser.parse_args()
    # inject the timeout policy into the environment for the current/child sessions
    if args.default_timeout and args.default_timeout > 0:
        os.environ["CRUISER_DEFAULT_TIMEOUT"] = str(args.default_timeout)
    if args.max_timeout and args.max_timeout > 0:
        os.environ["CRUISER_MAX_TIMEOUT"] = str(args.max_timeout)

    # worker model mix: --worker-models first, then the CRUISER_WORKER_MODELS environment variable;
    # comma-separated, e.g. "deepseek-v4-flash,deepseek-v4-flash,deepseek-v4-pro".
    # when given, the number of workers = list length (overrides --sessions), and worker i uses model i.
    # parsed only in the main process: worker subprocesses carry CRUISER_WORKER_ID and their model is already injected by the parent via ANTHROPIC_MODEL;
    # parsing again here (subprocesses also inherit CRUISER_WORKER_MODELS from .env) would wrongly enter the multi-session branch and spawn recursively.
    _is_worker_proc = os.environ.get("CRUISER_WORKER_ID") is not None
    _wm_raw = "" if _is_worker_proc else (args.worker_models or os.environ.get("CRUISER_WORKER_MODELS", ""))
    worker_models = [m.strip() for m in _wm_raw.split(",") if m.strip()]
    sessions = len(worker_models) if worker_models else args.sessions
    if worker_models:
        print(f"[Main] worker model mix: {worker_models} ({sessions} workers in total)", flush=True)

    # local challenge platform: challenge definition YAML (CRUISER_CHALLENGES, default challenges.yaml in the project root) +
    # reports/_platform_state.json progress. Pin the definition file to an absolute path and write it back to the environment,
    # so workers and the submit_flag.py the Agent calls from its workspace read the same definitions.
    platform = get_platform()
    os.environ[CHALLENGES_ENV] = platform.challenges_file

    # main-process startup self-check (spawned worker/solver subprocesses carry CRUISER_WORKER_ID and skip it)
    if not _is_worker_proc:
        from cruiser.llm import get_deepseek_api_key, get_kimi_api_key, get_glm_api_key
        if not get_deepseek_api_key() and not get_kimi_api_key() and not get_glm_api_key() and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            print(
                "[Main] warning: no LLM key configured (DEEPSEEK_API_KEY / KIMI_API_KEY / GLM_API_KEY / ANTHROPIC_AUTH_TOKEN); "
                "the claude solving engine and the watcher will not be able to authenticate. Configure one in the project-root .env.",
                flush=True,
            )
        try:
            defined = platform.challenges()
        except PlatformError as e:
            print(f"[Main] failed to load challenge definitions: {e}", flush=True)
            sys.exit(2)
        print(f"[Main] loaded {len(defined)} challenges: {platform.challenges_file}", flush=True)
        # clean up cruiser_* compose projects left by a previous abnormal exit, to start from a clean state
        for name in platform.down_leftovers():
            print(f"[Startup] shut down leftover target {name}", flush=True)
        start_dashboard()

    DIFF_RANK = {"easy": 0, "medium": 1, "hard": 2}

    def fetch_all_unsolved() -> dict[str, dict] | None:
        """Return a map: code -> {challenge_code, difficulty, ...} for all unsolved challenges.
        Returns None on load/parse errors (do NOT update queues in that case).
        Returns {} when every defined challenge is solved.
        """
        try:
            statuses = platform.list_challenges()
        except Exception as e:
            try:
                print(f"[Fetcher] failed to fetch challenges: {e}", flush=True)
            except Exception:
                pass
            return None
        result: dict[str, dict] = {}
        for st in statuses:
            if st.completed:
                continue
            ch = st.challenge
            result[ch.code] = {
                "challenge_code": ch.code,
                "difficulty": ch.difficulty,
                "description": ch.description,
                "flag_count": st.total,
                "correct_flag_count": st.correct,
            }
        return result

    def ensure_challenge_started(code: str) -> list[str]:
        """Start the challenge target and return the list of target URLs; returns [] if startup fails.

        Static targets (target) return their address directly; compose challenges run docker compose up -d.
        """
        if not code:
            return []
        # readiness check: once we have the address, actively probe whether the target port is really reachable (a started container does not mean
        # the internal service is listening). Return as soon as any address connects; wait at most CRUISER_CONTAINER_WARMUP
        # seconds (default 60); if still unreachable by then, return the address anyway and let the LLM solve, to avoid hanging.
        try:
            max_wait_s = float(os.environ.get("CRUISER_CONTAINER_WARMUP", "60") or "60")
        except Exception:
            max_wait_s = 60.0

        def _addr_reachable(url: str, conn_timeout: float = 3.0) -> bool:
            import socket
            hp = target_host_port(url)
            if hp is None:
                return False
            try:
                with socket.create_connection(hp, timeout=conn_timeout):
                    return True
            except Exception:
                return False

        def _ready(addrs: list[str]) -> list[str]:
            if not addrs or max_wait_s <= 0:
                return addrs
            try:
                print(f"[Container] {code} target started, probing reachability (up to {max_wait_s:.0f}s)…", flush=True)
            except Exception:
                pass
            deadline = time.time() + max_wait_s
            while time.time() < deadline:
                if any(_addr_reachable(a) for a in addrs):
                    try:
                        print(f"[Container] {code} target reachable, starting sessions", flush=True)
                    except Exception:
                        pass
                    return addrs
                time.sleep(2)
            try:
                print(f"[Container] {code} target still unreachable after {max_wait_s:.0f}s, starting sessions anyway for the LLM (to avoid hanging)", flush=True)
            except Exception:
                pass
            return addrs

        try:
            return _ready(platform.start(code))
        except Exception as e:
            try:
                print(f"[Container] failed to start {code}: {e}", flush=True)
            except Exception:
                pass
            return []

    def close_challenge_quiet(code: str) -> None:
        """Shut down the challenge target (docker compose down -v for compose challenges; a no-op for static targets); exceptions are only printed."""
        if not code:
            return
        try:
            platform.close(code)
        except Exception as e:
            try:
                print(f"[Container] [WARN] failed to shut down {code}: {e}", flush=True)
            except Exception:
                pass

    def fetch_hint_text(code: str) -> str:
        """Read the challenge hint (the hint in the challenge definition; empty string if none)."""
        try:
            return (platform.hint(code) or "").strip()
        except Exception as e:
            try:
                print(f"[HintFetcher] error fetching hint: {e}", flush=True)
            except Exception:
                pass
            return ""

    # single session: use the central challenge fetcher to get challenges and hand them to the session;
    # if --challenge-code is given, run the assigned challenge once and return
    if args.sessions <= 1 and not worker_models:
        if args.challenge_code:
            code = args.challenge_code
            target = args.target or ""
            if code:
                os.environ["CRUISER_CHALLENGE_CODE"] = code
            # when no target is given explicitly, the local platform starts the target to get its address
            if not target:
                target = ", ".join(ensure_challenge_started(code))
            if not target:
                print(json.dumps({"flag": None, "error": f"target for challenge {code} not ready"}, ensure_ascii=False))
                return
            try:
                result = run_auto_scan(target, max_steps=args.max_steps, quiet=args.quiet, hint=args.hint, challenge_code=code, solver_task=args.solver_task)
            finally:
                # the solver reuses the container the explorer started and must never shut it down on exit (that would tear down a target in use)
                if not args.solver_task:
                    close_challenge_quiet(code)
            try:
                obj = json.loads(result)
                if isinstance(obj, dict) and "flag" in obj:
                    print(json.dumps(obj, ensure_ascii=False))
                else:
                    print(json.dumps({"flag": result}, ensure_ascii=False))
            except Exception:
                print(json.dumps({"flag": result}, ensure_ascii=False))
            return
        while True:
            chal_map = fetch_all_unsolved()
            chal = None
            # Choose easiest available
            if isinstance(chal_map, dict) and chal_map:
                try:
                    sorted_items = sorted(chal_map.values(), key=lambda it: DIFF_RANK.get((it.get("difficulty") or "easy").lower(), 0))
                    chal = sorted_items[0] if sorted_items else None
                except Exception:
                    chal = None
            if chal_map is None:
                # Fetch error/timeout/abnormal -> do NOT change state, just retry later
                print("[Fetcher] fetch failed (queue not updated), retrying in 5 seconds…", flush=True)
                time.sleep(5)
                continue
            if not chal:
                print("[Fetcher] all challenges solved, exiting", flush=True)
                return
            code = chal.get("challenge_code") or ""
            target = args.target or ""
            if code:
                os.environ["CRUISER_CHALLENGE_CODE"] = code
            # when no target is given explicitly, the local platform starts the target and waits until it is ready
            if not target and code:
                target = ", ".join(ensure_challenge_started(code))
            if not target:
                print(f"[Fetcher] {code} target not ready, retrying in 5 seconds…", flush=True)
                time.sleep(5)
                continue
            try:
                os.environ["CRUISER_WORKSPACE_DIR"] = workspace_dir(code, SINGLE_WORKER_ID, resumable=True)
            except OSError:
                pass
            try:
                result = run_auto_scan(target, max_steps=args.max_steps, quiet=args.quiet, hint=args.hint, challenge_code=code or None)
            finally:
                # shut down the target after success or failure
                close_challenge_quiet(code)
            try:
                obj = json.loads(result)
                if isinstance(obj, dict) and "flag" in obj:
                    print(json.dumps(obj, ensure_ascii=False))
                else:
                    print(json.dumps({"flag": result}, ensure_ascii=False))
            except Exception:
                print(json.dumps({"flag": result}, ensure_ascii=False))
            # after success or failure, move on to the next challenge (the fetcher decides whether it changes)
            time.sleep(2)
            continue

    # multi-session concurrency: start subprocesses that scan in parallel, printing each session's output to stdout in real time;
    # a challenge counts as solved only by the local platform's flag progress (reports/_platform_state.json); worker logs are not parsed.
    num = max(1, int(sessions))

    def spawn_worker(idx: int, target: str, code: str | None, hint_text: str | None, env_overrides: dict | None = None, model: str | None = None):
        cmd = [
            sys.executable,
            "-u",  # unbuffered output
            "./main.py",
            "--max-steps",
            str(args.max_steps),
            "--sessions",
            "1",  # subprocesses always run in single-session mode
        ]
        if target:
            cmd += ["--target", target]
        if code:
            cmd += ["--challenge-code", code]
        if hint_text:
            cmd += ["--hint", hint_text]
        elif args.hint:
            cmd += ["--hint", args.hint]
        if args.quiet:
            cmd.append("--quiet")
        env = os.environ.copy()
        env["CRUISER_WORKER_ID"] = str(idx)
        env["CRUISER_SESSIONS"] = str(num)
        # subprocesses are always single-session and must never inherit the worker model list (otherwise they would wrongly enter the multi-session branch and spawn recursively)
        env.pop("CRUISER_WORKER_MODELS", None)
        if code:
            env["CRUISER_CHALLENGE_CODE"] = code
        if env_overrides:
            try:
                for k, v in env_overrides.items():
                    if v is None and k in env:
                        env.pop(k, None)
                    elif v is not None:
                        env[str(k)] = str(v)
            except Exception:
                pass
        # set the model this worker uses (read by _claude_env; overrides the default ANTHROPIC_MODEL/DEEPSEEK_MODEL)
        if model:
            env["ANTHROPIC_MODEL"] = model
            env["ANTHROPIC_SMALL_FAST_MODEL"] = model
        try:
            env["CRUISER_WORKSPACE_DIR"] = workspace_dir(code or "", str(idx), resumable=True)
        except OSError:
            pass
        # debug mode: all output goes to stdout
        if not args.quiet:
            env.pop("CRUISER_DEBUG_STDERR", None)
            env["CRUISER_QUIET"] = "0"
        # pass the timeout policy to the subprocess
        if args.default_timeout and args.default_timeout > 0:
            env["CRUISER_DEFAULT_TIMEOUT"] = str(args.default_timeout)
        if args.max_timeout and args.max_timeout > 0:
            env["CRUISER_MAX_TIMEOUT"] = str(args.max_timeout)
        # force unbuffered output in the subprocess
        env["PYTHONUNBUFFERED"] = "1"
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )
        p.cruiser_meta = {
            "idx": idx,
            "model": model or env.get("ANTHROPIC_MODEL") or "",
            "ws": env.get("CRUISER_WORKSPACE_DIR") or "",
            "kind": "explorer",
        }
        # register in the global process table for cleanup on exit
        with worker_procs_lock:
            worker_procs.add(p)
        return p

    # -------- solver: directed executor spawned by the watcher (deepseek-v4-flash, <=40 turns per task, reclaimed when done) --------
    # Note: this cap limits claude's number of turns (--max-turns), not the [COUNT] in the log.
    # [COUNT] counts every assistant event, roughly several times the number of turns, so for a 40-turn solver a [COUNT]
    # of ~100+ is normal and does not mean the cap is ineffective (error_max_turns is printed when the session hits the cap).
    SOLVER_MODEL = os.environ.get("CRUISER_SOLVER_MODEL", "deepseek-v4-flash")
    SOLVER_MAX_TURNS = int(os.environ.get("CRUISER_SOLVER_MAX_TURNS", "40") or "40")  # cap on claude turns
    MAX_SOLVERS_PER_CHALLENGE = int(os.environ.get("CRUISER_MAX_SOLVERS", "3") or "3")

    def spawn_solver(code: str, target: str, task_text: str, sid: int):
        """Spawn a solver subprocess: it executes only the single direction task_text, with the flash model and <=SOLVER_MAX_TURNS claude turns."""
        cmd = [
            sys.executable, "-u", "./main.py",
            "--sessions", "1",
            "--challenge-code", code,
            "--target", target,
            "--solver-task", task_text,
            "--max-steps", "0",
        ]
        if args.quiet:
            cmd.append("--quiet")
        env = os.environ.copy()
        env["CRUISER_WORKER_ID"] = f"solver{sid}"   # treated as a worker subprocess: skips the startup self-check and does not parse worker_models
        env["CRUISER_SESSIONS"] = str(num)
        env["CRUISER_CHALLENGE_CODE"] = code
        env.pop("CRUISER_WORKER_MODELS", None)
        env["ANTHROPIC_MODEL"] = SOLVER_MODEL
        env["ANTHROPIC_SMALL_FAST_MODEL"] = SOLVER_MODEL
        env["CRUISER_MAX_TURNS"] = str(SOLVER_MAX_TURNS)   # hard cap on claude turns for a single solver session (!= the [COUNT] in the log)
        env["PYTHONUNBUFFERED"] = "1"
        if not args.quiet:
            env.pop("CRUISER_DEBUG_STDERR", None)
            env["CRUISER_QUIET"] = "0"
        try:
            env["CRUISER_WORKSPACE_DIR"] = workspace_dir(code, f"solver{sid}", resumable=False)
        except OSError:
            pass
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env, start_new_session=True,
        )
        p.cruiser_meta = {
            "idx": sid,
            "model": SOLVER_MODEL,
            "ws": env.get("CRUISER_WORKSPACE_DIR") or "",
            "kind": "solver",
            "task": task_text,
        }
        with worker_procs_lock:
            worker_procs.add(p)
        return p

    # -------- new flow: preprocess (50, no hint) -> tier 1 (100, no hint) -> tier 2 (150, no hint) -> tier 3 (200, hint from level four on) --------
    count_re = re.compile(r"\[COUNT\]\s*(\d+)")

    def _mark_completed(groups: dict) -> None:
        """Decide whether a challenge is solved from the local platform's flag progress; worker stdout is not parsed."""
        try:
            by_code = {st.code: st for st in platform.list_challenges()}
        except Exception:
            return
        for code, grp in groups.items():
            if grp.get("winner") is not None:
                continue
            st = by_code.get(code)
            if st is None:
                continue
            total, correct = st.total, st.correct
            grp["flag_total"] = max(grp.get("flag_total", 0), total)
            grp["flag_correct"] = max(grp.get("flag_correct", 0), correct)
            try:
                runtime.stage_flags(code, grp["flag_correct"], grp["flag_total"])
            except Exception:
                pass
            if st.completed:
                grp["winner"] = f"[platform] {code} flag {correct}/{total}"
                try:
                    runtime.stage_winner(code, grp["winner"])
                except Exception:
                    pass
                try:
                    print(f"[{code}] [STAGE] platform flag progress {correct}/{total}, ending this round", flush=True)
                except Exception:
                    pass

    def run_parallel_stage(codes: list[str], items: dict[str, dict], step_threshold: float, prefetch_hint: bool, disable_hint: bool, kill_map: dict[str, threading.Event] | None = None) -> tuple[set[str], set[str]]:
        """Run one round over several challenges in parallel, stopping each challenge's session group when it reaches the threshold or produces a flag.
        Each challenge's target is started by the local platform before scanning and all are shut down at the end of the round.
        Returns (flagged, remaining, skipped):
        - flagged: challenges that produced a flag
        - remaining: challenges that actually ran but were not solved (promoted to the next tier)
        - skipped: challenges whose target was not ready and did not run at all this round (not counted as attempted, retried at the same tier)"""
        groups = {}
        started_codes: list[str] = []
        for code in codes:
            addrs = ensure_challenge_started(code)
            if addrs:
                started_codes.append(code)
            target = ", ".join(addrs)
            if not target:
                try:
                    print(f"[Stage] {code} target not ready, skipped this round", flush=True)
                except Exception:
                    pass
                continue
            pre_hint = None
            if prefetch_hint:
                pre_hint = fetch_hint_text(code)
                if pre_hint:
                    try:
                        out_dir = os.path.join(os.getcwd(), "reports")
                        os.makedirs(out_dir, exist_ok=True)
                        with open(os.path.join(out_dir, f"hint_{code}.txt"), "w", encoding="utf-8") as hf:
                            hf.write(pre_hint)
                    except Exception:
                        pass
            # write the challenge description to a shared file, read by workers/solvers (injected via the blackboard hook) and the watcher
            try:
                desc = (items.get(code) or {}).get("description") or ""
                if desc.strip():
                    out_dir = os.path.join(os.getcwd(), "reports")
                    os.makedirs(out_dir, exist_ok=True)
                    with open(os.path.join(out_dir, f"desc_{code}.txt"), "w", encoding="utf-8") as df:
                        df.write(desc)
            except Exception:
                pass
            # base env (hints can be disabled)
            base_env_overrides = {"CRUISER_DISABLE_HINT": "1"} if disable_hint else {}
            procs = []
            # single wave: num black-box sessions (all counted toward the step threshold); when worker_models specifies models, they map one to one
            for j in range(1, num + 1):
                env_overrides_j = dict(base_env_overrides)
                model_j = worker_models[(j - 1) % len(worker_models)] if worker_models else None
                p = spawn_worker(j, target, code, pre_hint, env_overrides=env_overrides_j, model=model_j)
                procs.append({"proc": p, "wave": 2})
                if j < num:
                    time.sleep(2)
            groups[code] = {
                "procs": procs,
                "counts": {},
                "winner": None,
                "flag_total": 0,
                "flag_correct": 0,
                "stop_threshold": False,
                "start_ts": time.time(),
                "kill_evt": (kill_map.setdefault(code, threading.Event()) if kill_map is not None else threading.Event()),
                "target": target,
                "solver_stop": threading.Event(),
                "solver_threads": [],
            }
            try:
                wlist = []
                for i, entry in enumerate(procs, start=1):
                    meta = getattr(entry["proc"], "cruiser_meta", {}) or {}
                    wlist.append({
                        "id": str(i),
                        "kind": "explorer",
                        "pid": entry["proc"].pid,
                        "model": meta.get("model") or "",
                        "ws": meta.get("ws") or "",
                        "alive": True,
                        "count": 0,
                    })
                runtime.stage_begin(
                    code,
                    stage=runtime.stage_name_for_threshold(int(step_threshold)),
                    threshold=int(step_threshold),
                    target=target,
                    hint_enabled=bool(prefetch_hint) and not bool(disable_hint),
                    workers=wlist,
                )
            except Exception:
                pass

        def reader_thread(code: str, p: subprocess.Popen, idx: int, wave: int):
            grp = groups[code]
            prefix = f"[{code}:S{idx}] "
            if not p.stdout:
                return
            for raw in p.stdout:
                if grp["winner"] is not None or grp["stop_threshold"] or grp["kill_evt"].is_set():
                    break
                line = raw.rstrip("\n")
                # COUNT
                m = count_re.search(line)
                if m:
                    try:
                        c = int(m.group(1))
                        grp["counts"][idx] = c
                        try:
                            runtime.stage_count(code, str(idx), c)
                        except Exception:
                            pass
                        # all workers are in the main wave (wave=2) and all count toward the step threshold
                        if wave == 2 and c >= step_threshold and grp["winner"] is None:
                            try:
                                print(f"{prefix}[STAGE] step threshold reached {c}/{step_threshold}, ending this round", flush=True)
                            except Exception:
                                pass
                            grp["stop_threshold"] = True
                            break
                    except Exception:
                        pass
                print(prefix + line, flush=True)
                try:
                    runtime.push_log(code, f"S{idx}", line)
                except Exception:
                    pass

        def _solver_stage_over(grp) -> bool:
            return grp["winner"] is not None or grp["stop_threshold"] or grp["kill_evt"].is_set() or grp["solver_stop"].is_set()

        def solver_driver(code: str):
            """One driver thread per challenge: keeps <=MAX_SOLVERS_PER_CHALLENGE solvers, each claiming one task FIFO;
            exited solvers are reclaimed and replaced; on a flag / end of round, stop and kill all solvers."""
            grp = groups[code]
            target = grp["target"]
            active: dict[int, subprocess.Popen] = {}
            sid_seq = 0

            def solver_reader(p: subprocess.Popen, sid: int):
                if not p.stdout:
                    return
                prefix = f"[{code}:SOLVER{sid}] "
                for raw in p.stdout:
                    if _solver_stage_over(grp):
                        break
                    line = raw.rstrip("\n")
                    print(prefix + line, flush=True)
                    try:
                        runtime.push_log(code, f"SOLVER{sid}", line)
                        m = count_re.search(line)
                        if m:
                            runtime.stage_count(code, f"solver{sid}", int(m.group(1)))
                    except Exception:
                        pass

            while not _solver_stage_over(grp):
                # reclaim solvers that have exited
                for sid, p in list(active.items()):
                    if p.poll() is not None:
                        active.pop(sid, None)
                        try:
                            runtime.solver_down(code, sid)
                        except Exception:
                            pass
                        with worker_procs_lock:
                            worker_procs.discard(p)
                # refill: claim new tasks FIFO (claiming erases the task, so deduplication is built in)
                while len(active) < MAX_SOLVERS_PER_CHALLENGE and not _solver_stage_over(grp):
                    sid = sid_seq + 1
                    try:
                        # claim under the worker id the solver will run as, so its report finds the claim
                        claimed = claim_task(code, f"solver{sid}")
                    except Exception:
                        claimed = None
                    if not claimed:
                        break
                    sid_seq = sid
                    try:
                        p = spawn_solver(code, target, claimed["text"], sid)
                    except Exception as e:
                        try:
                            print(f"[{code}:SOLVER{sid}] failed to start: {e}", flush=True)
                        except Exception:
                            pass
                        continue
                    active[sid] = p
                    try:
                        meta = getattr(p, "cruiser_meta", {}) or {}
                        runtime.solver_up(
                            code, sid,
                            pid=p.pid,
                            task=claimed["text"],
                            model=meta.get("model") or SOLVER_MODEL,
                            ws=meta.get("ws") or "",
                        )
                    except Exception:
                        pass
                    try:
                        print(f"[{code}:SOLVER{sid}] claimed and executing: {claimed['text'][:80]}", flush=True)
                    except Exception:
                        pass
                    threading.Thread(target=solver_reader, args=(p, sid), daemon=True).start()
                time.sleep(1.0)

            # wrap up: kill all running solvers
            for p in list(active.values()):
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGTERM)
                    except Exception:
                        try:
                            p.terminate()
                        except Exception:
                            pass
            time.sleep(1)
            for p in list(active.values()):
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except Exception:
                        try:
                            p.kill()
                        except Exception:
                            pass
                with worker_procs_lock:
                    worker_procs.discard(p)

        threads = []
        for code, grp in groups.items():
            for idx, entry in enumerate(grp["procs"], start=1):
                p = entry["proc"]
                wave = entry["wave"]
                t = threading.Thread(target=reader_thread, args=(code, p, idx, wave), daemon=True)
                t.start()
                threads.append(t)
            # one solver driver thread per challenge (started in parallel with the explorers, dedicated to working through task-board directions)
            st = threading.Thread(target=solver_driver, args=(code,), daemon=True)
            st.start()
            grp["solver_threads"].append(st)

        # wait for all challenges to finish this round (threshold or platform-confirmed solve)
        last_poll = 0.0
        while True:
            now = time.time()
            if now - last_poll >= 2.0:
                _mark_completed(groups)
                last_poll = now
            all_done = True
            for code, grp in groups.items():
                if grp["kill_evt"].is_set():
                    grp["stop_threshold"] = True
                if grp["winner"] is None and not grp["stop_threshold"]:
                    # check whether all processes have exited
                    any_alive = False
                    for idx, entry in enumerate(grp["procs"], start=1):
                        p = entry["proc"]
                        if p.poll() is None:
                            any_alive = True
                        else:
                            try:
                                runtime.worker_down(code, str(idx))
                            except Exception:
                                pass
                    if any_alive:
                        all_done = False
                        break
            if all_done:
                break
            try:
                time.sleep(0.2)
            except Exception:
                pass
        # reconcile once more at the end: when a group ends due to an external kill/process exit, avoid missing a challenge that was just completed
        _mark_completed(groups)

        # stop all processes (kill whole groups: send SIGTERM to the process group first, then SIGKILL on timeout)
        # first let each challenge's solver driver wrap up (it kills the solver subprocesses it spawned), then wait for it to exit
        for grp in groups.values():
            grp["solver_stop"].set()
        for grp in groups.values():
            for st in grp.get("solver_threads", []):
                try:
                    st.join(timeout=6)
                except Exception:
                    pass
        for grp in groups.values():
            for entry in grp["procs"]:
                p = entry["proc"]
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGTERM)
                    except Exception:
                        try:
                            p.terminate()
                        except Exception:
                            pass
            # wait a moment, then force kill
            for entry in grp["procs"]:
                p = entry["proc"]
                try:
                    p.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except Exception:
                        try:
                            p.kill()
                        except Exception:
                            pass

        # unregister from the global process table (processes were terminated at the end of this round)
        for grp in groups.values():
            for entry in grp["procs"]:
                with worker_procs_lock:
                    worker_procs.discard(entry["proc"])

        # shut down the challenge targets started this round
        for code in started_codes:
            close_challenge_quiet(code)

        flagged: set[str] = set()
        remaining: set[str] = set()
        skipped: set[str] = set()
        for code in codes:
            grp = groups.get(code)
            if grp is None:
                # target not ready, did not actually run this round
                skipped.add(code)
            elif grp["winner"] is not None:
                flagged.add(code)
            else:
                remaining.add(code)
        for code, grp in groups.items():
            try:
                runtime.stage_end(code, flagged=grp.get("winner") is not None)
            except Exception:
                pass
        return flagged, remaining, skipped

    preprocessed: set[str] = set()
    solved: set[str] = set()
    tier1: set[str] = set()
    tier2: list[str] = []
    tier3: list[str] = []
    stage_lock = threading.Lock()
    kill_flags: dict[str, threading.Event] = {}
    preproc_threads: dict[str, threading.Thread] = {}
    tier1_threads: dict[str, threading.Thread] = {}
    tier2_threads: dict[str, threading.Thread] = {}
    tier3_threads: dict[str, threading.Thread] = {}

    # cap on challenges running at the same time (default 3, overridden by CRUISER_MAX_ACTIVE):
    # each challenge uses a group of workers + one target; limit concurrency to control local resources and LLM quota usage.
    MAX_INFLIGHT = max(1, int(os.environ.get("CRUISER_MAX_ACTIVE", "3") or "3"))

    def _inflight_count() -> int:
        return len(preproc_threads) + len(tier1_threads) + len(tier2_threads) + len(tier3_threads)

    # -------- exit cleanup: on Ctrl+C / SIGTERM, kill all worker groups and shut down running targets --------
    # workers are started with start_new_session (their own process group, so they do not receive Ctrl+C's SIGINT),
    # so the parent must killpg each of them on exit, otherwise they all escape as orphan processes.
    worker_procs: set[subprocess.Popen] = set()
    worker_procs_lock = threading.Lock()

    def _cleanup_workers() -> None:
        # 1) terminate all workers by group (a worker's group includes its claude subprocesses)
        with worker_procs_lock:
            procs = list(worker_procs)
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except Exception:
                    pass
        time.sleep(1)
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except Exception:
                    pass
        if procs:
            print(f"[Main] cleaned up {len(procs)} worker process groups", flush=True)
        # 2) shut down all running compose targets (cruiser_* projects)
        try:
            for name in platform.down_leftovers():
                print(f"[Main] shut down target {name}", flush=True)
        except Exception as e:
            try:
                print(f"[Main] error while shutting down targets: {type(e).__name__}: {e}", flush=True)
            except Exception:
                pass

    def _shutdown(signum, frame):
        # raise SystemExit so with-blocks/locks unwind normally; atexit does the actual cleanup
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    atexit.register(_cleanup_workers)

    def _rank_code(c: str, items_ref: dict[str, dict]) -> int:
        return DIFF_RANK.get((items_ref.get(c, {}).get("difficulty") or "easy").lower(), 0)

    while True:
        items = fetch_all_unsolved()
        if items is None:
            print("[Fetcher] fetch failed (waiting 5 seconds)", flush=True)
            time.sleep(5)
            continue
        # do the cleanup/force-kill check even if the list is empty
        present = set(items.keys()) if isinstance(items, dict) else set()
        with stage_lock:
            preprocessed &= present
            solved &= present
            tier1 &= present
            tier2 = [c for c in tier2 if c in present]
            tier3 = [c for c in tier3 if c in present]
            # force-kill challenges that are solved / removed from the definitions but still running (including when the list is empty)
            for code in list(kill_flags.keys()):
                if code not in present:
                    try:
                        print(f"[Fetcher] challenge {code} solved or removed, force-stopping its sessions…", flush=True)
                    except Exception:
                        pass
                    try:
                        kill_flags[code].set()
                    except Exception:
                        pass
        if not present:
            # all challenges solved: wait for in-flight session groups to wrap up, then exit (atexit does the cleanup)
            with stage_lock:
                inflight_now = _inflight_count()
            if inflight_now == 0:
                print("[Fetcher] all challenges solved, exiting", flush=True)
                return
            time.sleep(1.0)
            continue

        # start preprocessing (dynamic, no hint, a separate executor per challenge, 50 steps)
        new_codes = [c for c in present if c not in preprocessed]
        for code in new_codes:
            if code in preproc_threads:
                continue
            if _inflight_count() >= MAX_INFLIGHT:
                break  # active slots are full; remaining challenges wait for the next scheduling round
            print(f"[Stage-Preprocess] starting {code} 50-step preprocessing…", flush=True)
            def _preproc_one(c: str, items_snap: dict[str, dict]):
                try:
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=50, prefetch_hint=False, disable_hint=True, kill_map=kill_flags)
                    with stage_lock:
                        if c in flagged:
                            preprocessed.add(c)
                            solved.add(c)
                        elif c in remaining:
                            preprocessed.add(c)
                            tier1.add(c)
                        # skipped: did not actually run, not marked preprocessed, retried with priority as a new challenge next round
                finally:
                    with stage_lock:
                        preproc_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t = threading.Thread(target=_preproc_one, args=(code, items.copy()), daemon=True)
            preproc_threads[code] = t
            t.start()

        # start tier 1 (dynamic parallel, no hint, a separate executor per challenge, 100 steps)
        with stage_lock:
            tier1_ready = sorted([c for c in tier1 if c not in tier1_threads], key=lambda c: _rank_code(c, items))
        for code in tier1_ready:
            if _inflight_count() >= MAX_INFLIGHT:
                break
            print(f"[Stage-Tier1] starting {code} (no hint) up to 100 steps…", flush=True)
            def _tier1_one(c: str, items_snap: dict[str, dict]):
                try:
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=100, prefetch_hint=False, disable_hint=True, kill_map=kill_flags)
                    with stage_lock:
                        if c in flagged:
                            solved.add(c)
                            tier1.discard(c)
                        elif c in remaining:
                            tier1.discard(c)
                            # promote to tier 2
                            tier2.append(c)
                        # skipped: did not actually run, stays in tier 1 for a retry
                finally:
                    with stage_lock:
                        tier1_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t = threading.Thread(target=_tier1_one, args=(code, items.copy()), daemon=True)
            with stage_lock:
                tier1_threads[code] = t
            t.start()

        # start tier 2 (parallel, no hint, a separate executor per challenge, 150 steps)
        with stage_lock:
            tier2_ready = [c for c in tier2 if c not in tier2_threads]
        for code in tier2_ready:
            if _inflight_count() >= MAX_INFLIGHT:
                break
            print(f"[Stage-Tier2] starting {code} (no hint) up to 150 steps…", flush=True)
            def _tier2_one(c: str, items_snap: dict[str, dict]):
                try:
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=150, prefetch_hint=False, disable_hint=True, kill_map=kill_flags)
                    with stage_lock:
                        if c in flagged:
                            try:
                                tier2.remove(c)
                            except ValueError:
                                pass
                            solved.add(c)
                        elif c in remaining:
                            # promote to tier 3
                            try:
                                tier2.remove(c)
                            except ValueError:
                                pass
                            tier3.append(c)
                        # skipped: did not actually run, stays in tier 2 for a retry
                finally:
                    with stage_lock:
                        tier2_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t2 = threading.Thread(target=_tier2_one, args=(code, items.copy()), daemon=True)
            with stage_lock:
                tier2_threads[code] = t2
            t2.start()

        # start tier 3 (parallel, with hint, a separate executor per challenge, 200 steps; hints are only used from level four on)
        with stage_lock:
            tier3_ready = [c for c in tier3 if c not in tier3_threads]
        for code in tier3_ready:
            if _inflight_count() >= MAX_INFLIGHT:
                break
            print(f"[Stage-Tier3] starting {code} (with hint) up to 200 steps…", flush=True)
            def _tier3_one(c: str, items_snap: dict[str, dict]):
                try:
                    # step_threshold=200: level four with hint, capped at 200 steps; converges on a flag / step threshold / platform removal (kill) / process exit
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=200, prefetch_hint=True, disable_hint=False, kill_map=kill_flags)
                    with stage_lock:
                        # remove from tier 3
                        try:
                            tier3.remove(c)
                        except ValueError:
                            pass
                        if c in flagged:
                            solved.add(c)
                        else:
                            # not solved or did not actually run: put back at the end of the queue
                            tier3.append(c)
                finally:
                    with stage_lock:
                        tier3_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t3 = threading.Thread(target=_tier3_one, args=(code, items.copy()), daemon=True)
            with stage_lock:
                tier3_threads[code] = t3
            t3.start()

        try:
            with stage_lock:
                pre_run = list(preproc_threads)
                t1_run = list(tier1_threads)
                t2_run = list(tier2_threads)
                t3_run = list(tier3_threads)
                t1_wait = [c for c in tier1 if c not in tier1_threads]
                t2_wait = [c for c in tier2 if c not in tier2_threads]
                t3_wait = [c for c in tier3 if c not in tier3_threads]
                solved_list = list(solved)
                inflight = _inflight_count()
                preprocessed_snap = set(preprocessed)
            pre_wait = [
                c for c in present
                if c not in preprocessed_snap and c not in pre_run
            ]
            runtime.set_scheduler(
                items=items,
                solved=solved_list,
                queues={
                    "preprocess": {"running": pre_run, "waiting": pre_wait},
                    "tier1": {"running": t1_run, "waiting": t1_wait},
                    "tier2": {"running": t2_run, "waiting": t2_wait},
                    "tier3": {"running": t3_run, "waiting": t3_wait},
                },
                max_active=MAX_INFLIGHT,
                inflight=inflight,
                worker_models=worker_models,
                solver_model=SOLVER_MODEL,
            )
        except Exception:
            pass

        # brief pause before the next scheduling round
        time.sleep(1.0)


if __name__ == "__main__":
    main()
