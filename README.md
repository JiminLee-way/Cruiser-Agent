# Cruiser

Cruiser is an automated agent for finding and exploiting CTF Web/logic vulnerabilities. It runs entirely on the local machine: challenges are defined in a local YAML file (`challenges.yaml`), and a target can be either an already-running service or a docker compose project. It automates the full loop of "read challenge → start target → drive the agent to solve → verify the flag → shut down the target", and raises solving throughput and success rate through multi-process concurrency, tiered scheduling, and a blackboard shared across sessions.

## Core architecture

Cruiser's solving engine drives an autonomous agent through the [`claude` CLI](https://docs.anthropic.com/en/docs/claude-code) (in `--output-format stream-json` streaming mode); the Anthropic-compatible endpoint defaults to DeepSeek. The system has three process layers with clear boundaries and crash recovery:

1. **Scheduler layer (`main.py` main process)** — the only process that manages target lifecycles. It polls unsolved challenges, schedules them in tiers by difficulty, starts workers, monitors `[COUNT]` step counts, shuts down targets and reaps orphan processes, and serves the local dashboard (default `http://127.0.0.1:8765`).
2. **Execution layer (worker subprocesses)** — copies of `main.py --sessions 1 --challenge-code <CODE>` with `CRUISER_WORKER_ID` set. Each calls `run_auto_scan()`, which in turn launches a `claude` CLI process.
3. **Agent layer (`claude` CLI process)** — the actual solving agent, which uses its built-in Bash/Read/Write and other tools for reconnaissance and exploitation.

Process chain: `main.py (scheduler) → main.py --sessions 1 (worker) → claude CLI → bash/python tool subprocesses`.

Cross-process collaboration goes through the **file system** (the `reports/` directory). All of it is made concurrency-safe with `fcntl` file locks plus atomic rewrites via a temp file and `os.replace`:

- **Shared blackboard** `reports/info_<code>.txt` — key facts found by each session (credentials, paths, endpoints, conclusions, etc.).
- **Exploration task board** `reports/tasks_<code>.txt` — exploration directions waiting to be claimed; claiming erases the entry, first come, first served.
- **Shared hint** `reports/hint_<code>.txt` — the hint from the challenge definition (written from tier 3 onward, shared by all sessions).
- **Solving progress** `reports/_platform_state.json` — the flags the local platform has accepted for each challenge (shared across processes; read and written by both `submit_flag.py` and the scheduler).

## Tiered scheduling

A new challenge is promoted through four queues, with a growing step threshold at each tier. As soon as any session finds the flag, the whole group stops:

| Tier | Trigger | Step threshold | Hint given |
|------|---------|----------------|------------|
| Pre-processing | New challenge | 50 | No |
| Tier 1 | Not solved in pre-processing | 100 | No |
| Tier 2 | Not solved in tier 1 | 150 | No |
| Tier 3 | Not solved in tier 2 | 200 | Yes (the hint is fetched only from tier 3 onward; if still unsolved, the challenge goes back to the end of the queue and retries in 200-step rounds) |

At each tier, `--sessions` **black-box** worker sessions run concurrently on the same challenge (black-box throughout, no source-code audit). Each session explores independently and signs its entries with its own session number, and the sessions exchange findings through the shared blackboard to reduce duplicate exploration. `--worker-models` lets you give each worker a different model (for example 2 × `deepseek-v4-flash` + 1 × `deepseek-v4-pro`). The number of challenges running at the same time is capped at 3 by default (`CRUISER_MAX_ACTIVE`).

## Shared blackboard

- **Hard context injection (`blackboard_hook.py`)** — writes `.claude/settings.json` into the worker's working directory to register hooks: `SessionStart` injects the challenge description + hint + current blackboard once at the start, and `PostToolUse` injects the latest content every 10 tool calls. The content enters the model context directly through `additionalContext`, so it does not depend on the model choosing to read it.
- **Blackboard curation watcher** — by default every 4 steps (`CRUISER_WATCHER_EVERY`), a separate watcher LLM reviews the session's recent activity in the background, maintains blackboard quality (extracts new key information, corrects or deletes stale entries), and recommends exploration directions to the task board. On the first successful submission, the submitting session writes a `[flag-method]` entry by itself; the watcher never adds, deletes, or edits these entries. When applying changes, entries are located by fuzzy content match to avoid line-number drift under concurrency. The watcher uses the **`deepseek-v4-pro`** model (override with `WATCHER_MODEL`).

## Project layout

```
Cruiser/
├── main.py                  # CLI entry: challenge scheduling, multi-session concurrency, tiered scheduling, target/process management
├── challenges.example.yaml  # Example challenge definitions (copy to challenges.yaml to use)
├── examples/web-demo/       # Demo target (Flask + docker compose, with one path traversal bug)
├── blackboard_hook.py       # Claude Code hook: hard-injects description/hint/blackboard into the model context
├── kill_orphans.py          # Fallback cleanup for dangling worker/claude processes
├── frontend/                # Dashboard static assets (served by cruiser/dashboard.py)
├── tools/                   # CLI wrapper scripts called by the agent
│   ├── submit_flag.py       # Submit a flag from the command line (called by the agent, verified by the local platform)
│   ├── dirsearch_scan.py    # Directory-scan CLI deduplicated across sessions (each URL is scanned once, others reuse it)
│   ├── task_board.py        # Exploration task board CLI (list/claim/report)
│   └── decompile.py         # PyGhidra headless decompiler CLI (C pseudocode + data-reference/switch-dispatch analysis + disassembly)
├── pyproject.toml           # Project configuration and dependencies
├── cruiser/
│   ├── __init__.py          # Package init: disables LangSmith tracing, loads .env
│   ├── challenges.py        # Local challenge platform: YAML definitions, target start/stop, flag verification and progress
│   ├── claude_agent.py      # Current solving engine: claude CLI driver + blackboard watcher
│   ├── taskboard.py         # Task board read/write (file lock + atomic rewrite)
│   ├── llm.py               # LLM providers: solver (DeepSeek) / watcher (deepseek-v4-pro)
│   ├── dashboard.py         # Dashboard HTTP: snapshot / blackboard / task board / logs
│   ├── runtime.py           # Scheduler runtime snapshot (read by the dashboard)
│   ├── prompt.py            # System prompts and task templates
│   └── tools.py             # submit_flag, dirsearch/xss and other tools
├── resource/                # Username/password/XSS payload wordlists
├── kb/                      # Offline vulnerability knowledge base (git submodules: vulhub / nuclei-templates / PayloadsAllTheThings; download the nuclei binary yourself)
├── tests/                   # pytest tests (local platform, flag submission, scheduler smoke test)
├── doc/                     # TECHNICAL_DESIGN.md (technical design)
└── reports/                 # Runtime shared blackboard / task board / hints / solving progress (empty dir is tracked; contents are generated and not tracked)
```

> **Offline knowledge base**: the three directories under `kb/` are git submodules linking to
> [vulhub](https://github.com/vulhub/vulhub),
> [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates), and
> [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).
> Clone with `--recurse-submodules` to fetch them (only pointers are stored; upstream files are not bundled into this repo).
> `kb/bin/nuclei` exceeds GitHub's 100MB per-file limit, so download it yourself from [nuclei Releases](https://github.com/projectdiscovery/nuclei/releases).
> You can also point `CRUISER_KB_DIR` at an existing knowledge base directory. A missing `kb/` does not affect the main flow; it only reduces local PoC lookup.

> **Dashboard**: the scheduler main process serves a dashboard at `http://127.0.0.1:8765` (challenge queue, blackboard, task board, flags, worker logs). You can also open it on its own with `uv run python -m cruiser.dashboard` (it only reads `reports/`). `CRUISER_DASHBOARD=0` turns it off; `CRUISER_DASHBOARD_PORT` / `CRUISER_DASHBOARD_HOST` change the port and listen address.

## Requirements

- Python >= 3.11
- [uv](https://docs.astral.sh/uv/) package manager
- **[claude CLI](https://docs.anthropic.com/en/docs/claude-code)** (must be installed and on PATH, or the engine cannot start)
- Optional: Docker (with the compose plugin) — only needed for `compose:` challenges; `target:` challenges need no Docker
- Optional: Ghidra + JDK (for PyGhidra reverse engineering in `tools/decompile.py`)

## Installation

```bash
# Install uv (if not installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone (including the three kb/ submodules)
git clone --recurse-submodules https://github.com/TJR181/Cruiser-Agent.git
cd Cruiser-Agent

# If you already cloned without initializing the submodules:
git submodule update --init --recursive

# Install dependencies
uv sync
```

Optional: download the zip for your platform from [nuclei Releases](https://github.com/projectdiscovery/nuclei/releases) and put the `nuclei` executable at `kb/bin/nuclei`. Skipping it does not affect the main flow.

> Note: `uv sync` only installs the core dependencies declared in `pyproject.toml`; while solving, the agent may install
> other Python packages on demand (such as `web3`/`slither`/`angr`-related ones). For consistency, offline deployment images ship
> a ready-made virtual environment as a whole instead of re-running `uv sync` in the target environment.

## Configuration

API keys are **always provided through environment variables** (they can be written to `.env` in the project root, which does not override variables that already exist); the source code contains no hard-coded keys. The repo ships a `.env.example` template; copy it to `.env` and fill in real values:

```bash
DEEPSEEK_API_KEY=<DeepSeek key>           # Required: used by default by the solving engine (claude CLI) and the watcher
KIMI_API_KEY=<Kimi/Moonshot key>          # Optional: used when a worker/watcher is set to a kimi model
GLM_API_KEY=<Tencent TokenHub key>        # Optional: used when a worker/watcher is set to a glm model
```

If `DEEPSEEK_API_KEY` is not configured and `ANTHROPIC_AUTH_TOKEN` is not set, startup prints a warning and the LLM cannot authenticate.
All logic for "which model/endpoint/key to use" lives in `cruiser/llm.py`, which **routes to the provider automatically by model name**:
`kimi-*` models use the Moonshot endpoint + `KIMI_API_KEY`, `glm-*` models use the Tencent TokenHub endpoint + `GLM_API_KEY`, and everything else (`deepseek-*`) uses the DeepSeek endpoint + `DEEPSEEK_API_KEY`.
So `--worker-models` can mix vendors, for example `deepseek-v4-flash,deepseek-v4-flash,kimi-k3,glm-5.3`.

> **Using GLM models**: set `GLM_API_KEY` in `.env`, then pick the solving model with `CRUISER_MODEL=glm-5.3`
> (the `glm5.3` spelling also works and is normalized to the TokenHub model ID `glm-5.3`); the watcher can be set
> separately with `WATCHER_MODEL=glm-5.3`. GLM-5.x models always think, so the framework automatically enables thinking for the claude CLI
> (`MAX_THINKING_TOKENS=32000`, adjustable). glm-5.3/5.2 have a 1M context window
> (the framework manages compaction for that by default); older models such as glm-5.1/5/5-turbo have 200K, so set
> `CLAUDE_CODE_MAX_CONTEXT_TOKENS=200000` explicitly when using them.
> The default TokenHub endpoint is `https://tokenhub.tencentmaas.com`; override it with `GLM_ANTHROPIC_BASE_URL` / `GLM_BASE_URL`.

> **Endpoint defaults**: each provider's endpoint defaults to its official https address (such as `https://api.deepseek.com/anthropic`,
> `https://api.deepseek.com/v1`), and each can be overridden explicitly with the matching `*_BASE_URL` environment variable (for example, to use your own gateway/proxy).

> Tip: never commit a `.env` containing real keys to version control; add it to `.gitignore` and rotate keys properly.

## Challenge definitions (local platform)

Cruiser does not depend on any external competition platform: challenges, targets, and flag answers all live in one YAML file managed by `cruiser/challenges.py`.
The file path comes from `CRUISER_CHALLENGES` (relative paths resolve against the current directory) and defaults to `challenges.yaml` in the project root (gitignored; see `challenges.example.yaml` for a template).

```yaml
challenges:
  - code: WEB-1                  # Required, of the form <alphanumeric>-<digits> (the agent recognizes submit commands by this shape)
    difficulty: easy             # easy / medium / hard (default easy), decides scheduling order
    description: Login page, the admin password is weak
    hint: Try common weak passwords  # Optional; only given to the agent from tier 3 (200 steps) onward
    flags:                       # Required, at least one; with several flags, all must be submitted (progress X/Y) to count as solved
      - flag{plain_text_flag}    # Plain text
      - sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08   # Or a sha256 digest, so the answer need not be stored in plain text
    target: http://127.0.0.1:8080   # Target option 1: an already-running service (string or list); start/stop are no-ops

  - code: WEB-2
    difficulty: medium
    flags: ["flag{another_one}"]  # Flags inside an inline list [...] contain braces and must be quoted
    compose: challenges/web2/docker-compose.yml   # Target option 2: a docker compose file (relative to this YAML's directory)
    addresses: ["127.0.0.1:8082"]                 # Required with compose: addresses given to the agent (http:// is added when no scheme is given)
```

- **Compose targets**: start runs `docker compose -p cruiser_<code> -f <file> up -d`, followed by a port readiness probe (`CRUISER_CONTAINER_WARMUP`); each round ends with `docker compose -p cruiser_<code> -f <file> down -v`. On startup and exit, the scheduler runs `down` on any leftover `cruiser_*` projects.
- **Solving progress** is stored in `reports/_platform_state.json` (`fcntl` file lock + atomic rewrite, shared across processes by workers, solvers, and the `submit_flag.py` the agent calls). Resubmitting an already-accepted flag counts as an idempotent success; once all flags are in, the challenge is removed from the unsolved list, and the scheduler exits automatically when every challenge is solved.
- The challenge definition file is reloaded automatically when it changes (by mtime); if YAML validation fails, startup errors out and names the challenge and field at fault.

Platform CLI:

```bash
uv run python -m cruiser.challenges list            # Show challenges and flag progress
uv run python -m cruiser.challenges reset [CODE…]   # Clear progress (all challenges when no argument is given), for reruns
uv run python -m cruiser.challenges down            # Manually bring down all cruiser_* compose projects
```

### End-to-end demo

`examples/web-demo/` is a Flask target of about 30 lines (a note viewer; `/view?name=` has a path traversal bug, and the flag comes from the `FLAG` environment variable):

```bash
cp challenges.example.yaml challenges.yaml   # Contains DEMO-1 (compose mode, flag stored as sha256)
cp .env.example .env                          # Fill in DEEPSEEK_API_KEY
uv run python main.py --sessions 2
```

Without Docker, start the service by hand first, then configure it like the commented-out `DEMO-2` (`target:` mode) in `challenges.example.yaml`:

```bash
FLAG='flag{cruiser_local_demo_path_traversal}' PORT=5000 uv run python examples/web-demo/app.py
```

## Usage

### Automatic mode (schedule challenge by challenge from the definitions, recommended)

```bash
uv run python main.py --sessions 5
```

The main process validates the challenge definitions, cleans up leftover `cruiser_*` compose projects, then solves challenges concurrently with tiered scheduling and exits once all challenges are solved. Open `http://127.0.0.1:8765` in a browser to see the dashboard.

### Scan a single target

```bash
uv run python main.py --target http://<IP:port> --challenge-code <CODE>
```

`<CODE>` must be a challenge in the definitions (flag verification depends on its answer); without `--target`, the local platform starts that challenge's target.

### Command-line options

| Option | Default | Description |
|--------|---------|-------------|
| `--target` | none | Target address to scan (when omitted, the local platform starts the challenge's target to get the address) |
| `--challenge-code` | none | Challenge code |
| `--sessions` | 1 | Number of concurrent worker sessions (tiered scheduling starts at >=2) |
| `--worker-models` | none | Comma-separated list of models, one per worker (such as `deepseek-v4-flash,deepseek-v4-flash,kimi-k3`); when given, the worker count equals the list length and overrides `--sessions`; `kimi-*` models are routed to the Kimi endpoint automatically |
| `--max-steps` | 0 | Maximum AI scan steps (0 = no forced stop inside the engine; the scheduler monitors thresholds) |
| `--hint` | none | Challenge hint (helps the agent reason) |
| `--quiet` | False | Silence intermediate output and keep only the final JSON |
| `--default-timeout` | 0 | Default `run_command` timeout in seconds (0 = built-in default) |
| `--max-timeout` | 0 | Upper limit for the `run_command` timeout in seconds (0 = built-in limit) |

## Environment variables

| Variable | Description |
|----------|-------------|
| `CRUISER_CHALLENGES` | Path to the challenge definition YAML (default `challenges.yaml` in the project root) |
| `DEEPSEEK_API_KEY` | DeepSeek key (used by default by the solving engine and the watcher) |
| `KIMI_API_KEY` | Kimi/Moonshot key (used automatically for `kimi-*` models) |
| `GLM_API_KEY` | Tencent TokenHub key (used automatically for `glm-*` models) |
| `GLM_ANTHROPIC_BASE_URL` / `GLM_BASE_URL` | GLM's Anthropic / OpenAI-compatible endpoints (default `https://tokenhub.tencentmaas.com`, `.../v1`) |
| `CRUISER_MODEL` | Solving engine model (highest priority, overrides `ANTHROPIC_MODEL`/`DEEPSEEK_MODEL`; the recommended way to pick a model across vendors, such as `glm-5.3`) |
| `KIMI_ANTHROPIC_BASE_URL` / `KIMI_BASE_URL` | Kimi's Anthropic / OpenAI-compatible endpoints (default `https://api.moonshot.cn/anthropic`, `.../v1`) |
| `DEEPSEEK_MODEL` / `ANTHROPIC_MODEL` | Solving engine model (default `deepseek-v4-flash`) |
| `DEEPSEEK_BASE_URL` | DeepSeek OpenAI-compatible endpoint (default `https://api.deepseek.com/v1`) |
| `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` | Anthropic-compatible endpoint used by the claude CLI (DeepSeek default `https://api.deepseek.com/anthropic`) and its token |
| `CLAUDE_CODE_MAX_CONTEXT_TOKENS` | Declares the model's real context window (default `1000000`, i.e. DeepSeek 1M; used to correct when auto-compact triggers) |
| `CLAUDE_CODE_AUTO_COMPACT_WINDOW` | Token threshold for triggering context compaction early (default `800000`, leaving headroom before the hard limit) |
| `WATCHER_MODEL` | Blackboard watcher model (default `deepseek-v4-pro`) |
| `WATCHER_TEMPERATURE` | Watcher temperature (not sent by default; left to the server) |
| `CRUISER_WATCHER_EVERY` | Trigger the watcher every N steps (default 4) |
| `CRUISER_WATCHER_RECENT` | Number of entries in the watcher's activity window (default 48; the latest 12 are kept in full) |
| `CRUISER_WATCHER_SUBMIT` | Set to `0` to turn off the watcher's fallback automatic flag submission |
| `CRUISER_DASHBOARD` | Set to `0` to turn off the dashboard (on by default) |
| `CRUISER_DASHBOARD_HOST` / `CRUISER_DASHBOARD_PORT` | Dashboard listen address and port (default `127.0.0.1:8765`) |
| `CRUISER_LOG_FILE` | Scheduler log path read by the dashboard (default `/tmp/cruiser.log`) |
| `CRUISER_MAX_ACTIVE` | Maximum number of challenges running at the same time (default 3) |
| `CRUISER_CONTAINER_WARMUP` | Upper limit in seconds for the target readiness probe (default 60): after getting the address, the target port is probed actively and sessions start once it accepts connections; on timeout they start anyway and the LLM takes over, to avoid hanging |
| `CRUISER_KB_DIR` | Offline vulnerability knowledge base directory (default `kb/`; used for nuclei/PoC lookup) |
| `CRUISER_MAX_TURNS` | Maximum **turns** per claude session (default 0 = unlimited; note that a turn ≠ a log `[COUNT]`; `[COUNT]` is roughly several times the turn count) |
| `CRUISER_SOLVER_MAX_TURNS` / `CRUISER_MAX_SOLVERS` / `CRUISER_SOLVER_MODEL` | Per-session solver turn limit (default 40) / maximum concurrent solvers per challenge (default 3) / solver model (default `deepseek-v4-flash`) |
| `CRUISER_SESSIONS` / `CRUISER_WORKER_ID` | Total session count / worker session number (injected into subprocesses automatically) |
| `CRUISER_WORKER_MODELS` | Per-worker model list (same as `--worker-models`, comma-separated) |
| `CRUISER_WORKSPACE_DIR` | Session workspace directory (injected into subprocesses automatically) |
| `CRUISER_TEMP_MIN` / `CRUISER_TEMP_MAX` | Lower/upper LLM temperature bound across sessions (default 0.0 / 0.9) |
| `CRUISER_DEFAULT_TIMEOUT` / `CRUISER_MAX_TIMEOUT` | Default/maximum command timeout (seconds) |
| `CRUISER_QUIET` | Set to `1` to suppress intermediate output |
| `CRUISER_DEBUG` | Set to `1` to enable debug output |
| `GHIDRA_INSTALL_DIR` / `JAVA_HOME` | PyGhidra reverse-engineering runtime |

## Built-in tools and scripts

| Tool/script | Purpose |
|-------------|---------|
| `tools/submit_flag.py` | Submit a flag to the local platform and verify it (the receipt includes progress X/Y) |
| `python -m cruiser.challenges` | Local platform CLI: `list` / `reset` / `down` |
| `tools/dirsearch_scan.py` | Directory scan deduplicated across sessions (sessions hitting the same URL scan it once; the rest block and reuse the report) |
| `tools/task_board.py` | Task board `list` / `claim` / `report` |
| `tools/decompile.py` | PyGhidra headless decompiler: prints C pseudocode and annotates loads the compiler eliminated, the meaning of each switch case, and unconfirmed opcodes |
| `kill_orphans.py` | Cleans up dangling worker/claude process groups whose parent has died |
| `cruiser/dashboard.py` | Dashboard HTTP (started by the scheduler main process automatically; or `uv run python -m cruiser.dashboard`) |
| Web/pentest | `dirsearch` / `sqlmap` / `fenjing` / `nuclei` (built-in template library) / `ffuf` / `whatweb` / Metasploit + PostgreSQL |
| Reversing/Pwn | Ghidra + PyGhidra / `radare2` / `pwntools` / `angr` / `ropper` / `one_gadget` / GDB |
| Crypto/forensics | `pycryptodome` / `gmpy2` / `sympy` / `z3` / `steghide` / `zsteg` / `binwalk`, etc. |
| Smart contracts | Foundry (`forge`/`cast`/`anvil`) / multiple `solc` versions / `slither` / `web3.py` |
| Offline knowledge base | `kb/`: vulhub / nuclei-templates / PayloadsAllTheThings (local PoC lookup by CVE/component) |
| `resource/*.txt` | Username / password / XSS payload wordlists |

## Tests

```bash
uv run pytest
```

Covers YAML parsing and validation, plain-text/sha256 flag verification, multi-flag X/Y progress, duplicate submissions, concurrent submissions from multiple processes, compose start/stop (with `subprocess` mocked), `tools/submit_flag.py` end to end, and a scheduler smoke test that runs `main.py --sessions 2` with a stub `claude` CLI (no LLM key, Docker, or network needed).

## License

This project is open source under the [Apache License 2.0](LICENSE).

**Disclaimer**: this project is for security research and CTF learning only. Do not use it against targets you are not authorized to test. Users bear full responsibility for any consequences of using this project.
