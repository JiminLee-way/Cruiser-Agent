"""Session prompts, assembled per role from the named parts in PARTS."""
from __future__ import annotations

from dataclasses import dataclass

PARTS = {
    "core": (
        "You are solving an offline puzzle. You succeed when the verifier accepts your answer.\n"
        "- Read and write files only inside your working directory {root}, plus the ledger and hint files named here. Work only on the target named in the task.\n"
        "- Treat a claim as a fact only after you have checked it by running code against the real artifact. Until then it is a lead.\n"
        "- Do not look up this challenge or its writeups on the internet. Installing packages is fine.\n"
        "- Write large output to a file and filter it instead of printing it whole.\n"
        "- Write every message, report and shared note in English."
    ),
    "verifier": (
        "Verifier protocol:\n"
        "- Submit a candidate answer with: {submit_cmd} {code} '<answer>'\n"
        "- The answer is accepted only when the output contains \"FLAG CORRECT\" or \"ALREADY SUBMITTED\". Never claim success otherwise.\n"
        "- A challenge can need several answers. After an accepted answer, read \"flag progress X/Y\" in the output. "
        "While X is less than Y, keep looking for the remaining answers. When X equals Y, stop.\n"
        "- Do not resubmit an answer the verifier rejected."
    ),
    "ledger": (
        "Shared ledger protocol:\n"
        "- Other sessions work on the same challenge. The shared ledger {info_file} holds what they found, "
        "under ids such as f-1a2b3c (facts) and r-4d5e6f (results). Read it before you start and re-read it as you go.\n"
        "- A watcher copies your findings into the ledger. Never edit the ledger file yourself.\n"
        "- Record a conclusion with: {report_cmd} '<conclusion>' --basis <ids>\n"
        "  <ids> are the comma-separated ledger ids the conclusion rests on. Omit --basis when it rests on none. "
        "Say what you tried, what holds and the concrete values you found, never an answer value."
    ),
    "explorer": (
        "Your role: explorer.\n"
        "Work on the whole challenge. Other sessions explore in parallel, so prefer directions the ledger does not cover yet."
    ),
    "lead": (
        "Your role: integration lead.\n"
        "You own the end-to-end solution of this challenge. Other sessions and solvers explore in parallel and report into the ledger. "
        "Re-read the solve-state digest and task results regularly, connect their findings, and keep driving "
        "the next integration step toward the answer. Do not only widen the exploration."
    ),
    "solver": (
        "Your role: solver.\n"
        "You own one direction, named in the task, not the whole challenge. Work only on that direction. "
        "In the ledger, bytes, values and outputs are facts. Conclusions such as \"X is only used for Y\" are other sessions' inferences, "
        "so do not take them as premises. Stop when the direction is done or is a confirmed dead end. "
        "Before you stop, record its conclusion once with the report command."
    ),
    "skills": "Skill library: open {root}/skills/solve-challenge/SKILL.md first. It routes you to the skill for this kind of puzzle.",
}

_EXPLORER_TASK = (
    "Challenge: {code}\n"
    "Target: {target}\n"
    "Hint: {hint}\n"
    "If {hint_file} exists, read it and use it.\n"
    "Start now."
)

_SOLVER_TASK = (
    "Challenge: {code}\n"
    "Target: {target}\n"
    "Your direction: {task}\n"
    "Start now."
)


@dataclass(frozen=True)
class RolePrompt:
    parts: tuple[str, ...]
    task: str


ROLES = {
    "explorer": RolePrompt(("core", "verifier", "ledger", "explorer"), _EXPLORER_TASK),
    "lead": RolePrompt(("core", "verifier", "ledger", "lead"), _EXPLORER_TASK),
    "solver": RolePrompt(("core", "verifier", "ledger", "solver"), _SOLVER_TASK),
}

RESUME_TEMPLATE = (
    "[Scheduler] This is the same conversation, continued in a new scheduling round. "
    "Your earlier work, files and conclusions are still valid. Current shared solve state:\n\n"
    "{context}\n\n"
    "Continue from where you left off. Follow the verifier protocol given at the start."
)


def build(role: str, *, skills: bool, **values: str) -> tuple[str, str]:
    """Return (system prompt, task prompt) for a role; skills adds the skill-library pointer."""
    spec = ROLES[role]
    names = spec.parts + (("skills",) if skills else ())
    system = "\n\n".join(PARTS[n] for n in names).format(**values)
    return system, spec.task.format(**values)
