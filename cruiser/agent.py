from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Dict, List, Optional
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from .tools import ALL_TOOLS,  list_security_tools_tool
from .llm import get_llm
from .prompt import (
    BASE_SYSTEM_PROMPT,
    REACT_INSTRUCTION_TEMPLATE,
    REFLECT_PROMPT,
    SCAN_QUESTION_TEMPLATE,
    WORKER_HINT_TEMPLATE,
)

# ------------------------------
# Fetch an overview of available security tools at startup
# ------------------------------
_SECURITY_TOOLS_OVERVIEW: str = ""

def _refresh_security_tools_overview() -> None:
    """Call list_security_tools_tool to get the command-line security tools available in this environment and build a short overview.
    The overview is injected into the system prompt to help the model understand the environment's capabilities; it is also printed to the console (green) at startup.
    """
    global _SECURITY_TOOLS_OVERVIEW
    try:
        # Invoke the tool
        txt = list_security_tools_tool.invoke({"only_available": True, "with_version": True})

        # Write the result to a file first, then read it back (for auditing and reuse)
        try:
            out_dir = os.path.join(os.getcwd(), "reports")
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, "list_security_tools.json")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(txt if isinstance(txt, str) else str(txt))
            # Read back
            with open(out_path, "r", encoding="utf-8") as f:
                txt = f.read()
        except Exception:
            # Failing to write the file does not affect the main flow
            pass
        summary = "none"
        try:
            arr = json.loads(txt)
            if isinstance(arr, list):
                items = []
                for t in arr:
                    name = (t or {}).get("name") or ""
                    ver = (t or {}).get("version") or ""
                    items.append(name + (f" ({ver})" if ver else ""))
                summary = ", ".join([s for s in items if s]) or "none"
        except Exception:
            # If the result is not JSON, fall back to showing the first line of the raw text
            line = (txt or "").strip().splitlines()[:1]
            summary = line[0] if line else "none"
        _SECURITY_TOOLS_OVERVIEW = summary
        # Print to the console in green (non-quiet mode)
        if os.environ.get("CRUISER_QUIET") != "1":
            try:
                print("\x1b[32m" + f"[SECURITY] Available tools: {summary}" + "\x1b[0m")
            except Exception:
                print(f"[SECURITY] Available tools: {summary}")
    except Exception:
        # Fail silently
        pass


# ------------------------------
# Lightweight error classification
# ------------------------------
def _is_context_limit_error(err: Exception) -> bool:
    """Detect context-limit errors more strictly to avoid false positives.

    The error is treated as a context-limit error only when its text contains one of these more explicit phrases:
    - "maximum context length"
    - "max context length"
    - "token limit"
    - "exceeds" together with "token" or "context"
    - "exceeded" together with "token" or "context"
    - "context window" together with "exceed"
    """
    try:
        text = f"{getattr(err, 'message', '')} {err}"
        text = (text or "").lower()
        if "maximum context length" in text or "max context length" in text:
            return True
        if "token limit" in text:
            return True
        if ("exceeds" in text or "exceeded" in text) and ("token" in text or "context" in text):
            return True
        if "context window" in text and ("exceed" in text or "exceeded" in text):
            return True
        return False
    except Exception:
        return False

# ------------------------------
# In-session conversation history (in memory, lives only as long as the current process)
# ------------------------------
_CONV_HISTORY: List[Dict[str, str]] = []  # Each item: {"q": str, "a": str, "r"?: str, "n"?: str}


def _format_conversation_context(limit: int = 10) -> str:
    if not _CONV_HISTORY:
        return ""
    lines: List[str] = []
    for item in _CONV_HISTORY[-limit:]:
        q = item.get("q", "")
        a = item.get("a", "")
        r = item.get("r", "")
        n = item.get("n", "")
        # Truncate moderately to avoid overly long text
        q_show = (q[:400] + "…") if len(q) > 400 else q
        a_show = (a[:400] + "…") if len(a) > 400 else a
        line = f"- U: {q_show}\n  A: {a_show}"
        if r:
            r_show = (r[:400] + "…") if len(r) > 400 else r
            line += f"\n  R: {r_show}"
        if n:
            n_show = (n[:400] + "…") if len(n) > 400 else n
            line += f"\n  N: {n_show}"
        lines.append(line)
    return "\n".join(lines)


def _is_info_duplicate(challenge_code: str, info: str) -> bool:
    """Check whether a piece of key info already exists (deduplication).
    
    Uses smart matching: extracts the key parts for comparison to avoid writing similar info twice.
    
    Args:
        challenge_code: challenge ID
        info: key info
        
    Returns:
        True if the info already exists, otherwise False
    """
    if not challenge_code or not info:
        return True
    try:
        out_dir = os.path.join(os.getcwd(), "reports")
        info_path = os.path.join(out_dir, f"info_{challenge_code}.txt")
        if not os.path.exists(info_path):
            return False
        
        # Read the existing info
        with open(info_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        if not content:
            return False
        
        info_normalized = info.lower().strip()
        
        # Method 1: exact match
        if f"info: {info}" in content or f"info: {info_normalized}" in content.lower():
            return True
        
        # Method 2: match on extracted key parts (for paths, APIs, etc.)
        # Extract key parts such as paths, URLs and passwords
        # Extract paths
        path_pattern = r'([/\w\-\.]+\.(php|html|txt|js|css|json|xml))'
        new_paths = set(re.findall(path_pattern, info, re.IGNORECASE))
        if new_paths:
            # Check whether the existing info already contains these paths
            for path_tuple in new_paths:
                path = path_tuple[0] if isinstance(path_tuple, tuple) else path_tuple
                if path.lower() in content.lower():
                    return True
        
        # Extract URLs
        url_pattern = r'(https?://[^\s]+)'
        new_urls = set(re.findall(url_pattern, info, re.IGNORECASE))
        if new_urls:
            for url in new_urls:
                if url.lower() in content.lower():
                    return True
        
        # Method 3: for short info (e.g. passwords, simple paths), check whether it already exists
        if len(info) < 100:
            # Collect all existing info lines
            lines = content.split("\n")
            existing_infos = []
            for i, line in enumerate(lines):
                if "info:" in line:
                    existing_info = line.split("info:")[-1].strip().lower()
                    if existing_info:
                        existing_infos.append(existing_info)
            
            # Check whether the new info is highly similar to existing info
            for existing in existing_infos:
                # If the new info is a subset or superset of existing info, treat it as a duplicate
                if info_normalized in existing or existing in info_normalized:
                    # But allow partial overlap (e.g. different paths); only full containment counts as a duplicate
                    if len(info_normalized) > 20 and len(existing) > 20:
                        # Compute similarity (simple method: ratio of shared words)
                        new_words = set(info_normalized.split())
                        existing_words = set(existing.split())
                        if new_words and existing_words:
                            overlap = len(new_words & existing_words)
                            similarity = overlap / min(len(new_words), len(existing_words))
                            if similarity > 0.8:  # Over 80% similar counts as a duplicate
                                return True
                    else:
                        # Short info: check containment directly
                        if info_normalized == existing or (len(info_normalized) < 30 and info_normalized in existing):
                            return True
        
        return False
    except Exception:
        # On error, be conservative and do not write
        return True


def _write_shared_info(challenge_code: str, worker_id: str, info: str) -> None:
    """Write key info to the shared file (with a deduplication check).
    
    Args:
        challenge_code: challenge ID
        worker_id: session number
        info: key info (e.g. default passwords, paths, APIs)
    """
    if not challenge_code or not info:
        return
    
    # Deduplication check
    if _is_info_duplicate(challenge_code, info):
        return
    
    try:
        out_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(out_dir, exist_ok=True)
        info_path = os.path.join(out_dir, f"info_{challenge_code}.txt")
        # Use append mode so multiple sessions can write
        with open(info_path, "a", encoding="utf-8") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] session: {worker_id}\n")
            f.write(f"info: {info}\n")
            f.write("-" * 60 + "\n")
    except Exception:
        pass


def _read_shared_info(challenge_code: str, limit: int = 5) -> str:
    """Read the shared key-info file; by default return only the last 5 entries.
    
    Args:
        challenge_code: challenge ID
        limit: number of entries to return, default 5
        
    Returns:
        The text of the shared info, or an empty string if the file does not exist or cannot be read
    """
    if not challenge_code:
        return ""
    try:
        out_dir = os.path.join(os.getcwd(), "reports")
        info_path = os.path.join(out_dir, f"info_{challenge_code}.txt")
        if os.path.exists(info_path):
            with open(info_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    # Split on the separator line; each entry ends with "------------------------------------------------------------"
                    separator = "-" * 60
                    # Split on the separator, keeping the content before and after it
                    parts = content.split(separator)
                    # Drop empty entries and recombine (each entry + separator)
                    entries = []
                    for i, part in enumerate(parts):
                        part = part.strip()
                        if part:
                            entries.append(part)
                    # Take the last `limit` entries
                    if entries:
                        last_entries = entries[-limit:]
                        # Recombine, appending a separator line after each entry
                        result = (separator + "\n").join(last_entries)
                        if result:
                            return f"\nShared key info (from other sessions, latest {len(last_entries)} entries):\n{result}\n{separator}\n"
    except Exception:
        pass
    return ""


def _extract_key_info(observation: str, thought: str, tool: str, llm) -> Optional[Dict[str, str]]:
    """Extract objective key info from an observation.
    
    Key info includes: default passwords, new paths, new APIs, etc.
    Note: an already-identified vulnerability point does not count as key info.
    The LLM is used directly to judge whether something is objective key info.
    
    Args:
        observation: observation from the tool run
        thought: current thought
        tool: the tool used
        llm: LLM instance used to judge whether it is key info
        
    Returns:
        {"info": "..."} if it is key info, otherwise None
    """
    if not observation or len(observation) < 10 or llm is None:
        return None
    
    try:
        verify_prompt = (
            "Determine whether the following contains objective key info; this covers only default passwords, new paths and new APIs\n"
            f"Thought: {thought}\n"
            f"Observation: {observation}\n"
            f"Tool used: {tool}\n\n"
            "Criteria:\n"
            "1. It must be objective, verifiable info (e.g. a concrete path, API, password)\n"
            "2. It must actually help solve the challenge\n"
            "3. Do not extract basic info such as server fingerprints or version numbers (unless it is a specific vulnerable version)\n"
            "4. Do not extract widely known info\n"
            "6. The info must be concise and clear; avoid lengthy descriptions\n\n"
            "7. Judge whether the info is correct by combining the thought and the observation\n"
            "Examples of key info: default passwords, newly found paths, newly found API endpoints, config file locations, etc.\n"
            "If it is objective key info, return JSON: {\"is_key\": true, \"info\": \"key info (concise, at most 50 words)\"}\n"
            "If it is not key info, return JSON: {\"is_key\": false}\n"
            "Return only JSON, nothing else."
        )
        verify_msgs = [
            SystemMessage(content="You are an information-extraction assistant responsible for identifying objective key info. Only identify key info that actually exists and is verifiable, such as default passwords and newly found paths/APIs."),
            HumanMessage(content=verify_prompt),
        ]
        verify_resp = llm.invoke(verify_msgs)
        verify_text = verify_resp.content if isinstance(verify_resp.content, str) else json.dumps(verify_resp.content)
        vs, ve = verify_text.find("{"), verify_text.rfind("}")
        if vs != -1 and ve != -1:
            verify_obj = json.loads(verify_text[vs: ve + 1])
            if verify_obj.get("is_key"):
                info = verify_obj.get("info", "").strip()
                if info:
                    return {
                        "info": info
                    }
    except Exception:
        # LLM judgment failed; do not record
        pass
    
    return None


def _should_print_llm_input() -> bool:
    """Whether to print the input sent to the LLM.

    Off by default; on when CRUISER_PRINT_LLM_INPUT is "1" or "true"; never printed when CRUISER_QUIET=1.
    """
    if os.environ.get("CRUISER_QUIET") == "1":
        return False
    val = (os.environ.get("CRUISER_PRINT_LLM_INPUT", "0") or "0").lower().strip()
    return val in {"1", "true"}


def _render_msgs_for_print(msgs: List[object]) -> str:
    """Render the messages sent to the LLM as readable text."""
    parts: List[str] = []
    for m in msgs:
        try:
            role = getattr(m, "type", None) or getattr(m, "role", None)
            if not role:
                # LangChain message classes: SystemMessage/HumanMessage/AIMessage/ToolMessage
                cls_name = m.__class__.__name__.replace("Message", "").lower()
                role = "system" if "system" in cls_name else ("human" if "human" in cls_name else ("ai" if "ai" in cls_name else ("tool" if "tool" in cls_name else cls_name)))
            content = getattr(m, "content", "")
            if not isinstance(content, str):
                try:
                    content = json.dumps(content, ensure_ascii=False)
                except Exception:
                    content = str(content)
            parts.append(f"[{role}]\n{content}")
        except Exception:
            try:
                parts.append(str(m))
            except Exception:
                parts.append("<unprintable message>")
    return "\n---\n".join(parts)


def _print_llm_input(msgs: List[object], label: str = "") -> None:
    """Print the messages about to be sent to the LLM."""
    if not _should_print_llm_input():
        return
    try:
        rendered = _render_msgs_for_print(msgs)
        header = f"[LLM Input]{' ' + label if label else ''}"
        to_stderr = os.environ.get("CRUISER_DEBUG_STDERR") == "1"
        if to_stderr:
            print(header, file=sys.stderr)
            print(rendered, file=sys.stderr)
        else:
            print(header)
            print(rendered)
    except Exception:
        pass


def build_system_prompt() -> str:
    # Build the tool descriptions dynamically to avoid hardcoding
    lines = [BASE_SYSTEM_PROMPT]
    # Inject an overview of the command-line security tools available in this environment
    if _SECURITY_TOOLS_OVERVIEW:
        lines.append("\n\nCommand-line security tools available in this environment: " + _SECURITY_TOOLS_OVERVIEW + "\n")
    lines.append("\nAvailable tools (name: description):\n")
    for t in ALL_TOOLS:
        desc = (t.description or "").strip()
        lines.append(f"- {t.name}: {desc}")
    return "".join(s if isinstance(s, str) else str(s) for s in lines)


def _tool_map() -> Dict[str, any]:
    return {t.name: t for t in ALL_TOOLS}


def _tool_specs_text() -> str:
    """Generate a readable argument spec and a minimal example for each available tool, helping the model "see" how to call it."""
    parts: List[str] = ["\nTool argument specs and examples:\n"]
    # Preset minimal examples (closer to real usage)
    minimal_examples = {
        "read_file": {"tool": "read_file", "args": {"path": "./README.md"}},
        "run_command": {"tool": "run_command", "args": {"command": "echo hello"}},
    }
    for t in ALL_TOOLS:
        desc = (t.description or "").strip()
        parts.append(f"- {t.name}: {desc}")
        schema = getattr(t, "args_schema", None)
        try:
            if schema is not None and hasattr(schema, "model_json_schema"):
                js = schema.model_json_schema()
                required = js.get("required", [])
                properties = js.get("properties", {})
                # Show only condensed info: required fields and field descriptions
                props_lines: List[str] = []
                for k, v in properties.items():
                    pdesc = v.get("description") or ""
                    ptype = v.get("type") or v.get("anyOf") or ""
                    props_lines.append(f"    • {k}: {pdesc} (type={ptype})")
                parts.append(f"  Required fields: {required if required else 'none'}")
                if props_lines:
                    parts.append("  Fields:")
                    parts.extend(props_lines)
        except Exception:
            pass
        # Example
        try:
            example = minimal_examples.get(t.name)
            if example:
                parts.append("  Example (one-line JSON):")
                parts.append("  " + json.dumps(example, ensure_ascii=False))
        except Exception:
            pass
        parts.append("")
    return "\n".join(parts)



def _react_until_flag(llm, user_input: str, flag_key: str = "flag", max_steps: int = 0, quiet: bool = False, challenge_code: Optional[str] = None) -> str:
    """Continuous ReAct loop that only stops when a JSON flag is produced.

    - max_steps <= 0 means unlimited.
    - Requires the model to set tool='none' only when it can output final JSON
      like {"flag":"flag_content"}. Premature stops are ignored and the loop continues.
    """
    tool_names = "|".join([t.name for t in ALL_TOOLS] + ["none"])  # Build the list of selectable tool names dynamically
    conv_ctx = _format_conversation_context(10)

    # Read the tunable timeout policy (not used directly in this function at the moment; kept in the instructions)

    tool_names_list = [t.name for t in ALL_TOOLS]
    tool_names_str = f"Available tool names: {tool_names_list}."
    tool_specs_text = _tool_specs_text()
    react_instruction = (
        REACT_INSTRUCTION_TEMPLATE.replace("{tool_names_placeholder}", tool_names_str, 1)
        .replace("{tool_specs_placeholder}", tool_specs_text)
        .replace("{tool_names_placeholder}", tool_names)
    )
    instruction = (
        build_system_prompt()
        + ("\n\nRecent conversation (up to 10 turns):\n" + conv_ctx if conv_ctx else "")
        + react_instruction
    )

    def _replace_hint_line(q: str, hint: str) -> str:
        try:
            lines = q.splitlines()
            for i in range(len(lines)):
                if lines[i].strip().startswith("Challenge hint: "):
                    lines[i] = f"Challenge hint: {hint}"
                    return "\n".join(lines)
            # Otherwise insert it at the top
            return f"Challenge hint: {hint}\n" + q
        except Exception:
            return q



    # Bind the current challenge's challenge_code (dispatched by the external scheduler or provided via an environment variable)
    current_challenge_code = os.environ.get("CRUISER_CHALLENGE_CODE") or (challenge_code or "")


    # Outer loop: iterate by task round (each round is one full scan of the target; after a flag is found the policy decides whether to switch targets or wait)
    worker_id = os.environ.get("CRUISER_WORKER_ID", "unknown")
    while True:
        scratchpad = ""
        step = 0
        mapping = _tool_map()
        total_steps_for_target = 0
        hint_requested_for_this_target = False
        hint = ""
        gethint = False
        flag_confirmed = False
        cached_shared_info = ""  # Cached key info
        last_info_read_step = -1  # Step at which key info was last read
        while True:
            # Task switching is monitored and controlled by the external scheduler (main); the session no longer polls for task changes

            # If a shared hint file exists (written by any session), all sessions see the hint (can be disabled via the CRUISER_DISABLE_HINT environment variable)
            if hint == "" and current_challenge_code and os.environ.get("CRUISER_DISABLE_HINT") != "1":
                try:
                    out_dir = os.path.join(os.getcwd(), "reports")
                    os.makedirs(out_dir, exist_ok=True)
                    shared_hint_path = os.path.join(out_dir, f"hint_{current_challenge_code}.txt")
                    if os.path.exists(shared_hint_path):
                        with open(shared_hint_path, "r", encoding="utf-8") as hf:
                            shared_hint = (hf.read() or "").strip()
                        if shared_hint:
                            hint = shared_hint
                            hint_requested_for_this_target = True
                except Exception:
                    pass
            if hint != "" and hint_requested_for_this_target and not gethint:
                gethint = True
                user_input = _replace_hint_line(user_input, hint)
            
            # Read shared key info at the start of a stage (step == 0) or every 10 rounds
            should_read_info = False
            if current_challenge_code and os.environ.get("CRUISER_DISABLE_HINT") != "1":
                if step == 0:
                    # Read once at the start of the stage
                    should_read_info = True
                elif step > 0 and step % 10 == 0:
                    # Read once every 10 rounds
                    should_read_info = True
            
            if should_read_info:
                cached_shared_info = _read_shared_info(current_challenge_code)
                last_info_read_step = step
                if cached_shared_info:
                    try:
                        print(f"[SharedInfo] Loaded shared key info (round {step})", flush=True)
                    except Exception:
                        pass
            
            if total_steps_for_target == 100:
                break
            
            # Build the user input, including shared key info (from the cache)
            user_content = f"{user_input}\n\n"
            if cached_shared_info:
                user_content += cached_shared_info + "\n"
            user_content += f"Scratchpad so far:\n{scratchpad}\n\n"
            user_content += "Please output JSON."
            
            msgs = [
                SystemMessage(content=instruction),
                HumanMessage(content=user_content),
            ]
            _print_llm_input( msgs, label="decision")
            try:
                ai: AIMessage = llm.invoke(msgs)  # type: ignore
            except Exception as e:  # noqa: BLE001
                if _is_context_limit_error(e):
                    # Context limit reached: start a new session (reset scratchpad and counters)
                    if not quiet:
                        try:
                            print("[Session] Context limit reached, starting a new session.")
                        except Exception:
                            pass
                    scratchpad = ""
                    step = 0
                    # Optional: re-create the LLM instance to avoid any lingering session state
                    try:
                        llm, _, _ = get_llm()
                    except Exception:
                        pass
                    continue
                # Other errors: print and try the next round
                if not quiet or os.environ.get("CRUISER_DEBUG") == "1":
                    try:
                        print(f"[Error] LLM call failed: {e}")
                    except Exception:
                        pass
                continue

            # Only after a successful LLM call do we increment the step and total counters and print COUNT
            step += 1
            total_steps_for_target += 1
            try:
                print(f"[COUNT] {total_steps_for_target}", flush=True)
            except Exception:
                pass

            text = ai.content if isinstance(ai.content, str) else json.dumps(ai.content)

            # Extract JSON
            try:
                start = text.find("{")
                end = text.rfind("}")
                obj = json.loads(text[start : end + 1])
            except Exception:
                # Could not parse; keep looping to enforce JSON
                scratchpad += "Step %d\nThought: Model output was not JSON; keep requiring strict JSON output.\n\n" % step
                continue

            thought = obj.get("thought", "")
            tool = obj.get("tool", "none")
            args = obj.get("args", {}) or {}
            scratchpad += f"Step {step}\nThought: {thought}\n"

            if tool == "none":
                final = obj.get("final")
                if isinstance(final, str) and final:
                    # If final is JSON containing a flag, capture it and handle it per policy (do not return immediately)
                    try:
                        fs, fe = final.find("{"), final.rfind("}")
                        if fs != -1 and fe != -1:
                            fobj = json.loads(final[fs : fe + 1])
                            flag_val = fobj.get(flag_key)
                            if isinstance(flag_val, str) and flag_val.strip():
                                flag_json = final[fs : fe + 1]
                                if flag_confirmed:
                                    try:
                                        print(f"\x1b[95;1m[FOUND FLAG] {flag_json}\x1b[0m", flush=True)
                                    except Exception:
                                        pass
                                    # Flag submitted and confirmed: end the session immediately and return the result JSON
                                    return flag_json
                                else:
                                    # Not yet confirmed by a successful submit_flag; continue
                                    scratchpad += "Action: none\nObservation: A flag field was detected but has not been confirmed by a successful submit_flag; continuing.\n\n"
                                    continue
                    except Exception:
                        pass
                # No valid flag provided; continue
                scratchpad += "Action: none\nObservation: Attempted to stop early without a valid flag; continuing the scan.\n\n"
                # Even with a step limit set, we keep going after reaching it (unlimited), so do not force termination here
                continue

            fn = mapping.get(tool)
            if not fn:
                scratchpad += f"Action: INVALID_TOOL({tool})\nObservation: unknown tool\n\n"
                continue

            # Execute the action
            try:
                out = fn.invoke(args)
            except Exception as e:  # noqa: BLE001
                out = f"[ERROR] Tool execution failed: {e}"


            scratchpad += f"Action: {tool}({json.dumps(args, ensure_ascii=False)})\nObservation:\n{out}\n"
            # submit_flag confirmed success
            try:
                if tool == "submit_flag":
                    txt = str(out or "")
                    if ("FLAG CORRECT" in txt) or ("ALREADY SUBMITTED" in txt):
                        flag_confirmed = True
            except Exception:
                pass

            # Reflection and next-step suggestion
            try:
                reflect_prompt = REFLECT_PROMPT

                reflect_system = build_system_prompt() + ("\n\nRecent conversation (up to 10 turns):\n" + conv_ctx if conv_ctx else "")
                msgs_reflect = [
                    SystemMessage(content=reflect_system),
                    HumanMessage(
                        content=(
                            f"Question: {user_input}\n\n"
                            f"Scratchpad so far:\n{scratchpad}\n\n"
                            f"Observation (latest):\n{out}\n\n"
                            + reflect_prompt
                        )
                    ),
                ]
                _print_llm_input(msgs_reflect, label="reflection")
                rmsg: AIMessage = llm.invoke(msgs_reflect)  # type: ignore
                rtxt = rmsg.content if isinstance(rmsg.content, str) else json.dumps(rmsg.content)
                rs, re = rtxt.find("{"), rtxt.rfind("}")
                robj = json.loads(rtxt[rs: re + 1]) if rs != -1 and re != -1 else {}
                reflection = robj.get("reflection") or ""
                suggested = robj.get("suggested_next") or ""
                if reflection:
                    scratchpad += f"Reflection: {reflection}\n"
                    try:
                        print(f"[Reflection] {reflection}")
                    except Exception:
                        pass
                if suggested:
                    scratchpad += f"Suggested next: {suggested}\n"
                    try:
                        print(f"[Next] {suggested}")
                    except Exception:
                        pass
                
                # Record key info once every 6 rounds during the reflection phase
                if current_challenge_code and step > 0 and step % 6 == 0:
                    try:
                        # Extract key info from the observation and the reflection
                        combined_context = f"{thought}\n{out}\n{reflection}"
                        key_info = _extract_key_info(combined_context, thought, tool, llm)
                        if key_info:
                            info_text = key_info.get("info", "").strip()
                            if info_text:
                                _write_shared_info(
                                    current_challenge_code,
                                    worker_id,
                                    info_text
                                )
                                try:
                                    print(f"[KeyInfo] Found shared key info during reflection: {info_text[:50]}...", flush=True)
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception:
                scratchpad += "Reflection: (failed to generate)\n"

            scratchpad += "\n"

            # With a finite step limit, do not stop when it is reached; just note it and continue (satisfies "until a flag is found")
            if max_steps > 0 and step >= max_steps:
                scratchpad += f"[Info] Step limit {max_steps} reached; continuing the loop until a flag is found.\n\n"
                # Reset the counter but keep the scratchpad so we can continue
                step = 0


def run_auto_scan(target: str, max_steps: int = 0, quiet: bool = False, hint: Optional[str] = None, challenge_code: Optional[str] = None) -> str:
    """Run a non-interactive LLM-driven vulnerability scan against a target.

    The LLM is instructed to perform web vulnerability discovery and exploitation
    using available tools, and to stop with a strict one-line JSON: {"flag":"..."}
    or {"flag": null} when not found.
    """
    # Refresh the security tools overview once at startup
    try:
        _refresh_security_tools_overview()
    except Exception:
        pass

    llm, provider, supports_tools = get_llm()
    if llm is None:
        try:
            return json.dumps({"flag": None, "error": "LLM not available"}, ensure_ascii=False)
        except Exception:
            return '{"flag": null, "error": "LLM not available"}'

    worker_id = os.environ.get("CRUISER_WORKER_ID")
    worker_hint = WORKER_HINT_TEMPLATE.format(worker_id=worker_id) if worker_id else ""
    if hint:
        hint_line = f"Challenge hint: {hint}\n"
    else:
        hint_line = "Challenge hint: none\n"
    code_line = f"Challenge code: {challenge_code}\n" if challenge_code else ""
    ws_dir = os.environ.get("CRUISER_WORKSPACE_DIR")
    ws_line = f"Session workspace directory: {ws_dir}\n" if ws_dir else ""
    question = SCAN_QUESTION_TEMPLATE.format(
        target=target,
        worker_hint=worker_hint,
        code_line=code_line,
        ws_line=ws_line,
        hint_line=hint_line,
    )

    # Silence intermediate output in auto mode
    prev_quiet = os.environ.get("CRUISER_QUIET")
    if quiet:
        os.environ["CRUISER_QUIET"] = "1"
    try:
        # Keep scanning until the model outputs a valid JSON flag
        result_json = _react_until_flag(llm, question, flag_key="flag", max_steps=max_steps, quiet=quiet, challenge_code=challenge_code)
        return result_json
    finally:
        # Restore the environment
        if quiet:
            if prev_quiet is None:
                try:
                    del os.environ["CRUISER_QUIET"]
                except Exception:
                    pass
            else:
                os.environ["CRUISER_QUIET"] = prev_quiet


