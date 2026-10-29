#!/usr/bin/env python
"""PyGhidra headless decompiler (called by the Claude Code engine).

Usage:
    python tools/decompile.py <binary>              # list all functions and decompile main (if present)
    python tools/decompile.py <binary> <func_name>  # decompile every function whose name contains the string
    python tools/decompile.py <binary> --all        # decompile all functions (large output; redirect to a file and grep)
    Add --no-asm to print only pseudocode (by default disassembly and the data reference table are printed too)

Each function prints four sections: C pseudocode / Data references / Switch dispatch (when there is a jump table) / disassembly.
Switch dispatch reports the effect of each case and flags cases whose "loads were eliminated by the decompiler";
the operations of such opcodes were never compiled into the binary, which is direct evidence that "the opcode set is not fully recovered yet".
Data references flags addresses that are "read by this function but have no matching expression in the pseudocode" (marked "no"); this usually
means the related operations were eliminated by the compiler as dead code (the pseudocode is not trustworthy), or abstracted away by the decompiler (e.g. a switch jump table).
With custom VMs / bytecode obfuscation, such gaps are often the key clue; do not draw conclusions from the pseudocode alone.

Environment: GHIDRA_INSTALL_DIR / JAVA_HOME defaults are built into the script and can be overridden by environment variables of the same name.
"""
from __future__ import annotations

import os
import sys
import warnings

os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra_12.1.2_PUBLIC")
os.environ.setdefault("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64")

warnings.filterwarnings("ignore", category=DeprecationWarning)  # open_program's deprecation warning would clutter the output

import pyghidra  # noqa: E402

_PRINTABLE = range(0x20, 0x7F)


def _read_bytes(flat, addr, n: int):
    """Read n bytes; return None when unreadable (e.g. uninitialized .bss)."""
    try:
        return bytes(b & 0xFF for b in flat.getBytes(addr, n))
    except Exception:
        return None


def _hex_preview(data: bytes) -> str:
    text = "".join(chr(b) if b in _PRINTABLE else "." for b in data)
    return " ".join(f"{b:02x}" for b in data) + f"  |{text}|"


def _symbol_name(prog, addr):
    sym = prog.getSymbolTable().getPrimarySymbol(addr)
    return sym.getName() if sym is not None else None


def _data_refs(prog, func):
    """Data address referenced in the function body -> address of the first instruction referencing it."""
    refs = {}
    for instr in prog.getListing().getInstructions(func.getBody(), True):
        for ref in instr.getReferencesFrom():
            if ref.isStackReference() or ref.isExternalReference():
                continue
            if not ref.getReferenceType().isData():
                continue
            to = ref.getToAddress()
            if to is not None and prog.getMemory().contains(to):
                refs.setdefault(to, instr.getAddress())
    return refs


def _visible_in_c(c_text: str, prog, addr, data: bytes | None = None) -> bool:
    """Whether this data address left a trace in the pseudocode (symbol name, raw address, or as a string literal)."""
    low = c_text.lower()
    off = addr.getOffset()
    cands = [f"{off:x}", f"{off:08x}"]
    name = _symbol_name(prog, addr)
    if name:
        cands.append(name)
    if any(c.lower() in low for c in cands):
        return True
    if data:  # string constants are usually inlined as literals in pseudocode, so no symbol name appears
        s = data.split(b"\x00", 1)[0]
        if len(s) >= 4 and all(b in _PRINTABLE for b in s):
            return s.decode("ascii", "ignore") in c_text
    return False


def _print_data_refs(
    prog, flat, func, c_text: str, show_asm: bool = True, preview: int = 48, merge_gap: int = 4
) -> None:
    refs = _data_refs(prog, func)
    if not refs:
        return
    # Merge adjacent offsets (different indices of the same array) into one group to avoid DAT_x+1/+2 noise
    groups: list = []
    for addr in sorted(refs, key=lambda a: a.getOffset()):
        if groups and addr.getOffset() - groups[-1][0].getOffset() <= merge_gap:
            groups[-1][1].append(addr)
        else:
            groups.append((addr, []))

    print("// --- Data references (address / visible in pseudocode / content preview) ---")
    hidden = []
    for base, extras in groups:
        name = _symbol_name(prog, base) or "-"
        data = _read_bytes(flat, base, preview)
        if name.lower().startswith("switchdata"):
            status = "jump table (switch abstracted)"
        elif _visible_in_c(c_text, prog, base, data):
            status = "yes"
        else:
            status = "no  <=="
            hidden.append(base)
        tail = f"   (plus adjacent refs {', '.join(str(a) for a in extras)})" if extras else ""
        print(f"//   {base}  {name:<22}visible:{status:<22}referenced from {refs[base]}{tail}")
        print(f"//       {_hex_preview(data) if data else '(unreadable/uninitialized)'}")
    if hidden:
        print("// [WARN] Data marked \"no\" is read by this function, but the pseudocode has no matching expression. Common causes:")
        print("//   (a) the related operations were eliminated by the compiler as dead code; the pseudocode is then untrustworthy, and the real")
        print("//       transform can only be inferred from the data contents + bytecode/control-flow structure, and no decompiler can recover it;")
        print("//   (b) it was abstracted away by the decompiler (e.g. a switch jump-table base), which is normal.")
        where = "the disassembly below" if show_asm else "the disassembly (rerun without --no-asm to see it)"
        print(f"//   If (a) is suspected, do not conclude this data is unused; check {where} to see which operations it takes part in.")


_BRANCHY = {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN", "CALL", "CALLIND", "CALLOTHER"}


def _reads_stack(instr, sp) -> bool:
    """Whether this instruction's memory read is stack-pointer based. Register save/restore such as PUSH/POP is compiler bookkeeping,
    for which the decompiler never generates a LOAD anyway; it must be excluded, or the function epilogue is flagged wholesale."""
    if sp is None:
        return False
    ops = list(instr.getPcode())
    defs = {}
    for op in ops:
        out = op.getOutput()
        if out is not None:
            defs[str(out)] = op

    def touches_sp(vn, depth: int = 0) -> bool:
        if vn is None or depth > 6:
            return False
        if vn.isRegister() and vn.getAddress() == sp.getAddress():
            return True
        d = defs.get(str(vn))
        return bool(d) and any(touches_sp(i, depth + 1) for i in d.getInputs())

    return any(op.getMnemonic() == "LOAD" and touches_sp(op.getInput(1)) for op in ops)


def _load_dropped(instr, hf, sp) -> bool:
    """The raw pcode has a LOAD but the decompiler-simplified one does not, meaning this load was eliminated as dead code."""
    if _reads_stack(instr, sp):
        return False
    if not any(op.getMnemonic() == "LOAD" for op in instr.getPcode()):
        return False
    return not any(op.getMnemonic() == "LOAD" for op in hf.getPcodeOps(instr.getAddress()))


def _switch_cases(prog, func, hf):
    """{case entry address: [case values dispatched to it]}; returns {} when there is no switch."""
    cases: dict = {}
    try:  # prefer the jump table recovered by the decompiler, which gives the case values (e.g. 0xc1)
        for jt in hf.getJumpTables():
            values = list(jt.getLabelValues() or [])
            for i, a in enumerate(list(jt.getCases() or [])):
                cases.setdefault(a, []).append(values[i] if i < len(values) else None)
    except Exception:
        cases = {}
    if not cases:  # fallback path: take the flow-reference targets of the computed jump directly
        for instr in prog.getListing().getInstructions(func.getBody(), True):
            ft = instr.getFlowType()
            if ft.isJump() and ft.isComputed():
                for ref in instr.getReferencesFrom():
                    if ref.getReferenceType().isFlow():
                        cases.setdefault(ref.getToAddress(), [])
    return cases


def _case_region(prog, start, stops):
    """Take instructions sequentially from the case entry; stop at a merge point / another case entry / an unconditional transfer."""
    listing = prog.getListing()
    region = []
    instr = listing.getInstructionAt(start)
    while instr is not None:
        addr = instr.getAddress()
        if region and (addr in stops or sum(
            1 for r in prog.getReferenceManager().getReferencesTo(addr)
            if r.getReferenceType().isFlow()
        ) >= 2):
            break
        region.append(instr)
        ft = instr.getFlowType()
        if ft.isTerminal() or (ft.isJump() and not ft.isConditional()):
            break
        instr = listing.getInstructionAfter(addr)
    return region


def _dispatch_info(prog, func):
    """Return (computed jump instruction, [conditional branches before dispatch]). The latter usually include the bounds check (default path)
    and special-case values intercepted before the table lookup; both keep some opcodes out of the case list."""
    listing = prog.getListing()
    jumps = [i for i in listing.getInstructions(func.getBody(), True)
             if i.getFlowType().isJump() and i.getFlowType().isComputed()]
    if not jumps:
        return None, []
    jmp = jumps[0]
    guards = []
    instr = listing.getInstructionBefore(jmp.getAddress())
    for _ in range(12):
        if instr is None:
            break
        ft = instr.getFlowType()
        if ft.isJump() and ft.isConditional():
            tgts = ",".join(str(r.getToAddress()) for r in instr.getReferencesFrom()
                            if r.getReferenceType().isFlow())
            guards.append(f"{instr.getAddress()}  {instr}" + (f"   -> {tgts}" if tgts else ""))
        # Stop backtracking upon reaching a basic-block entry (this address is jumped to from elsewhere)
        if any(r.getReferenceType().isFlow()
               for r in prog.getReferenceManager().getReferencesTo(instr.getAddress())):
            break
        instr = listing.getInstructionBefore(instr.getAddress())
    return jmp, guards


def _print_switch_cases(prog, func, hf) -> None:
    cases = _switch_cases(prog, func, hf)
    if not cases:
        return
    sp = None
    try:
        sp = prog.getCompilerSpec().getStackPointer()
    except Exception:
        pass
    stops = set(cases)
    print("// --- switch/jump-table dispatch (common shape of custom VM interpreters) ---")
    lost, quiet = [], []
    for target in sorted(cases, key=lambda a: a.getOffset()):
        region = _case_region(prog, target, stops)
        calls, writes, dropped, effects = [], [], [], 0
        for instr in region:
            addr = instr.getAddress()
            ft = instr.getFlowType()
            if ft.isCall():
                calls.append(str(addr))
            for ref in instr.getReferencesFrom():
                if ref.getReferenceType().isWrite():
                    writes.append(str(addr))
            if _load_dropped(instr, hf, sp):
                dropped.append(f"{addr}  {instr}")
            # Count only non-control-transfer instructions: the COPYs attached to jump instructions are artifacts of SSA
            # register merging at join points, not real operations; counting them would make the "no live operations" check below never hold.
            if not (ft.isJump() or ft.isTerminal() or ft.isCall()):
                effects += sum(1 for op in hf.getPcodeOps(addr)
                               if op.getMnemonic() not in _BRANCHY)
        vals = [v for v in cases[target] if v is not None]
        label = ("case " + "/".join(f"0x{int(v):x}" for v in vals)) if vals else "case(value unknown)"
        print(f"//   {label} -> {target}  [{len(region)} instructions]  "
              f"calls:{','.join(calls) or '-'}  memory writes:{','.join(writes) or '-'}  "
              f"live operations in pseudocode:{effects}")
        for d in dropped:
            print(f"//       eliminated load: {d}")
        if dropped:
            lost.append((label, target))
        elif not calls and not writes and effects == 0:
            quiet.append((label, target))
    if lost:
        print("// [WARN] The loads of the cases listed above were eliminated by the decompiler; their real semantics cannot be obtained from the pseudocode:")
        for label, t in lost:
            print(f"//     {label} -> {t}")
        print("//   The operations of such opcodes were never compiled into the binary, and no decompiler can recover them;")
        print("//   infer them from the data contents and bytecode structure, then enumerate a small space of candidate semantics with a printability check.")
    if quiet:
        print("// [NOTE] The cases below have no calls, no memory writes and no live operations in the pseudocode; they may be real NOPs,")
        print("//   or their semantics may not be reflected in the code. Confirm each one before concluding \"the opcode set is fully recovered\":")
        for label, t in quiet:
            print(f"//     {label} -> {t}")
    covered = sorted({int(v) for vs in cases.values() for v in vs if v is not None})
    if covered:
        print("//   case values covered by the jump table: " + " ".join(f"0x{v:x}" for v in covered))
    jmp, guards = _dispatch_info(prog, func)
    if jmp is not None:
        print(f"//   dispatch point: {jmp.getAddress()}  {jmp}")
    for g in guards:
        print(f"//   conditional branch before dispatch: {g}")
    if covered and guards:
        print("//   [NOTE] The conditional branches above intercept some values before the table lookup, so an opcode that \"appears in the bytecode but is not among the covered values\""
              " takes the default path;")
        print("//     it does not appear in the case list and its semantics are likewise unconfirmed; compare every value the bytecode uses against the covered values one by one.")


def _print_disasm(prog, func) -> None:
    print("// --- Disassembly (addresses match the pseudocode above, to check whether the pseudocode dropped operations) ---")
    for instr in prog.getListing().getInstructions(func.getBody(), True):
        print(f"//   {instr.getAddress()}  {instr}")


def main() -> int:
    argv = [a for a in sys.argv[1:] if a != "--no-asm"]
    show_asm = "--no-asm" not in sys.argv
    if not argv:
        print(__doc__)
        return 2
    binary = argv[0]
    func_filter = argv[1] if len(argv) > 1 else None
    if not os.path.exists(binary):
        print(f"[ERROR] File not found: {binary}")
        return 1

    pyghidra.start()
    from ghidra.app.decompiler import DecompInterface

    with pyghidra.open_program(binary, analyze=True) as flat:
        prog = flat.getCurrentProgram()
        decomp = DecompInterface()
        try:
            decomp.openProgram(prog)
            fm = prog.getFunctionManager()
            functions = [f for f in fm.getFunctions(True) if not f.isExternal() and not f.isThunk()]

            if func_filter is None:
                # Default mode: function list + decompile main
                print(f"// {len(functions)} functions in total (non-library):")
                for f in functions:
                    print(f"//   {f.getName()} @ {f.getEntryPoint()}")
                targets = [f for f in functions if f.getName() == "main"]
            elif func_filter == "--all":
                targets = functions
            else:
                targets = [f for f in functions if func_filter in f.getName()]
                if not targets:
                    print(f"[WARN] No function matches '{func_filter}', available functions:")
                    for f in functions:
                        print(f"//   {f.getName()} @ {f.getEntryPoint()}")
                    return 1

            for f in targets:
                res = decomp.decompileFunction(f, 60, None)
                if res and res.getDecompiledFunction():
                    c_text = res.getDecompiledFunction().getC()
                    print(f"\n// ===== {f.getName()} @ {f.getEntryPoint()} =====")
                    print(c_text)
                    _print_data_refs(prog, flat, f, c_text, show_asm)
                    hf = res.getHighFunction()
                    if hf is not None:
                        _print_switch_cases(prog, f, hf)
                    if show_asm:
                        _print_disasm(prog, f)
        finally:
            decomp.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
