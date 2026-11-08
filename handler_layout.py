#!/usr/bin/env python3
"""handler_layout.py - derive each QM opcode's byte layout from its handler.

For every entry of a runtime's opcode dispatch table this tool walks the
handler's x86 code and abstractly tracks the interpreter's instruction pointer
(IP, a field of the VM context passed in ECX). It reports, per control-flow
path, the sequence of

    ADV n   IP advanced by n bytes (opcode byte itself counts)
    RD w@o  handler reads a w-byte value from code at IP-relative offset o
    SUB     a nested dispatch: the next instruction is evaluated here
            (its own length is whatever that sub-instruction's layout is)
    CALL f  call into a helper that was not inlined (IP effect unknown)

so that the *layout* of every opcode - how many immediate bytes follow it and
where the sub-expressions sit - comes from the runtime's own code instead of
from reading prose. Layouts are compared with qmdis.DOCUMENTED_OPCODES.

Usage:
    python handler_layout.py <exe> <table_va> [--count 86] [--json out.json]

Static, read-only. Handler bytes are read from the PE image (same initialized
bytes REA's read_bytes returns; spot-compared in research-log.md).
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import struct
import sys
from typing import Any

from capstone import Cs
from capstone import CS_ARCH_X86
from capstone import CS_MODE_32
from capstone.x86 import X86_OP_IMM
from capstone.x86 import X86_OP_MEM
from capstone.x86 import X86_OP_REG
import pefile

MAXPATHS = 24
MAXINSNS = 220
_FN_CACHE = {}
_RUN_CACHE = {}


class Image:
    """A PE image providing byte reads by virtual address."""

    def __init__(self, path: str) -> None:
        """Loads a PE file and records its image base and raw bytes.

        Args:
          path: Path of the PE file to open.
        """
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = open(path, "rb").read()

    def read(self, va: int, n: int) -> bytes:
        """Reads n bytes at virtual address va.

        Args:
          va: Virtual address to read from.
          n: Number of bytes requested.

        Returns:
          The bytes found at that address in the file image.
        """
        off = self.pe.get_offset_from_rva(va - self.base)
        return self.data[off : off + n]

    def u32(self, va: int) -> int:
        """Reads a little-endian u32 at va.

        Args:
          va: Virtual address to read from.

        Returns:
          The unsigned 32-bit value.
        """
        return struct.unpack("<I", self.read(va, 4))[0]


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True


def disasm(img: Image, va: int, n: int = 1200) -> list[Any]:
    """Disassembles n bytes of img at va.

    Args:
      img: The image to read from.
      va: Virtual address of the first byte.
      n: Number of bytes to disassemble.

    Returns:
      The capstone instructions decoded from those bytes.
    """
    return list(md.disasm(img.read(va, n), va))


class Fn:
    """Decoded instructions of one function (by address), recursive descent."""

    def __init__(self, img: Image, va: int) -> None:
        """Decodes the function reachable from va into self.ins.

        Follows fall-through and nearby direct jumps (within 0x2000 bytes of
        va), stopping at ret/int3/jmp or after 4000 instructions.

        Args:
          img: The image to read from.
          va: Virtual address of the function entry.
        """
        self.ins = {}
        todo = [va]
        while todo and len(self.ins) < 4000:
            a = todo.pop()
            while a not in self.ins:
                try:
                    i = next(md.disasm(img.read(a, 16), a))
                except StopIteration:
                    break
                self.ins[a] = i
                m = i.mnemonic
                if m.startswith("j"):
                    if i.operands and i.operands[0].type == X86_OP_IMM:
                        t = i.operands[0].imm
                        if abs(t - va) < 0x2000:
                            todo.append(t)
                    if m == "jmp":
                        break
                if m in ("ret", "int3"):
                    break
                a += i.size


def find_ip_offsets(img: Image, handlers: list[int]) -> list[tuple[int, int]]:
    """IP field = most common `inc dword [r+K]`; returns (IP, CODE).

    Args:
      img: The image to read from.
      handlers: Virtual addresses of the opcode handlers to scan.

    Returns:
      Up to three (displacement, count) pairs, most common first.
    """
    c = Counter()
    for va in handlers:
        for i in Fn(img, va).ins.values():
            if i.mnemonic == "inc" and i.operands[0].type == X86_OP_MEM:
                c[i.operands[0].mem.disp] += 1
    return c.most_common(3)


# ---------------------------------------------------------------- abstract run
def reg_name(i: Any, op: Any) -> str:
    """Returns the register name of operand op.

    Args:
      i: The capstone instruction owning the operand.
      op: A register operand of i.

    Returns:
      The register name.
    """
    return i.reg_name(op.reg)


def run(
    img: Image,
    va: int,
    ipoff: int,
    codeoff: int,
    table: tuple[int, ...],
    inline_depth: int = 1,
    entry_ctx: str = "ecx",
) -> list[list[str]]:
    """Return list of paths; each path is a list of event strings.

    Results are cached per (img, va, ipoff, inline_depth).

    Args:
      img: The image to read from.
      va: Virtual address of the handler.
      ipoff: Context offset of the interpreter's IP field.
      codeoff: Context offset of the code-base pointer.
      table: Dispatch table address(es) of the runtime.
      inline_depth: How many levels of called helpers to inline.
      entry_ctx: Register holding the VM context on entry.

    Returns:
      One list of event strings (ADV, RD, SUB, CALL, ...) per explored path.
    """
    key = (id(img), va, ipoff, depth_key := inline_depth)
    if key in _RUN_CACHE:
        return _RUN_CACHE[key]
    if (id(img), va) not in _FN_CACHE:
        _FN_CACHE[(id(img), va)] = Fn(img, va)
    fn = _FN_CACHE[(id(img), va)]
    results = []
    _RUN_CACHE[key] = results

    def mem_parts(i: Any, op: Any) -> tuple[list[tuple[Any, ...]], int]:
        """Splits a memory operand into its components.

        Args:
          i: The capstone instruction owning the operand.
          op: A memory operand of i.

        Returns:
          A list of ("b", base) / ("i", index, scale) parts and the
          displacement.
        """
        m = op.mem
        parts = []
        if m.base:
            parts.append(("b", i.reg_name(m.base)))
        if m.index:
            parts.append(("i", i.reg_name(m.index), m.scale))
        return parts, m.disp

    def explore(
        addr: int,
        st: dict[str, Any],
        ev: list[str],
        seen: frozenset[int],
        depth: int,
    ) -> None:
        """Explores the handler paths from addr.

        Appends each finished path's event list to the enclosing results.

        Args:
          addr: Address of the next instruction to interpret.
          st: Abstract state with keys regs, ctx and ip.
          ev: Events recorded so far on this path.
          seen: Addresses already visited on this path.
          depth: Current inlining depth.
        """
        regs, ctxregs, ipd = st["regs"], st["ctx"], st["ip"]
        steps = 0
        while True:
            steps += 1
            if steps > MAXINSNS or len(results) > MAXPATHS:
                return
            i = fn.ins.get(addr)
            if i is None:
                ev.append("?code")
                results.append(ev)
                return
            if addr in seen:
                ev.append("LOOP")
                results.append(ev)
                return
            seen = seen | {addr}
            m, ops = i.mnemonic, i.operands
            nxt = addr + i.size

            def val(op: Any) -> tuple[Any, ...]:
                """Returns the abstract value of operand op."""
                if op.type == X86_OP_REG:
                    return regs.get(i.reg_name(op.reg), ("u",))
                if op.type == X86_OP_IMM:
                    return ("c", op.imm)
                return ("u",)

            def setreg(op: Any, v: tuple[Any, ...]) -> None:
                """Assigns abstract value v to register operand op."""
                if op.type == X86_OP_REG:
                    regs[i.reg_name(op.reg)] = v

            def is_ipmem(op: Any) -> bool:
                """Tells whether op addresses the IP field."""
                return (
                    op.type == X86_OP_MEM
                    and op.mem.disp == ipoff
                    and op.mem.base
                    and i.reg_name(op.mem.base) in ctxregs
                    and not op.mem.index
                )

            def is_codeoff(op: Any) -> bool:
                """Tells whether op is an IP-relative code offset."""
                return (
                    op.type == X86_OP_MEM
                    and op.mem.disp == codeoff
                    and op.mem.base
                    and i.reg_name(op.mem.base) in ctxregs
                    and not op.mem.index
                )

            # ---- IP updates ----
            if m == "inc" and is_ipmem(ops[0]):
                ipd = (ipd[0] + 1, ipd[1])
                ev.append("ADV1")
            elif m == "add" and is_ipmem(ops[0]) and ops[1].type == X86_OP_IMM:
                ipd = (ipd[0] + ops[1].imm, ipd[1])
                ev.append(f"ADV{ops[1].imm}")
            elif m == "mov" and is_ipmem(ops[0]):
                v = val(ops[1])
                if v[0] == "ip":
                    delta = v[1][0] - ipd[0]
                    if delta:
                        ev.append(f"ADV{delta}")
                    ipd = v[1]
                else:
                    ev.append("IPSET?")
            elif m == "mov" and ops[0].type == X86_OP_REG and is_ipmem(ops[1]):
                regs[i.reg_name(ops[0].reg)] = ("ip", ipd)
            elif (
                m == "mov" and ops[0].type == X86_OP_REG and is_codeoff(ops[1])
            ):
                regs[i.reg_name(ops[0].reg)] = ("cb",)
            elif (
                m == "mov"
                and len(ops) == 2
                and ops[0].type == X86_OP_REG
                and ops[1].type == X86_OP_REG
            ):
                src = i.reg_name(ops[1].reg)
                regs[i.reg_name(ops[0].reg)] = regs.get(src, ("u",))
                if src in ctxregs:
                    ctxregs = ctxregs | {i.reg_name(ops[0].reg)}
            elif m == "lea" and ops[1].type == X86_OP_MEM:
                parts, disp = mem_parts(i, ops[1])
                base = [regs.get(p[1], ("u",)) for p in parts if p[0] == "b"]
                if len(parts) == 1 and base and base[0][0] == "ip":
                    setreg(
                        ops[0], ("ip", (base[0][1][0] + disp, base[0][1][1]))
                    )
                else:
                    setreg(ops[0], ("u",))
            elif (
                m in ("add", "sub")
                and ops[0].type == X86_OP_REG
                and ops[1].type == X86_OP_IMM
            ):
                v = val(ops[0])
                k = ops[1].imm if m == "add" else -ops[1].imm
                if v[0] == "ip":
                    setreg(ops[0], ("ip", (v[1][0] + k, v[1][1])))
                else:
                    setreg(ops[0], ("u",))
            elif m == "inc" and ops[0].type == X86_OP_REG:
                v = val(ops[0])
                setreg(
                    ops[0],
                    ("ip", (v[1][0] + 1, v[1][1])) if v[0] == "ip" else ("u",),
                )
            elif (
                m == "add"
                and ops[0].type == X86_OP_REG
                and ops[1].type == X86_OP_REG
            ):
                a, b = val(ops[0]), val(ops[1])
                if (a[0], b[0]) in (("ip", "cb"), ("cb", "ip")):
                    ipv = a if a[0] == "ip" else b
                    setreg(ops[0], ("ipabs", ipv[1]))
                else:
                    setreg(ops[0], ("u",))
            elif (
                m in ("movzx", "mov", "movsx")
                and len(ops) == 2
                and ops[0].type == X86_OP_REG
                and ops[1].type == X86_OP_MEM
            ):
                parts, disp = mem_parts(i, ops[1])
                kinds = [regs.get(p[1], ("u",)) for p in parts if p[0] == "b"]
                idx = [regs.get(p[1], ("u",)) for p in parts if p[0] == "i"]
                allv = kinds + idx
                ipv = [v for v in allv if v[0] in ("ip", "ipabs")]
                hascb = any(v[0] == "cb" for v in allv)
                w = ops[1].size
                if ipv and (hascb or ipv[0][0] == "ipabs"):
                    off = ipv[0][1][0] + disp
                    ev.append(
                        f"RD{w}@{off}"
                        if not ipv[0][1][1]
                        else f"RD{w}@sub+{off}"
                    )
                    setreg(ops[0], ("code", w, off, len(ev) - 1))
                elif (
                    ops[1].mem.base
                    and i.reg_name(ops[1].mem.base) in ctxregs
                    and ops[1].mem.index == 0
                    and ops[1].mem.disp == ipoff
                ):
                    regs[i.reg_name(ops[0].reg)] = ("ip", ipd)
                else:
                    # table load: mov eax,[reg*4+TABLE]
                    if idx and ops[1].mem.disp == table[0]:
                        ci = regs.get(i.reg_name(ops[1].mem.index), ("u",))
                        setreg(
                            ops[0], ("fn", ci[3] if ci[0] == "code" else None)
                        )
                    else:
                        setreg(ops[0], ("u",))
            elif m == "call":
                tgt = ops[0]
                if tgt.type == X86_OP_MEM and tgt.mem.disp in table:
                    ci = (
                        regs.get(i.reg_name(tgt.mem.index), ("u",))
                        if tgt.mem.index
                        else ("u",)
                    )
                    if ci[0] == "code" and ci[3] < len(ev):
                        ev[ci[3]] = ""
                    ipd = (ipd[0], ipd[1] + 1)
                    ev.append("SUB")
                elif (
                    tgt.type == X86_OP_REG
                    and regs.get(i.reg_name(tgt.reg), ("u",))[0] == "fn"
                ):
                    fi = regs[i.reg_name(tgt.reg)][1]
                    if fi is not None and fi < len(ev):
                        ev[fi] = ""
                    ipd = (ipd[0], ipd[1] + 1)
                    ev.append("SUB")
                elif (
                    tgt.type == X86_OP_IMM
                    and "ecx" in ctxregs
                    or (tgt.type == X86_OP_IMM and depth < inline_depth)
                ):
                    # helper taking ctx in ECX (or pushed): inline when possible
                    sub = inline(tgt.imm, ctxregs, ipd, depth)
                    if sub is None:
                        ev.append(f"CALL{tgt.imm:x}")
                    else:
                        for e in sub[0]:
                            ev.append(e)
                        ipd = (ipd[0] + sub[1][0], ipd[1] + sub[1][1])
                else:
                    ev.append("CALL?")
                for r in ("eax", "ecx", "edx"):
                    regs[r] = ("u",)
                # ctx pointer survives in esi/ebx/edi by convention
                ctxregs = (
                    ctxregs - {"ecx", "eax", "edx"}
                    if ctxregs - {"ecx"}
                    else ctxregs
                )
            elif m == "ret":
                ev.append(f"END[ip+{ipd[0]}{'+sub'*ipd[1] if ipd[1] else ''}]")
                results.append(ev)
                return
            elif m == "jmp":
                if ops[0].type == X86_OP_IMM:
                    addr = ops[0].imm
                    continue
                ev.append("JMP?")
                results.append(ev)
                return
            elif m.startswith("j") and ops and ops[0].type == X86_OP_IMM:
                # fork: taken / not taken
                st2 = {"regs": dict(regs), "ctx": set(ctxregs), "ip": ipd}
                explore(ops[0].imm, st2, list(ev) + [f"<{m}>"], seen, depth)
                ev.append(f"<!{m}>")
            elif (
                ops
                and ops[0].type == X86_OP_REG
                and m not in ("cmp", "test", "push", "pop")
            ):
                setreg(ops[0], ("u",))
            addr = nxt

    def inline(
        target: int, ctxregs: set[str], ipd: tuple[int, int], depth: int
    ) -> tuple[list[str], tuple[int, int]] | None:
        # analyse helper: assume ctx in ECX
        """Explores an inlined call target.

        Args:
          target: Address of the called helper.
          ctxregs: Registers currently holding the VM context.
          ipd: Current abstract IP delta.
          depth: Current inlining depth.

        Returns:
          The helper's events and an (advance, sub-instruction count) pair,
          or None when it cannot be inlined or its paths disagree.
        """
        sub_results = (
            run(img, target, ipoff, codeoff, table, inline_depth, "ecx")
            if depth < inline_depth
            else None
        )
        if not sub_results:
            return None
        # use the first complete path; fall back if it disagrees
        sigs = {
            tuple(e for e in p if not e.startswith("END")) for p in sub_results
        }
        if len(sigs) != 1:
            return None
        p = sub_results[0]
        adv = 0
        subs = 0
        evs = []
        for e in p:
            if e.startswith("ADV"):
                adv += int(e[3:])
            elif e == "SUB":
                subs += 1
            if not e.startswith("END") and not e.startswith("<"):
                evs.append(e)
        return evs, (adv, subs)

    explore(
        va,
        {"regs": {}, "ctx": {entry_ctx, "ecx"}, "ip": (0, 0)},
        [],
        frozenset(),
        0,
    )
    return results


def summarize(paths: list[list[str]]) -> list[str]:
    """Summarizes control-flow paths into layout strings.

    Args:
      paths: Event lists as returned by run().

    Returns:
      The distinct space-joined path signatures, in first-seen order.
    """
    sigs = []
    for p in paths:
        s = " ".join(e for e in p if e and not e.startswith("<"))
        if s not in sigs:
            sigs.append(s)
    return sigs


def main() -> None:
    """Runs the command line tool.

    Prints each opcode's handler layout signatures and optionally writes them
    as JSON.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("table", type=lambda x: int(x, 0))
    ap.add_argument("--count", type=int, default=86)
    ap.add_argument("--json")
    ap.add_argument(
        "--table-json", help="runtime_tables.py output: use the post-init table"
    )
    ap.add_argument("--only", help="comma list of hex opcodes")
    ap.add_argument(
        "--codeoff",
        type=lambda x: int(x, 0),
        default=0x10,
        help="ctx offset of the code-base pointer (2.4.2: 0x10, 2.4.12: 0x3c)",
    )
    a = ap.parse_args()
    img = Image(a.exe)
    if a.table_json:
        rt = json.load(open(a.table_json))["1"]
        tbl = [rt[str(k)][1] if str(k) in rt else 0 for k in range(256)]
        a.count = 256
    else:
        tbl = [img.u32(a.table + 4 * k) for k in range(a.count)]
    handlers = sorted(set(t for t in tbl if t))
    offs = find_ip_offsets(img, handlers)
    ipoff = offs[0][0]
    print("inc [reg+K] histogram:", [(hex(k), n) for k, n in offs])
    # code base field: the other frequently loaded ctx field
    codeoff = a.codeoff
    out = {}
    only = {int(x, 16) for x in a.only.split(",")} if a.only else None
    for op, h in enumerate(tbl):
        if only and op not in only:
            continue
        if not h:
            out[op] = {"handler": 0, "sigs": ["PHANTOM"]}
            continue
        try:
            paths = run(img, h, ipoff, codeoff, (a.table,))
            sigs = summarize(paths)
        except Exception as exc:  # keep going; report
            sigs = [f"ERR {exc!r}"]
        out[op] = {"handler": h, "sigs": sigs}
        print(f"0x{op:02x} @0x{h:x}")
        for s in sigs[:6]:
            print("     ", s)
        if len(sigs) > 6:
            print(f"      ... +{len(sigs) - 6} more")
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
