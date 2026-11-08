#!/usr/bin/env python3
"""Reconstructs the interpreter dispatch tables after startup filled them in.

The tables are rebuilt as they stand AFTER the runtime's startup code ran.

The PE image only contains the first ~86 handlers of each table; the startup
function (FUN_0040abc4 in QM 2.4.2) writes ~100 more entries
(`mov [table+4*k], imm32` / `mov [..], reg`) into the writable .data table
before any script runs. Reading only the static table (what earlier notes did)
makes control-flow opcodes such as 0xad (if) / 0xc9 (out) / 0xd0 (ret) look
like "phantoms" with handler VA 0.

Usage: python runtime_tables.py <exe> <table1_va> <table2_va> [--json out]
"""

from __future__ import annotations

import argparse
import json
import struct

from capstone.x86 import X86_OP_IMM
from capstone.x86 import X86_OP_MEM
from capstone.x86 import X86_OP_REG

import handler_layout as h


def build(
    exe: str,
    t1: int,
    t2: int,
) -> tuple[
    h.Image,
    dict[int, dict[int, tuple[str, int | None]]],
    list[tuple[int, int, int | None]],
]:
    """Builds the dispatch tables of an exe, including startup-written slots.

    Args:
      exe: Path of the QM exe (anything h.Image accepts).
      t1: Virtual address of dispatch table 1.
      t2: Virtual address of dispatch table 2.

    Returns:
      Tuple (image, tables, writes): the loaded image, a dict
      {1: {k: (kind, value)}, 2: {...}} and the list of
      (instruction address, slot VA, value) startup writes found.
    """
    img = h.Image(exe)
    tab = {1: {}, 2: {}}
    for k in range(256):
        for tn, base in ((1, t1), (2, t2)):
            v = img.u32(base + 4 * k)
            if v:
                tab[tn][k] = ("static", v)
    text = [s for s in img.pe.sections if s.Name.startswith(b".text")][0]
    start = img.base + text.VirtualAddress
    code = img.read(start, text.Misc_VirtualSize)
    lo, hi = t1, t2 + 0x400
    writes = []
    regs = {}
    cur = {}  # slot VA -> value (static + written)
    for tn, base in ((1, t1), (2, t2)):
        for k, (_, v) in tab[tn].items():
            cur[base + 4 * k] = v
    # find the writer function range: first/last instruction writing into tables
    ins = list(h.md.disasm(code, start))
    idxs = [
        n
        for n, i in enumerate(ins)
        if i.mnemonic == "mov"
        and len(i.operands) == 2
        and i.operands[0].type == X86_OP_MEM
        and not i.operands[0].mem.base
        and not i.operands[0].mem.index
        and lo <= (i.operands[0].mem.disp & 0xFFFFFFFF) < hi
    ]
    a, b = idxs[0], idxs[-1]
    # walk a window around it (the init function), tracking reg constants
    for n in range(max(0, a - 400), b + 5):
        i = ins[n]
        ops = i.operands
        if i.mnemonic == "mov" and len(ops) == 2:
            if ops[0].type == X86_OP_REG:
                r = i.reg_name(ops[0].reg)
                if ops[1].type == X86_OP_IMM:
                    regs[r] = ops[1].imm & 0xFFFFFFFF
                elif ops[1].type == X86_OP_REG:
                    regs[r] = regs.get(i.reg_name(ops[1].reg))
                elif (
                    ops[1].type == X86_OP_MEM
                    and not ops[1].mem.base
                    and not ops[1].mem.index
                    and lo <= (ops[1].mem.disp & 0xFFFFFFFF) < hi
                ):
                    regs[r] = cur.get(
                        ops[1].mem.disp & 0xFFFFFFFF
                    )  # alias of a slot
                else:
                    regs[r] = None
            elif (
                ops[0].type == X86_OP_MEM
                and not ops[0].mem.base
                and not ops[0].mem.index
            ):
                d = ops[0].mem.disp & 0xFFFFFFFF
                if lo <= d < hi:
                    if ops[1].type == X86_OP_IMM:
                        val = ops[1].imm & 0xFFFFFFFF
                    elif ops[1].type == X86_OP_REG:
                        val = regs.get(i.reg_name(ops[1].reg))
                    else:
                        val = None
                    writes.append((i.address, d, val))
                    cur[d] = val
        elif (
            i.mnemonic in ("xor",)
            and len(ops) == 2
            and ops[0].type == X86_OP_REG
            and ops[1].type == X86_OP_REG
            and ops[0].reg == ops[1].reg
        ):
            regs[i.reg_name(ops[0].reg)] = 0
        elif (
            ops
            and ops[0].type == X86_OP_REG
            and i.mnemonic not in ("cmp", "test", "push")
        ):
            regs[i.reg_name(ops[0].reg)] = None
        if i.mnemonic == "call":
            for r in ("eax", "ecx", "edx"):
                regs[r] = None
    for addr, d, val in writes:
        if t1 <= d < t1 + 0x400:
            tn, k = 1, (d - t1) // 4
        else:
            tn, k = 2, (d - t2) // 4
        if val == 0:
            tab[tn].pop(
                k, None
            )  # explicit zeroing (xor reg,reg ; mov [slot],reg)
        elif val:
            tab[tn][k] = ("init", val)
        else:
            tab[tn][k] = ("init?", None)
            print(f"  unresolved write 0x{addr:x} -> table{tn}[0x{k:02x}]")
    return img, tab, writes


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("t1", type=lambda x: int(x, 0))
    ap.add_argument("t2", type=lambda x: int(x, 0))
    ap.add_argument("--json")
    a = ap.parse_args()
    img, tab, w = build(a.exe, a.t1, a.t2)
    for tn in (1, 2):
        ks = sorted(tab[tn])
        stat = sum(1 for k in ks if tab[tn][k][0] == "static")
        init = sum(1 for k in ks if tab[tn][k][0] == "init")
        unk = sum(1 for k in ks if tab[tn][k][0] == "init?")
        print(
            f"table{tn}: entries={len(ks)} static={stat} "
            f"init-written={init} unresolved-writes={unk}"
        )
    if a.json:
        json.dump(
            {
                str(tn): {str(k): [v[0], v[1]] for k, v in tab[tn].items()}
                for tn in tab
            },
            open(a.json, "w"),
            indent=0,
        )
