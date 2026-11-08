#!/usr/bin/env python3
"""Immediate-constant sweep over EVERY function block of a QM exe.

Replaces an earlier throw-away script that was driven by a
hand-supplied (and for some targets wrong) stream offset and covered block 0
only. Streams are located from each block's header (qmdis.locate_stream_from_
header); every statement-bounded gap is decoded with the documented opcode
lengths and every non-zero push_* immediate is reported.

Usage: python threshold_sweep.py <exe | extraction-dir> [--all-values]
"""

from __future__ import annotations

from pathlib import Path
import struct
import sys

import qmdis
import qmtool

FIXED = {  # fmt -> length (only fixed-length formats; others stop the walk)
    "call7": 7,
    "global3": 3,
    "for": 4,
    "type2_u16": 4,
    "imm_i32": 5,
    "imm_u32": 5,
    "imm_i8": 2,
    "imm_f64": 9,
    "imm_i64": 9,
    "frame_addr": 5,
    "local3": 3,
    "var_access": 4,
    "deref_sub": 2,
    "computed_var": 4,
    "addr_of_var": 2,
    "var_access_deref": 3,
}


def load(path: Path) -> tuple[bytes, bytes, bytes]:
    """Loads the res2, res3 and res4 resources.

    Args:
      path: An extraction directory (res2.bin, res3.bin, res4.bin) or an exe.

    Returns:
      Tuple (res2, res3, res4) of bytes.
    """
    if path.is_dir():
        return (
            (path / "res2.bin").read_bytes(),
            (path / "res3.bin").read_bytes(),
            (path / "res4.bin").read_bytes(),
        )
    named = qmtool.parse_pe_resources_named(path.read_bytes())[252]
    return named[2], named[3], named[4]


def main() -> None:
    """Prints non-trivial push immediates of every function block of an exe.

    Reads the target path (and optional --all-values) from sys.argv.
    """
    res2, res3, res4 = load(Path(sys.argv[1]))
    names = qmdis.decrypt_res3(res3)
    recs = qmdis.parse_res2_index(res2)
    starts = sorted(r["data_offset"] for r in recs) + [len(res4)]
    for rec in recs:
        b = rec["data_offset"]
        end = starts[starts.index(b) + 1]
        loc = qmdis.locate_stream_from_header(res4, b)
        if not loc:
            continue
        so, cnt = loc
        code = res4[b + 0x4C : so]
        ents = list(struct.unpack_from("<%dH" % cnt, res4, so))
        for i, st in enumerate(ents):
            nxt = ents[i + 1] if i + 1 < len(ents) else len(code)
            off = st
            while off < nxt and off < len(code):
                op = code[off]
                info = qmdis.DOCUMENTED_OPCODES.get(op)
                if qmdis.is_phantom(op) or info is None or info[1] not in FIXED:
                    off += 1
                    continue
                mn, fmt = info
                ln = FIXED[fmt]
                if off + ln > len(code):
                    break
                imm = None
                if fmt == "imm_i32":
                    imm = struct.unpack_from("<i", code, off + 1)[0]
                elif fmt == "imm_u32":
                    imm = struct.unpack_from("<I", code, off + 1)[0]
                elif fmt == "imm_i8":
                    imm = code[off + 1]
                elif fmt == "imm_f64":
                    imm = struct.unpack_from("<d", code, off + 1)[0]
                elif fmt == "imm_i64":
                    imm = struct.unpack_from("<q", code, off + 1)[0]
                if imm not in (None, 0) and (
                    abs(imm) > 3 or "--all-values" in sys.argv
                ):
                    print(
                        f"fn{rec['index']} {names[rec['index']][:22]:22s} "
                        f"stmt={i:3d} off=0x{off:04x} {mn:10s} imm={imm}  "
                        f"{code[off:off+ln].hex(' ')}"
                    )
                off += ln


if __name__ == "__main__":
    main()
