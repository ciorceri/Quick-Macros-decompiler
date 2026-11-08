#!/usr/bin/env python3
"""Falsifiable layout test against real bytecode.

For every function block of every QM exe of the corpus (see qmcorpus.py),
each top-level stream entry e_i is decoded with qmlayout.Decoder using a
layout table; the decode must END exactly at the next entry e_{i+1}
("tiling"). Per top-level opcode this reports ok / bad / unresolved counts,
and with --samples N prints example spans (hex) so layouts can be derived or
corrected.

Layout table = qmlayout.T1 overlaid with analysis/layout_final.json (merge of
the group A-E override files; see docs/research-log.md)
(opcode(decimal string) -> token list: ints = fixed bytes incl. opcode byte,
"S" = nested table-1 instruction, "T2" = table-2 instruction, "BLOCK",
"FOR").

Usage:
    python tile_check.py [--corpus DIR] [--op 0xc9] [--samples 3]
        [--layout file.json]
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
from pathlib import Path
import struct
import sys

import qmcorpus
import qmdis
import qmlayout
import qmtool

ROOT = Path(__file__).resolve().parent


def load_funcs(
    corpus: str | Path | None = None,
) -> list[tuple[str, str, bytes, list[int]]]:
    """Loads every function block of every exe of the corpus.

    Args:
      corpus: Optional corpus directory or file (see qmcorpus.find_exes).

    Returns:
      List of (exe name, function name, code bytes, stream entries).
    """
    files = qmcorpus.find_exes(corpus)
    out = []
    for f in files:
        n = qmtool.parse_pe_resources_named(f.read_bytes())[252]
        r4 = n[4]
        names = [x.decode() for x in qmtool.qm_decrypt(n[3]).split(b"\0") if x]
        for rec, nm in zip(qmtool.parse_bytecode_index(n[2]), names):
            b = rec["block_off"]
            so, cnt = qmdis.locate_stream_from_header(r4, b)
            out.append(
                (
                    f.name,
                    nm,
                    r4[b + 0x48 : so],
                    list(struct.unpack_from("<%dH" % cnt, r4, so)),
                )
            )
    return out


def load_layout(path: str | Path | None = None) -> dict[int, list]:
    """Loads the layout table.

    Args:
      path: Optional layout JSON; default analysis/layout_final.json. Keys
        starting with "t2:" are stored into qmlayout.T2_EXTRA instead.

    Returns:
      qmlayout.T1 overlaid with the layout JSON (opcode -> token list).
    """
    lay = {k: list(v) for k, v in qmlayout.T1.items()}
    p = Path(path) if path else ROOT / "analysis" / "layout_final.json"
    if p.exists():
        for k, v in json.load(open(p)).items():
            if k.startswith("t2:"):  # groupC ext: table-2 layout
                qmlayout.T2_EXTRA[int(k[3:], 0)] = v
                continue
            lay[int(k, 0) if not k.isdigit() else int(k)] = v
    return lay


def run(
    funcs: list[tuple[str, str, bytes, list[int]]],
    layout: dict[int, list],
    want: int | None = None,
    samples: int = 0,
) -> tuple[dict[int, list[int]], dict[int, list[tuple[str, str, str, str]]]]:
    """Decodes every stream entry and checks that it tiles.

    Args:
      funcs: Output of load_funcs.
      layout: Layout table from load_layout.
      want: If not None, only collect examples for this opcode.
      samples: If non-zero, collect example spans.

    Returns:
      Tuple (stats, examples): stats maps opcode -> [ok, bad, unresolved];
      examples maps opcode -> list of (message, hex, exe, function).
    """
    st = collections.defaultdict(lambda: [0, 0, 0])
    ex = collections.defaultdict(list)
    for fname, nm, code, stream in funcs:
        for i, e in enumerate(stream):
            if e >= len(code):
                continue
            op = code[e]
            d = qmlayout.Decoder(code, layout)
            d.stream = stream
            try:
                end = d.instr(e, 1)
            except qmlayout.Unresolved as exc:
                st[op][2] += 1
                if samples and (want is None or op == want):
                    ex[op].append(
                        (
                            "ERR " + str(exc),
                            code[e : e + 24].hex(" "),
                            fname,
                            nm,
                        )
                    )
                continue
            if i + 1 < len(stream):
                ok = end == stream[i + 1]
                st[op][0 if ok else 1] += 1
                if samples and not ok and (want is None or op == want):
                    ex[op].append(
                        (
                            f"decoded {end - e} span {stream[i + 1] - e}",
                            code[e : stream[i + 1]].hex(" "),
                            fname,
                            nm,
                        )
                    )
    return st, ex


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--op", type=lambda x: int(x, 0))
    ap.add_argument("--samples", type=int, default=0)
    ap.add_argument("--layout")
    ap.add_argument(
        "--corpus",
        help="directory with QM exes (default ./corpus or $QM_CORPUS)",
    )
    a = ap.parse_args()
    funcs = load_funcs(a.corpus)
    if not funcs:
        sys.exit(1)
    lay = load_layout(a.layout)
    st, ex = run(funcs, lay, a.op, a.samples)
    tot = [sum(v[i] for v in st.values()) for i in range(3)]
    print("tiling ok/bad/unresolved:", tot)
    for op, v in sorted(st.items()):
        if a.op is not None and op != a.op:
            continue
        if v[1] + v[2] or a.op is not None:
            print(
                f"  0x{op:02x} ok={v[0]} bad={v[1]} unres={v[2]} "
                f"layout={lay.get(op)}"
            )
            for s in ex.get(op, [])[: a.samples]:
                print(
                    "      ", s[0], "|", s[1][:110], "|", s[2][:18], s[3][:14]
                )
