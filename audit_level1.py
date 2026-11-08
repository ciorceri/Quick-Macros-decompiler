#!/usr/bin/env python3
"""Level-1 regression audit of qmtool.py and the documented container facts.

Re-validates qmtool.py and the documented container facts against every QM
exe of the corpus.

Usage:
  python audit_level1.py [--corpus DIR] [--write-baseline]
  (exit 0 = all checks pass)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

import pefile

import qmcorpus
import qmdis
import qmtool

ROOT = Path(__file__).resolve().parent
BASELINE = ROOT / "baseline.json"
_ap = argparse.ArgumentParser(description=__doc__)
_ap.add_argument(
    "--corpus",
    help=(
        "directory with QM exes (default ./corpus or $QM_CORPUS; "
        "QM_EXCLUDE=a,b skips names)"
    ),
)
_ap.add_argument(
    "--write-baseline",
    action="store_true",
    help=(
        "record the current tiling / end-of-region numbers in baseline.json "
        "(run once on a clean corpus)"
    ),
)
_args = _ap.parse_args()
files = qmcorpus.find_exes(_args.corpus)
if not files:
    sys.exit(1)

fails = 0
tables_seen = {}
gaps = {}  # opcode -> hits: valid handlers with NO documented semantics


def check(ok: object, msg: str) -> None:
    """Counts a failure and prints msg when ok is falsy.

    Args:
      ok: The condition that must be truthy.
      msg: Message printed when the condition is falsy.
    """
    global fails
    if not ok:
        fails += 1
        print("   FAIL:", msg)


for f in files:
    d = f.read_bytes()
    print("==", f.name)
    named = qmtool.parse_pe_resources_named(d)[252]
    check(set(named) >= {1, 2, 3, 4, 6}, f"resource names {sorted(named)}")
    # res8/res9 = per-exe 0x49 builtin-id table, res10 = hidden
    # global-variable declarations (opcode 0x20); all three are parsed with
    # exact framing below.
    check(
        set(named)
        <= {
            1,
            2,
            3,
            4,
            6,
            8,
            9,
            10,
            11,
        },  # 11 = embedded zip DLL (sample29 `zip`)
        f"unexpected names {sorted(named)}",
    )
    # positional view must agree with the named view
    check(
        list(named.values()) == qmtool.parse_pe_resources(d)[252],
        "positional/named views differ",
    )
    k = qmtool.check_runtime_key(d)
    check(k["matches_known"], "key not found: " + k["status"])
    # runtime key location must be one of the known per-build RVAs
    check(
        any(int(r, 16) in qmtool.KNOWN_KEY_RVAS for r in k["found_rvas"]),
        f"key RVAs {k['found_rvas']} not a known build layout",
    )
    # res8 / res9 / res10: exact framing, consistent indices (qmtool.parse_*)
    check((8 in named) == (9 in named), "res8 and res9 must come together")
    try:
        bt = qmtool.parse_builtin_tables(named)
        dlls, ids = bt["dlls"], bt["ids"]
        check(
            all(v["dll_index"] < len(dlls) for v in ids.values()),
            "res9 dll index outside res8",
        )
        check(
            all(v["name"].isprintable() and v["name"] for v in ids.values()),
            "res9 name not printable",
        )
        check(all(0 < i < 0x10000 for i in ids), "res9 id out of range")
        if 8 in named:
            check(
                len(dlls) == struct.unpack_from("<H", named[8])[0], "res8 count"
            )
        if 9 in named:
            check(
                len(ids) == struct.unpack_from("<H", named[9])[0], "res9 count"
            )
        if 10 in named:
            check(
                all(
                    v["type"] < 0x100
                    and (v["size"] in (0, 1, 2, 4, 8) or v["type"] == 0)
                    and (v["size"] != 0 or v["type"] != 0)
                    for v in bt["globals"].values()
                ),
                "res10 record {size,type,flags}: size 0 requires an object "
                "type",
            )
        tables_seen[f.name] = (len(dlls), len(ids), len(bt["globals"]))
    except (ValueError, IndexError) as e:
        check(False, f"res8/9/10 framing: {e}")
    # res1 count == res2 records == number of res3 names
    cnt = struct.unpack_from("<H", named[1])[0]
    recs = qmtool.parse_bytecode_index(named[2])
    r3 = qmtool.qm_decrypt(named[3])
    starts = [0] + [
        i + 1 for i, b in enumerate(r3) if b == 0 and i + 1 < len(r3)
    ]
    check(cnt == len(recs), f"res1 count {cnt} != res2 records {len(recs)}")
    check(
        [r["name_off"] for r in recs] == starts[: len(recs)],
        "res2 name_off != res3 name starts",
    )
    check(
        all(r["block_off"] < len(named[4]) for r in recs),
        "block_off outside res4",
    )
    # decrypted res3 must start with printable name text
    check(
        all(32 <= b < 127 for b in r3[: max(0, r3.index(0))]),
        "res3 first name not printable",
    )
    # import table: FindResourceW/LockResource addresses via pefile
    pe = pefile.PE(data=d)
    imp = {
        i.name.decode(): i.address
        for e in pe.DIRECTORY_ENTRY_IMPORT
        for i in e.imports
        if i.name
    }
    check(
        "FindResourceW" in imp and "LockResource" in imp,
        "resource imports missing",
    )
    # block-0 header must locate the instruction stream; the disassembler
    # must decode it with no undocumented opcodes (stream location is not
    # a heuristic scan any more)
    loc = qmdis.locate_stream_from_header(named[4], 0)
    check(loc is not None, "header stream locator failed")
    if loc:
        res = qmdis.disassemble(named[4], 0x48, loc[0], len(named[4]))
        check(
            res["stream_entries"] == loc[1],
            f"stream entries {res['stream_entries']} != header count {loc[1]}",
        )
        # Level 2 is NOT complete: ~99 runtime-registered opcodes (0x80-0xed)
        # have no documented semantics. Report them; do not hide them.
        gaps.update(res["undocumented"])
    # every function block (not just block 0) must decode with no gaps
    for item in qmdis.decode_all_functions(named[2], named[4]):
        check("error" not in item, f"fn{item['index']}: {item.get('error')}")
        if "result" in item:
            gaps.update(item["result"]["undocumented"])
    print(
        f"   ok  names={sorted(named)} recs={len(recs)} key={k['rva']} "
        f"FindResourceW=0x{imp['FindResourceW']:x}"
    )

import subprocess
import tempfile

# tool end-to-end: qmtool.py CLI must write the same payloads the in-process
# parser sees

with tempfile.TemporaryDirectory() as t:
    r = subprocess.run(
        [sys.executable, str(ROOT / "qmtool.py"), str(files[0]), "-o", t],
        capture_output=True,
        text=True,
    )
    check(r.returncode == 0, "qmtool run failed: " + r.stderr)
    _named0 = qmtool.parse_pe_resources_named(files[0].read_bytes())[252]
    got = sorted(p.name for p in Path(t).glob("res*.bin"))
    check(got == sorted(f"res{n}.bin" for n in _named0), f"output files {got}")
    for n, payload in _named0.items():
        check(
            (Path(t) / f"res{n}.bin").read_bytes() == payload,
            f"res{n}.bin differs from the in-process payload",
        )


# every 0x49 call in every exe must resolve in THAT exe's own res9 table
# (qmdec decompiles all)
import qmdec

_unres = 0
for f in files:
    for _nm, _rec, _lines, _st in qmdec.decompile(f):
        _unres += sum("is not in this exe's res9 table" in ln for ln in _lines)
check(
    _unres == 0, f"{_unres} opcode-0x49 ids missing from the exe's res9 table"
)
print(
    f"\nRES8/9/10: parsed for {len(tables_seen)} exes; "
    f"unresolved 0x49 ids: {_unres}"
)

import qmlayout as _ql
import tile_check

# ---- Level 2 layout model: falsifiable checks against real bytecode -------

_funcs = tile_check.load_funcs(_args.corpus)
_lay = tile_check.load_layout()
_st, _ = tile_check.run(_funcs, _lay)
_tot = [sum(v[i] for v in _st.values()) for i in range(3)]
print(
    "\nLAYOUT TILING (top-level stream entries end exactly at the next entry): "
    f"ok/bad/unresolved = {_tot}"
)
_base = (
    json.load(open(BASELINE))
    if BASELINE.exists() and not _args.write_baseline
    else None
)
if _base is None and not _args.write_baseline:
    print(
        f"NOTE: {BASELINE.name} not found - only the absolute checks "
        "(0 bad / 0 unresolved) apply. "
        "Run `python audit_level1.py --write-baseline` once on your corpus to "
        "enable the strict regression check."
    )
check(
    _tot[1] == 0 and _tot[2] == 0, f"tiling has bad/unresolved entries: {_tot}"
)
if _base:
    check(
        _tot[0] >= _base["tiling"][0] and len(files) >= _base["n_exes"],
        f"tiling regressed: {_tot} (baseline {_base['tiling']}, "
        f"{_base['n_exes']} exes; corpus now {len(files)} exes)",
    )
_ok_end = 0
for _f, _nm, _code, _stream in _funcs:
    _d = _ql.Decoder(_code, _lay)
    _d.stream = _stream
    _last = None
    try:
        for _e in _stream:
            _last = _d.instr(_e, 1)
        if 0 <= len(_code) - _last <= 3:
            _ok_end += 1
    except _ql.Unresolved:
        pass
print(
    "LAYOUT END-OF-REGION (last statement ends within alignment padding): "
    f"{_ok_end} of {len(_funcs)} functions"
)
check(
    _ok_end == len(_funcs),
    f"end-of-region: only {_ok_end} of {len(_funcs)} functions end in the "
    "alignment padding",
)
if _base:
    check(
        _ok_end >= _base["end_of_region"][0]
        and len(_funcs) >= _base["end_of_region"][1],
        f"end-of-region regressed: {_ok_end} of {len(_funcs)} "
        f"(baseline {_base['end_of_region']})",
    )
if _args.write_baseline:
    if fails:
        print("not writing baseline: there are failures")
    else:
        json.dump(
            {
                "_doc": (
                    "regenerate with `python audit_level1.py "
                    "--write-baseline` on YOUR corpus; "
                    "tiling = [ok, bad, unresolved] over all top-level stream "
                    "entries; "
                    "end_of_region = [functions whose last statement ends in "
                    "padding, total functions]"
                ),
                "n_exes": len(files),
                "tiling": _tot,
                "end_of_region": [_ok_end, len(_funcs)],
            },
            open(BASELINE, "w"),
            indent=1,
        )
        print(
            f"wrote {BASELINE} (tiling {_tot}, "
            f"end-of-region {_ok_end}/{len(_funcs)}, {len(files)} exes)"
        )

import json as _json

_sem = _json.load(
    open(ROOT / "analysis" / "opcode_semantics.json", encoding="utf-8")
)
_documented = {k[3:].lower() for k in _sem if k.startswith("T1:")}
gaps = {g for g in gaps if str(g).lower() not in _documented}

print(
    "\nLEVEL-2 GAP: valid runtime opcodes WITHOUT documented semantics seen in "
    f"real code: {len(gaps)} distinct -> {sorted(gaps)}"
)
print(
    "\nRESULT (Level 1 + container/stream checks):",
    "PASS" if not fails else f"{fails} FAILURE(S)",
)
sys.exit(1 if fails else 0)
