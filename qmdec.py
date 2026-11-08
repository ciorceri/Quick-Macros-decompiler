#!/usr/bin/env python3
"""qmdec.py - Level-3 decompiler for Quick Macros (QM 2.4.x) executables.

Input : a QM-built exe (PE resource type 252) or a directory holding extracted
        resN.bin files (names ending in res1/res2/res3/res4.bin).
Output: readable QM source per user function, covering ONLY the constructs whose
        semantics are validated (docs/research-log.md "Level 3 groundwork",
        analysis/opcode_semantics.json, label 'observed').

Hard rules (see agents/qm-code-writer.md):
  * nothing is invented: any opcode / layout / flag without validated semantics
    becomes an explicit `TODO(evidence ...)` marker (statement level), never a guess;
  * constructs whose semantics are only 'inferred' carry a `;;inferred` trailing comment;
  * local-variable NAMES are not stored in the exe -> neutral names `loc<i>`;
  * notes are emitted as `;;note` trailing comments, full comment lines start with `;`.

Model (all validated, see research-log.md): code base = block+0x48; the stream is
the list of top-level statements; jump operands are absolute STREAM INDICES of the
last skipped/enclosed statement; strings `1e <u32>` = pool base
(block+0x48+(ptr5-ptr0)) + u32; locals `1f <u16>` index the descriptor table at
header ptr2 (8-byte entries, count u16 at block+0x2a).

Usage:  python qmdec.py <exe|dir> [-o out.qml]
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

import qmdis
import qmlayout
import qmtool
import tile_check

ROOT = Path(__file__).resolve().parent


class Todo(Exception):
    """Statement/expression with no validated semantics (-> TODO(evidence))."""


# ----------------------------------------------------------------------------
# container loading
# ----------------------------------------------------------------------------

def _plain_names(raw: bytes) -> list[str]:
    def ok(b):
        parts = [x for x in b.split(b"\0") if x]
        return bool(parts) and all(all(32 <= c < 127 for c in p) for p in parts)
    if ok(raw):
        data = raw
    else:
        data = qmtool.qm_decrypt(raw)
    return [x.decode("latin-1") for x in data.split(b"\0") if x]


def load_container(path: Path):
    """-> (res2 records, names, res4)"""
    if path.is_dir():
        def find(n):
            c = sorted(path.glob(f"*res{n}.bin"))
            if not c:
                raise SystemExit(f"error: no *res{n}.bin in {path}")
            return c[0].read_bytes()
        r2, r3, r4 = find(2), find(3), find(4)
        named = {n: c[0].read_bytes() for n in (8, 9, 10)
                 if (c := sorted(path.glob(f"*res{n}.bin")))}
    else:
        named = qmtool.parse_pe_resources_named(path.read_bytes())[qmtool.QM_RESOURCE_TYPE]
        r2, r3, r4 = named[2], named[3], named[4]
    global LAST_TABLES, QM_BUILD
    QM_BUILD = "2.4.12"
    if not path.is_dir():
        try:
            import pefile
            if pefile.PE(str(path), fast_load=True).OPTIONAL_HEADER.AddressOfEntryPoint == 0x4d895:
                QM_BUILD = "2.4.2"       # entry point of the QM 2.4.2 runtime stub (QM 2.4.2 builds); all 2.4.12 exes: 0x51506
        except Exception:
            pass
    LAST_TABLES = qmtool.parse_builtin_tables(named)      # this exe's OWN 0x49 id table (res8/res9/res10)
    return qmtool.parse_bytecode_index(r2), _plain_names(r3), r4


# ----------------------------------------------------------------------------
# operator / type tables (labels from analysis/opcode_semantics.json)
# ----------------------------------------------------------------------------
# T2 operators: (text, observed?)
T2_OPS = {
    0x00: ("=", True), 0x01: ("+", True), 0x06: ("&", True),
    0x0c: (" and ", True), 0x0f: (">=", True),
    0x0e: (">", False), 0x10: ("<", False), 0x11: ("<=", False),
    0x07: ("|", False), 0x0a: (">>", False), 0x0b: ("<<", False),
    0x12: ("<>", False), 0x25: ("<>", False),
}
# T2 operators evidenced only by source correlation (samples/set2, same-position match of
# the .qml statement order): label -> why
T2_OPS.update({
    0x02: ("-", False), 0x03: ("*", False), 0x04: ("/", False), 0x05: ("%", False),
    0x09: ("^", False), 0x0d: (" or ", False),
    0x4c: ("=", True), 0x4e: ("!=", True),
    # double family (typed T2: op, type byte, S) - sample09
    0x39: ("=", False), 0x3a: ("+", False), 0x3b: ("-", False), 0x3c: ("*", False),
    0x3d: ("/", False), 0x47: (">", False), 0x48: (">=", False), 0x49: ("<", False),
    0x4a: ("<=", False), 0x4b: ("!=", False),
    # long family - sample13 (only the operators that occur)
    0x29: ("*", False), 0x2a: ("/", False), 0x2b: ("%", False), 0x31: ("<<", False),
    0x34: (">", False),
})
# GROUP L (sample30, one statement per operator, constants 1/2/3/2/1/255/1/7 match the bytes): long family
T2_OPS.update({0x27: ("+", False), 0x28: ("-", False), 0x2c: ("&", False), 0x2d: ("|", False),
               0x2f: ("^", False), 0x30: (">>", False)})
T2_OPS[0x08] = ("~", False)           # AND NOT: handler 0x40fb50 / 0x40fc40 (acc = lhs & ~rhs), help IDH_OPERATORS `~`; System.qml `flags~4`
T2_OPS[0x12] = ("!=", False)
T2_OPS[0x25] = ("!=", False)
T2_TYPED = set(range(0x39, 0x4c))                # op, type byte, S
LOCAL_TYPES_EXTRA = {3: "lpstr"}                # GROUP L: sample30 `lpstr ls="abc"` (descriptor type 3)
HANDLER_LABELS = {0x0e, 0x10, 0x11, 0x07, 0x0a, 0x0b, 0x08}
T2_WHY = "source correlation (samples/set2)"
LOCAL_TYPES = {0: "int", 1: "byte", 2: "word", 4: "str", 5: "double", 6: "long", 0x24: "Acc",
               0x14: "POINT", 0x15: "RECT", 0x9d: "IXml", 0x99: "IStringMap", 0x9a: "ICsv", 0x13: "VARIANT", 0xa3: "__Handle",
               0x9c: "IXmlNode", 0x0f: "BSTR", 0x09: "IDispatch"}    # 0x9c / 0x0f: GROUP M (sample33); 0x09 IDispatch: GROUP N (sample35 `IDispatch h=htm(..)`)
NEW_TYPES = {1, 2, 3, 5, 6, 0x14, 0x15, 0x9d, 0x99, 0x9a, 0x13, 0xa3, 0x9c, 0x0f, 0x09}   # type codes known only by source correlation
STRUCT_FIELDS = {0x14: ["x", "y"], 0x15: ["left", "top", "right", "bottom"]}
STORE_WANT = {0x24: 0, 0x26: 1, 0x27: 2, 0x28: 6, 0x29: 5, 0x34: 4}
RMW_OPS = {0x2a, 0x2c, 0x2d, 0x2e, 0x2f}
OPT_MASKS = {0x40000: "hidden", 0x40: "clip", 0x1000: "err", 0x4000: "waitmsg",
             0x8000: "waitcpu", 0x10000: "slowmouse"}
# QM-internal builtins whose implicit `0` argument is dropped in the spelling (source correlation, sample17)
WIN32_KNOWN = {"FindWindowA": ("$", "$"), "FindWindowExA": ("", "", "$", "$"), "MessageBeep": ("",), "GetCursorPos": ("POINT*",),
               "SetCursorPos": ("", ""), "Sleep": ("",), "GetForegroundWindow": (), "SetForegroundWindow": ("",), "IsWindow": ("",),
               "ShowWindow": ("", ""), "SendMessageA": ("", "", "", "")}
IMPLICIT_ZERO_ARG = {"CreateStringMap", "CreateCsv", "CreateXml"}
LAST_TABLES = {"dlls": [], "ids": {}, "globals": {}}
GLOBALS_USED = {}                        # res10 id -> record, filled while decoding (declaration header of the output)
GETOPT_NAMES = {2: "speed", 4: "itemname", 5: "nargs"}     # GROUP O: option byte of 0xaa, source-correlated in sample34 only
QM_BUILD = "2.4.12"
# class/COM type codes shift between builds (IXml 0x9d in 2.4.12, but `__Handle ph` is 0x9d in the 2.4.2 stdlib Softly
# and 163 in 2.4.12): only the 2.4.12 codes of sample17 are mapped, and for 2.4.2 only the System.qml-evidenced one.
LOCAL_TYPES_242 = {0: "int", 1: "byte", 2: "word", 4: "str", 5: "double", 6: "long", 0x24: "Acc",
                   0x14: "POINT", 0x15: "RECT", 0x9d: "__Handle", 0x13: "VARIANT"}
VARIANT_FIELDS = {(0x02, 0x00, 0): "vt"}      # member (type,flags) at offset 0 of a VARIANT local (System.qml `.vt`)
# GROUP M: COM interface methods keyed by (interface descriptor type, method id). The `class` word of 0x47 is a per-exe index of the
# interface (sample17: IXml 0, IStringMap 1, ICsv 2; sample33: IXml 0, IXmlNode 1, ICsv 2, IStringMap 3), so the descriptor type of the object is the key.
INTF_METHODS = {0x9d: {0x34: "FromString", 0x38: "ToString", 0x18: "RootElement"},
                0x9c: {0x80: "ChildCount"},
                0x9a: {0x14: "FromString", 0x18: "ToString", 0x38: "RowCount", 0x3c: "ColumnCount", 0x44: "Cell", 0x48: "Cell"},
                0x99: {0x14: "Add", 0x1c: "Get"}}
OBJ_METHODS = {(0, 0x34): "FromString", (0, 0x38): "ToString", (1, 0x14): "Add",
               (1, 0x1c): "Get", (2, 0x14): "FromString", (2, 0x38): "RowCount"}
# GROUP L: 0x37 selectors [sel n S*n] named from sample28 (one statement per selector, statement order == stream order)
STR_CNT = {0x3c: "addline", 0x12: "set", 0x04: "set", 0x16: "all", 0x17: "fix", 0x28: "unicode", 0x29: "ansi",
           0x2a: "escape", 0x2e: "timeformat", 0x30: "findreplace", 0x31: "replacerx", 0x14: "remove"}
STR_CMP = {0: "beg", 1: "begi", 2: "end", 3: "endi", 4: "mid", 5: "midi"}      # sel 0x34..0x39, flags byte == sel-0x34
STR_MODE = {(0x13, 0x69): "insert", (0x15, 0x72): "replace"}                   # sel + mode letter ('i' / 'r')
STR_METHODS0 = {0x0b: "ucase", 0x0a: "lcase", 0x07: "trim", 0x1c: "getclip", 0x1d: "setclip"}
KEY_MODS = {0x12: "A", 0x11: "C", 0x10: "S", 0x5b: "W"}
KEY_NAMED = {0x09: "T", 0x0d: "Y"}
ARR_ELEM = {0x00: "int", 0x04: "str", 0x24: "Acc", 0x06: "long", 0x14: "POINT", 0x15: "RECT"}   # 0x14/0x15 GROUP M (sample33 ARRAY(POINT))   # arr_elem tail type word
# opcodes whose semantics are 'observed' (statement-level accounting)
OBSERVED_STMT = {0x50, 0xae, 0xaf, 0xb0, 0xcb, 0xde, 0xea, 0xed, 0x9f, 0xc3, 0x37, 0x25, 0x24, 0x34, 0x2a, 0x30, 0x31, 0x52, 0xad, 0x98, 0x9c, 0xd1, 0xd0,
                 0x89, 0x86, 0xc9, 0x80, 0x8a, 0xa9, 0xb7, 0xc8, 0xda, 0xbc, 0xbd, 0xd3, 0xc0,
                 0x82, 0x9d, 0x01, 0x99, 0x9a, 0x85, 0xe3, 0x93, 0xb8, 0xc1, 0xd4,
                 0xab, 0xbe, 0x87, 0x8b, 0x95, 0xd2, 0xb6, 0x3d, 0xc3, 0xb9, 0xcc, 0xd5, 0xc2}
# wait-for kinds (opcode 0x31, byte after the timeout S): kind byte -> (name, observed?, takes S)
# (analysis/opcode_semantics.json T1:0x31 wait_for_kinds_sample23; 4 = WV from sample04)
# K (0x08) / M (0x0d) observed: confirmed by the sample27 order swap
WAIT_KINDS = {0x01: ("WA", True), 0x02: ("WC", True), 0x82: ("WD", True), 0x03: ("WP", False),
              0x12: ("V", True), 0x08: ("K", True), 0x0d: ("M", True), 0x0e: ("P", True),
              0x0a: ("ML", True), 0x0f: ("H", True), 0x81: ("-WA", True), 0x04: ("WV", True)}
# dedicated builtin-function opcodes (analysis/builtin_function_ids.json "dedicated_opcodes")
# plain-S-argument builtins: opcode -> (name, observed?)
# commands: opcode -> (name, observed?)
DEDICATED = {0x8c, 0xb4, 0x9b, 0xba, 0xa7, 0xa0, 0xa6, 0xa8, 0xa5, 0xa4, 0xc4, 0xc5, 0xe6,
             0xb2, 0xe2, 0xce, 0xcd, 0x96}
GROUP_N_FUNCS = {0x83, 0x84, 0x8d, 0xa1, 0xa2, 0xa3, 0xac, 0xb6, 0xdf}     # GROUP N (sample35)
MOUSE_CMDS = {0xb8: "lef", 0xd4: "rig", 0xc1: "mid", 0x93: "dou"}


# ----------------------------------------------------------------------------
# GROUP O: local / parameter names of embedded stdlib functions from System.qml (QM 2.4.12 source, STRICT alignment)
# ----------------------------------------------------------------------------
import os as _os
# OPTIONAL: path to your own QM installation's System.qml (env QM_SYSTEM_QML). Never shipped; without it
# stdlib parameter/local names simply stay neutral.
SYSTEM_QML = Path(_os.environ["QM_SYSTEM_QML"]) if _os.environ.get("QM_SYSTEM_QML") else Path("__no_system_qml__")
ROUNDTRIP = False                        # --roundtrip: every local declared WITHOUT initialiser at the function head in descriptor order (QM numbers descriptors in declaration order)
GUESS_NAMES = False                      # --guess-names: cosmetic names from type/usage, each marked /*guessed name*/
NAME_MARK = "/*name from System.qml (2.4.12 source, inferred)*/"
_SYSQ = {}


def _sysq_source(fname):
    """Source text of the System.qml item named like the exe function (`Name`, `Class.Method`, `<id>Name` = #sub section)
    or None. System.qml is an SQLite database (tables items/texts); opened read-only."""
    if "db" not in _SYSQ:
        _SYSQ["db"] = None
        try:
            import sqlite3
            if SYSTEM_QML.exists():
                _SYSQ["db"] = sqlite3.connect("file:" + str(SYSTEM_QML).replace("\\", "/") + "?mode=ro", uri=True)
        except Exception:
            _SYSQ["db"] = None
    db = _SYSQ["db"]
    if db is None:
        return None
    base = fname.split(">", 1)[1] if fname.startswith("<") else fname
    try:
        if not fname.startswith("<"):
            r = db.execute("select texts.text from items join texts on texts.id=items.id where items.name=?", (base,)).fetchall()
            if len(r) == 1:
                return r[0][0].replace("\r", "").split("\n#sub ")[0]
            return None
        found = []
        for (t,) in db.execute("select text from texts where text like ?", ("%#sub " + base + "%",)):
            t = t.replace("\r", "")
            m = re.search(r"^#sub " + re.escape(base) + r"[ \t]*\n", t, re.M)
            if m:
                found.append(t[m.end():].split("\n#sub ")[0])
        return found[0] if len(found) == 1 else None
    except Exception:
        return None


def _split_top(s):
    out, cur, d = [], "", 0
    for ch in s:
        if ch in "([":
            d += 1
        elif ch in ")]":
            d -= 1
        if ch in " \t" and d == 0:
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def system_names(fd):
    """-> {descriptor index: name} when the System.qml source of this function declares EXACTLY as many locals/parameters
    as the descriptor table has and every declared type (and pointer / by-reference flag) equals the descriptor in order;
    otherwise None (locals stay loc<i>). Parameters come from the `function ...` line, locals from declaration lines
    (`int a b`, `ARRAY(int) a a1`, `POINT p.x=1`), nested blocks included; comment lines (leading space) and `;;` comments
    are ignored. Undeclared implicit variables (`_s`, first-use ints) make the counts differ and the match is refused."""
    src = _sysq_source(fd.name)
    if src is None:
        return None
    tcodes = {v: k for k, v in fd.ltypes.items() if k in (0, 1, 2, 3, 4, 5, 6, 0x13, 0x0f, 0x14, 0x15, 0x24, 0x9d, 0xa3)}
    tcodes["lpstr"] = 3
    lines = src.split("\n")
    if lines and lines[0].strip() == "/":
        lines = lines[1:]
    sig = (lines[0] if lines else "").split(";;")[0].strip()
    rest = "\n".join(lines[1:])
    code = rest.split("\n\n\n", 1)[1] if "\n\n\n" in rest else rest
    names = []                                       # (name, type code or None for ARRAY, expected flag byte or None)
    toks = _split_top(sig)
    if toks and toks[0].startswith("function"):
        for t in toks[1:]:
            t = t.strip("[]")
            m = re.fullmatch(r"(`|[A-Za-z_]+['&*]|[A-Za-z_]+&)?([A-Za-z_][A-Za-z0-9_]*)", t)
            if not m:
                return None
            pre, nm = m.group(1), m.group(2)
            if pre is None:
                ty, fl = 0, 0
            elif pre == "`":
                ty, fl = 0x13, 0
            elif pre == "str&":
                ty, fl = 4, 4
            elif pre.endswith("'") and pre[:-1] in tcodes:
                ty, fl = tcodes[pre[:-1]], 0
            elif pre.endswith("*") and pre[:-1] in tcodes:
                ty, fl = tcodes[pre[:-1]], 1
            else:
                return None
            names.append((nm, ty, fl))
    elif toks:
        return None
    for ln in code.split("\n"):
        if ln.startswith(" ") or not ln.strip():
            continue
        ln = ln.split(";;")[0].strip()
        m = re.match(r"(ARRAY\([A-Za-z_]+\)|[A-Za-z_][A-Za-z0-9_]*)(\*?) +(.+)", ln)
        if not m:
            continue
        tn, star, tail = m.groups()
        if tn.startswith("ARRAY"):
            ty, fl = None, None
        elif tn in tcodes:
            ty, fl = tcodes[tn], (1 if star else 0)
        else:
            continue
        for t in _split_top(tail):
            mm = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", t)
            if not mm:
                break
            names.append((mm.group(1), ty if ty is not None else 0x0d, fl))
            if "=" in re.sub(r"\([^()]*\)", "", t) or "." in t[len(mm.group(1)):len(mm.group(1)) + 1]:
                break
    if len(names) != fd.nloc or len({n for n, _, _ in names}) != len(names):
        return None
    for i, (nm, ty, fl) in enumerate(names):
        d = fd.desc[i]
        if d[1] != ty or (fl is not None and d[2] != fl):
            return None
    return {i: nm for i, (nm, _, _) in enumerate(names)}


def guess_names(fd, lines):
    """--guess-names: cosmetic names from the descriptor type and usage; every guessed declaration line is marked."""
    by_type = {4: "s", 0x0d: "a", 0x14: "p", 0x15: "r", 0x13: "v", 0x0f: "b", 5: "d", 6: "n", 1: "b", 2: "w", 3: "s", 0x24: "a"}
    used, out = set(), {}
    text = "\n".join(l for l in lines if not l.lstrip().startswith("//"))
    for i in range(fd.nloc):
        if i in fd.thread:
            continue
        ty = fd.desc[i][1]
        if re.search(r"\bfor\(?\s*loc%d\b" % i, text):
            base = "i"
        elif re.search(r"\bloc%d=win\b" % i, text) or re.search(r"\bloc%d=win\(" % i, text):
            base = "hwnd"
        else:
            base = by_type.get(ty, "n" if ty == 0 else "v")
        nm, k = base, 1
        while nm in used:
            k += 1
            nm = f"{base}{k}"
        used.add(nm)
        out[i] = nm
    return out


def apply_names(lines, names, mark):
    """rename loc<i> -> names[i] in every line; the first CODE line that mentions a renamed local carries `mark`."""
    seen, out = set(), []
    for ln in lines:
        if ln.lstrip().startswith("//"):
            out.append(re.sub(r"\bloc(\d+)\b", lambda m: names.get(int(m.group(1)), m.group(0)), ln))
            continue
        hit = {int(x) for x in re.findall(r"\bloc(\d+)\b", ln)} & set(names)
        new = re.sub(r"\bloc(\d+)\b", lambda m: names.get(int(m.group(1)), m.group(0)), ln)
        if hit - seen:
            new += "  " + mark
        seen |= hit
        out.append(new)
    return out


class FuncDecoder:
    def __init__(self, name, rec, names, r4, lay):
        self.name, self.rec, self.names, self.r4 = name, rec, names, r4
        b = rec["block_off"]
        self.b = b
        self.ptrs = struct.unpack_from("<9I", r4, b)
        p = self.ptrs
        so, cnt = qmdis.locate_stream_from_header(r4, b)
        self.code = r4[b + 0x48:so]
        self.stream = list(struct.unpack_from("<%dH" % cnt, r4, so))
        self.pool = b + 0x48 + (p[5] - p[0])
        self.nloc = struct.unpack_from("<H", r4, b + 0x2a)[0]
        dt = b + 0x48 + (p[2] - p[0])
        self.desc = [struct.unpack_from("<IHBB", r4, dt + 8 * i) for i in range(self.nloc)]
        self.dec = qmlayout.Decoder(self.code, lay)
        self.dec.stream = self.stream
        self.ends = {}
        orig = self.dec.instr

        def rec_instr(pos, table, _orig=orig):
            e = _orig(pos, table)
            self.ends[(table, pos)] = e
            return e
        self.dec.instr = rec_instr          # instance-level recording (no edit of qmlayout)
        self.declared = set()
        self.hidden = set()
        self.thread = self.read_thread_table()      # descriptor idx -> thread-variable record (names ARE stored)
        self.thread_declared = set()
        self.skip_next = 0
        self.refs = []
        self.flag_inferred = False
        self.flag_todo = False
        self.notes = []
        self.cmts = []                     # observed annotations (e.g. dll of a res9 function)
        self.tables = LAST_TABLES
        self.stats = []                      # (idx, op, status, reason)
        self.arr_types = {}
        self.last3b_tail = None
        self.hoisted = []
        self.pending_lines = []
        self.post_lines = []                  # --roundtrip: bare declarations that must follow the statement just emitted
        self.unused = set()                   # --roundtrip: named locals never referenced by the code (declared but unused in the source)
        self.dll_kinds = {}
        self.stmt_decl = []                   # --roundtrip: locals declared by the statement being emitted (merged `int loc=..` form)
        self.pending = {}                     # --roundtrip: declaration lines (bare, no initialiser) waiting for flush_decls
        self.seen_explicit = set()            # every local index that appears as a named variable (filled by local())
        self.explicit_all = set()             # same, from the discarded first pass
        self.labels = {}
        self.ltypes = LOCAL_TYPES_242 if QM_BUILD == "2.4.2" else {**LOCAL_TYPES, **LOCAL_TYPES_EXTRA}

    # -- thread variables (`int- t_i`, `int-- t_k`): 12-byte records between header ptr8 and the string pool (ptr5) ----
    def read_thread_table(self):
        """Record {u32 name offset into the pool, u16 size, u8 b6, u8 b7, u16 descriptor index, u16 flags}
        (handler 0x40f260 via opcode 0x50: name = pool + [rec], size [rec+4], descriptor index [rec+8], flags [rec+0xa]:
        bit1 = `--` (per-function), bit0 = declared with an initialiser; observed sample34 t_i/t_j/t_k = flags 1/0/3).
        The 12-byte records between ptr8 and ptr5 also exist in other functions (stdlib Acc.*), where the first field is not
        an identifier; a record is accepted ONLY when its name field points to a plain identifier in the pool, its
        descriptor index is valid and that descriptor carries the by-reference flag byte 4."""
        p, b = self.ptrs, self.b
        o, e = b + 0x48 + (p[8] - p[0]), self.pool
        out = {}
        self.thread_recs = []
        if not (0 < e - o and (e - o) % 12 == 0):
            return out
        for k in range((e - o) // 12):
            no, size, b6, b7, didx, fl = struct.unpack_from("<IHBBHH", self.r4, o + 12 * k)
            rec = None
            try:
                a = self.pool + no
                z = self.r4.index(b"\0", a)
                nm = self.r4[a:z].decode("ascii")
                if (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", nm) and didx < self.nloc and self.desc[didx][2] == 4
                        and size and fl < 4):
                    rec = {"k": k, "name": nm, "size": size, "didx": didx, "flags": fl}
                    out[didx] = rec
            except (UnicodeDecodeError, ValueError):
                pass
            self.thread_recs.append(rec)
        return out

    # -- byte helpers --------------------------------------------------------
    def u16(self, o): return struct.unpack_from("<H", self.code, o)[0]
    def end(self, pos): return self.ends[(1, pos)]

    def inferred(self, txt, why="?"):
        """keep the text clean; the reason is attached to the statement line."""
        self.flag_inferred = True
        if why not in self.notes:
            self.notes.append(why)
        return txt

    def string_at(self, off):
        a = self.pool + off
        e = self.r4.index(b"\0", a)
        raw = self.r4[a:e]
        if b"\r\n" in raw or b"\t" in raw:
            raw2 = raw.replace(b"\r\n", b"[]").replace(b"\t", b"[9]")
            if all(0x20 <= c < 0x7f for c in raw2) and b'"' not in raw2:
                self.inferred("", "string escape []=CRLF / [9]=TAB from source correlation (sample11/21)")
                return raw2.decode("ascii")
        if any(0 < c < 0x20 and c not in (9, 10, 13) for c in raw):
            # GROUP L: other control characters (sample29 pool strings contain a BEL 0x07 where the .qml has `c:<BEL>.txt`):
            # rendered as [n] by analogy with [9] = TAB (sample21); the general decimal form is not separately evidenced
            raw2 = b"".join((b"[%d]" % c) if (0 < c < 0x20 and c not in (10, 13)) else bytes([c]) for c in raw)
            raw2 = raw2.replace(b"\r\n", b"[]")
            if all(0x20 <= c < 0x7f for c in raw2) and b'"' not in raw2:
                self.inferred("", "control character rendered as [n] by analogy with [9]=TAB (sample21); general decimal form not separately evidenced (sample29 BEL)")
                return raw2.decode("ascii")
        if b'"' in raw and all(0x20 <= c < 0x7f for c in raw) and b"''" not in raw and b"[" not in raw:
            # QM escape: two single quotes = a double quote (help IDP_CONSTANT); System.qml ShutDownProcess has a
            # message whose source spells win("" "class name") with doubled single quotes inside the string
            self.inferred("", "pool string with a double quote written as two single quotes (help IDP_CONSTANT escape; System.qml ShutDownProcess message)")
            return raw.decode("ascii").replace('"', "''")
        if not all(0x20 <= c < 0x7f for c in raw) or b'"' in raw:
            raise Todo(f"string constant @pool+{off} contains characters whose QM "
                       f"escape form has no evidence: {raw!r}")
        return raw.decode("ascii")

    def local(self, idx):
        if idx >= self.nloc:
            raise Todo(f"local index {idx} outside descriptor table ({self.nloc})")
        if idx in self.thread:
            return self.thread[idx]["name"]            # observed: name stored in the string pool (record of opcode 0x50)
        if idx not in self.hidden:
            self.refs.append(idx)
            self.seen_explicit.add(idx)
        return f"loc{idx}"

    # -- expressions ----------------------------------------------------------
    def ex(self, pos):
        c = self.code
        op = c[pos]
        if op == 0x1b:
            return str(c[pos + 1])
        if op == 0x19:
            v = struct.unpack_from("<i", c, pos + 1)[0]
            return hex(v) if v >= 0x10000 else str(v)
        if op == 0x1e:
            return '"' + self.string_at(struct.unpack_from("<I", c, pos + 1)[0]) + '"'
        if op == 0x1f:
            return self.local(self.u16(pos + 1))
        if op in (0x09, 0x0a):                       # ld_i32 / ld_u32 of address expr
            return self.ex(pos + 1)
        if op in (0x0b, 0x0c, 0x0d, 0x0e):           # typed loads byte/word/double/long
            self.inferred("", "typed load 0x0b byte/0x0c word/0x0d double/0x0e long by source correlation (sample09/13)")
            return self.ex(pos + 1)
        if op == 0x04:
            self.inferred("", "unary minus 0x04 by source correlation (sample08/09)")
            return "-" + self.ex(pos + 1)
        if op == 0x05:
            self.inferred("", "unary ~ 0x05 by source correlation (sample08)")
            return "~" + self.ex(pos + 1)
        if op == 0x0f:                               # GROUP L: pointer dereference (sample30 `*p`, `*dp`, `*lp`, `*sp`)
            self.inferred("", "pointer dereference `*p` proven only by single statements (sample30)")
            return "*" + self.ex(pos + 1)
        if op == 0x1d:                               # GROUP L: int64 constant (sample30 `1234567890123`, `5000000000`)
            return str(struct.unpack_from("<q", c, pos + 1)[0])
        if op == 0x1c:
            self.inferred("", "double constant 0x1c (8-byte IEEE) by source correlation")
            return repr(struct.unpack_from("<d", c, pos + 1)[0])
        if op == 0xda:
            return self.spe_text(pos)
        if op == 0x47:
            return self.obj_call(pos)
        if op == 0x12:                               # member + offset
            return self.member_ofs(pos)
        if op == 0x11:                               # address-of: `11 1f idx` = `&local` (sample26 `&a`, `&p`; sample30 `&i`)
            return "&" + self.ex(pos + 1)
        if op == 0x06:                               # not
            s = self.ex(pos + 1)
            return "!" + s
        if op == 0x03:
            return self.block(pos)
        if op == 0x13:                               # member  13 S t1 t2
            e = self.end(pos + 1)
            t1, t2 = c[e], c[e + 1]
            if (t1, t2) == (0x23, 0x40):
                return self.inferred(self.ex(pos + 1) + ".a", "member (type 0x23,flags 0x40) named .a from source correlation")
            if (t1, t2) == (0, 0) and c[pos + 1] == 0x1f and self.desc[self.u16(pos + 2)][1] in STRUCT_FIELDS:
                return self.inferred(self.ex(pos + 1) + "." + STRUCT_FIELDS[self.desc[self.u16(pos + 2)][1]][0],
                                     "struct member name from field order (sample12)")
            if c[pos + 1] == 0x1f and self.u16(pos + 2) < self.nloc:
                ty = self.desc[self.u16(pos + 2)][1]
                if ty == 0x13 and (t1, t2) in ((0x02, 0x00),):
                    return self.inferred(self.ex(pos + 1) + ".vt", "VARIANT member (word at offset 0) = .vt; source System.qml ShutDownProcess `sel hwndOrExename.vt`")
                if ty >= 0x100 and (t1, t2) == (0, 0):          # GROUP M: member at offset 0 of a user type (sample33 `ut.x1`)
                    return self.inferred(self.ex(pos + 1) + ".m0", "0x13 (type 0/0) on a user-type local = member at offset 0 (sample33 `out ut.x1+...`); member names are not stored in the exe")
                if ty == (0x9d if QM_BUILD == "2.4.2" else 0xa3) and (t1, t2) == (0, 0):
                    return self.inferred(self.ex(pos + 1), "member 0/0 of a __Handle local = the handle itself (source System.qml Softly `if ph` / `wait 5 H ph`)")
            raise Todo(f"member type 0x{t1:02x} flags 0x{t2:02x} has no validated member name")
        if op == 0x4b:                               # str_tmp u16 S
            self.hidden.add(self.u16(pos + 1))
            return self.inferred(self.ex(pos + 3), "str_tmp wrapper 0x4b")
        if op == 0x3a:
            a, bb = c[pos + 1], c[pos + 2]
            if (a, bb) == (10, 0):
                return self.inferred(self.ex(pos + 3) + ".len", "arr_op a=10,b=0 = .len (handler case unverified)")
            raise Todo(f"arr_op a={a} b={bb} not mapped")
        if op == 0x3b:                               # arr_elem S n idx*n type16
            e0 = self.end(pos + 1)
            n = c[e0]
            if n == 0:
                # append form `a[]` : [3b S 00 selbyte type16] (layout tiles; source System.qml Softly `a2[]=h`, sample02 Callback)
                t = self.u16(e0 + 2)
                if t not in ARR_ELEM:
                    raise Todo(f"arr_elem append form with element type word 0x{t:04x} not evidenced")
                self.note_arr(pos + 1, t)
                return self.inferred(self.ex(pos + 1) + "[]", "arr_elem n=0 = append `a[]` (bytes + System.qml Softly `a2[]=h`; the 0x24 type word agrees with ARRAY(Acc) in sample02 stdlib)")
            if n not in (1, 2):
                raise Todo(f"arr_elem with n={n} index args not evidenced")
            idxs, q = [], e0 + 1
            for _ in range(n):
                idxs.append(self.ex(q))
                q = self.end(q)
            self.note_arr(pos + 1, self.u16(q))
            self.last3b_tail = self.u16(q)
            return self.inferred(self.ex(pos + 1) + "[" + " ".join(idxs) + "]", "arr_elem 0x3b = [i] (thin handler evidence)")
        if op == 0x52:
            return self.call_method(pos)
        if op == 0x01:
            return self.call_user(pos)
        if op in DEDICATED:
            return self.dedicated(pos)
        if op in GROUP_N_FUNCS:
            return self.group_n(pos)
        if op == 0x9f:
            n = c[pos + 1]
            if n not in (2, 3, 4):
                raise Todo(f"find with n={n} args (n=2,3,4 evidenced: sample11/27)")
            parts, q = self._sargs(pos + 2, n)          # written order (sample27: find(s "o" 2), find(s "O" 0 1))
            return "find(" + " ".join(parts) + ")"
        if op == 0xcb:                               # GROUP L: ont (sample29 `ont w`, `a=ont(w)`: same bytes)
            if c[pos + 1] != 0x20:
                raise Todo(f"ont mode 0x{c[pos+1]:02x} as function not evidenced")
            return "ont(" + self.ex(pos + 2) + ")"
        if op in (0xbc, 0xbd, 0xd3):                 # min/max/res as functions (sample29 `a=min(w)`)
            want = {0xbc: 0x6e, 0xbd: 0x78, 0xd3: 0x73}[op]
            if c[pos + 1] != want:
                raise Todo(f"min/max/res mode byte 0x{c[pos+1]:02x} not evidenced")
            return {0xbc: "min(", 0xbd: "max(", 0xd3: "res("}[op] + self.ex(pos + 2) + ")"
        if op in (0xeb, 0xec):                       # xm / ym (handler 0x421ff0 shared; sample29 `xm(0 w)`, `ym(0 w)`)
            flag, n = c[pos + 1], c[pos + 2]
            if flag != (0 if op == 0xeb else 1) or not 1 <= n <= 3:
                raise Todo(f"xm/ym flag {flag} n {n} not evidenced")
            q, parts = pos + 3, []
            for k in range(n):
                if k == 1 and c[q] == 0x1b and c[q + 1] == 0:
                    parts.append("0"); q += 2
                else:
                    parts.append(self.ex(q)); q = self.end(q)
            # observed: handler 0x421ff0 stores the flag byte and returns y if non-zero else x (flag 0 = x, 1 = y); source order agrees
            return ("xm(" if op == 0xeb else "ym(") + " ".join(parts) + ")"
        if op == 0xd5:                               # run as function (sample29 `a=run("notepad.exe")`, same bytes as the statement)
            n = c[pos + 2]
            if c[pos + 1] != 0 or not 1 <= n <= 4:
                raise Todo("run form not evidenced (n 1..4 observed; 5..7 handler-only, see statement form)")
            parts, q = self._sargs(pos + 3, n)
            return "run(" + " ".join(parts) + ")"
        if op in (0xd6, 0xd7):                       # rget / rset (handlers 0x4221b2 / 0x422470; sample29)
            b1, b2 = c[pos + 1], c[pos + 2]
            if b2 != 0 or (b1 & 0xf0):
                raise Todo(f"rget/rset header 0x{b1:02x} 0x{b2:02x} not evidenced")
            n = b1 & 0xf
            parts, q = self._sargs(pos + 3, 2 + max(0, n - 2))
            # rget/rset identity: handler 0x4221b2 (rget) reads up to 6 slots (variable name key hive default datatype), handler 0x422470
            # (rset) up to 5 with `edi == -1 / -2` branches (delete value / delete subkey = help IDP_RGET `options`); coded order == written
            # order (sample29 `rget(v "name" "Software\QMTest")`: pool offsets name < key). Observed for n=3, handler-only for n>3.
            if n > 3:
                self.inferred("", "rget/rset with n>3 slots (hive/default/datatype/options): handlers 0x4221b2/0x422470 + help only, no sample")
            return ("rget(" if op == 0xd6 else "rset(") + " ".join(parts) + ")"
        if op == 0xb3:                               # inp (handler 0x42037b; sample29 `a=inp(v "text" "caption")`)
            fl, n = c[pos + 1], c[pos + 2]
            if fl != 0 or n != 3 or c[self.end(pos + 3)] != 0:
                raise Todo("inp form not evidenced (only flags 0, n=3, filler byte 0)")
            v = self.ex(pos + 3)
            q = self.end(pos + 3) + 1
            parts, q = self._sargs(q, 2)
            self.inferred("", "inp=0xb3: single occurrence (sample29); handler 0x42037b reads [flags][n] lvalue(var) [byte] then text, caption, default... in written order (help IDP_INP); the byte after the variable (0) is not interpreted")
            return "inp(" + " ".join([v] + parts) + ")"
        if op == 0xcf:
            if (c[pos + 1], c[pos + 2]) != (1, 3):
                raise Todo("qmitem form not evidenced")
            self.inferred("", "qmitem=0xcf: single occurrence (sample29); handler 0x4234b2: first byte = argument count (1 here), second byte = operand kind (3 here: string name; nonzero with value >= 0x10000 is looked up as a name pointer, else as an id)")
            return "qmitem(" + self.ex(pos + 3) + ")"
        if op == 0xc7:
            n = c[pos + 1]
            parts, q = self._sargs(pos + 2, n)
            self.inferred("", "net=0xc7: single occurrence (sample29); handler 0x42306a: [n] then computer, password, macro, [retval lvalue, 1b 00 = omitted] in written order (help IDP_NET)")
            return "net(" + " ".join(parts) + ")"
        if op == 0xe7:
            v = c[pos + 1]
            if v == 0:
                return "win"
            if v == 0x67:
                # k=7 + bit5 (propCSV form) + bit6: 6 arguments by handler 0x428895 (min(k,4)=4, propCSV 1, array 1);
                # source: System.qml Softly `win("" "" p.x 0 "" a)` (compiled in every exe that embeds ShutDownProcess)
                q, parts = pos + 2, []
                for _ in range(6):
                    parts.append(self.ex(q))
                    q = self.end(q)
                self.inferred("", "win with 6 args (v=0x67) by handler 0x428895 arg count + System.qml Softly source line (single occurrence)")
                return "win(" + " ".join(parts) + ")"
            if v & 0xe0 or (v & 0x1f) not in (1, 2):
                raise Todo(f"win form v=0x{v:02x} (only v=1 'win(title)', v=2 'win(title class)' and v=0x67 evidenced)")
            if v == 1:
                return "win(" + self.ex(pos + 2) + ")"
            return "win(" + self.ex(pos + 2) + " " + self.ex(self.end(pos + 2)) + ")"
        if op == 0xe8:
            # same handler as 0xe7 (0x42859a in 2.4.2 / 0x428895 in 2.4.12): bit7 = window handle operand first, then k args
            v = c[pos + 1]
            if not v & 0x80 or v & 0x60 or not 1 <= (v & 0x1f) <= 4:
                raise Todo(f"opcode 0xe8 form v=0x{v:02x}: only the hwnd + 1..4 args form (v=0x81..0x84) is derived from the handler")
            q, parts = pos + 2, []
            for _ in range(1 + (v & 0x1f)):
                parts.append(self.ex(q))
                q = self.end(q)
            self.chk(pos, q)
            return self.inferred("wintest(" + " ".join(parts) + ")",
                                 "0xe8 = wintest(hwnd name [class]...): shares win's handler, bit7 = hwnd operand (help IDP_WIN signature); "
                                 "source System.qml ShutDownProcess `WinTest(hwnd ...\"Ghost\")` (single occurrence, QM 2.4.2 builds only)")
        if op == 0x80:
            n = c[pos + 1]
            if n != 1:
                raise Todo(f"act as function with n={n} (only n=1 `act(window)` derived from handler 0x42809e / 0x427d92)")
            r = self.ex(pos + 2)
            self.chk(pos, self.end(pos + 2))
            return self.inferred("act(" + r + ")", "act as function returns the window handle (handler stores hwnd in ctx+0; help IDP_ACT); "
                                 "source form only in the QM 2.4.2 build samples (weak)")
        if op == 0xbb:
            b, n = c[pos + 1], c[pos + 2]
            if b != 0 or n < 1:
                raise Todo(f"mac as function with flag byte 0x{b:02x} / n={n} not evidenced")
            q = pos + 3
            if c[q] == 0x19:                             # first S = function id (handler evaluates it as an integer, 0x40adcc)
                fid = struct.unpack_from("<i", c, q + 1)[0]
                first = '"' + self.sub_name(fid) + '"'
                q = self.end(q)
            else:
                first = self.ex(q)
                q = self.end(q)
            args = [first]
            for _ in range(n - 1):
                args.append(self.ex(q))
                q = self.end(q)
            self.chk(pos, q)
            return self.inferred("mac(" + " ".join(args) + ")",
                                 "mac as function: first S = res2 function id of the named sub (handler 0x4230c6/0x42332f), "
                                 "source System.qml Softly caller `wait 0 H mac(\"sub.Softly\" \"\" &p)` (single occurrence)")
        if op in (0x14, 0x15):
            # member through a pointer slot: 0x15 = [op S t1 t2] (offset 0), 0x14 = [op S t1 t2 u16 ofs]  (handlers 0x412150 / 0x412bb0)
            e = self.end(pos + 1)
            t1, t2 = c[e], c[e + 1]
            ofs = self.u16(e + 2) if op == 0x14 else 0
            if (t1, t2) == (0, 0) and c[pos + 1] == 0x1f:
                ty = self.desc[self.u16(pos + 2)][1]
                if ty in STRUCT_FIELDS and ofs % 4 == 0 and ofs // 4 < len(STRUCT_FIELDS[ty]):
                    return self.inferred(self.ex(pos + 1) + "." + STRUCT_FIELDS[ty][ofs // 4],
                                         f"0x{op:02x} = member through a pointer parameter (POINT*p); field by offset order; "
                                         "source System.qml Softly `p.x` / `p.y`")
            if c[pos + 1] == 0x1f and self.desc[self.u16(pos + 2)][1] >= 0x100:      # GROUP L: pointer to user type (sample30 `tp.a`)
                return self.inferred(self.ex(pos + 1) + f".m{ofs}", f"0x{op:02x} = member through a pointer to a user-defined type (offset {ofs}); member names are not stored, neutral name m<offset> (sample30)")
            raise Todo(f"pointer member 0x{op:02x} type {t1:02x}/{t2:02x} ofs {ofs}: member name not evidenced")
        if op == 0x18:                               # GROUP L: element of an array member: [18 S(member) S(index) u16] (sample30 `t.c[1]=7`)
            base = self.ex(pos + 1)
            e1 = self.end(pos + 1)
            idx = self.ex(e1)
            # handler 0x4122a0 (2.4.12): [18] S(base address) S(index) u16: new address = base + index * u16 (element size in bytes; imul by the
            # trailing u16, here 1 = byte element); source `t.c[1]=7` (sample30). Observed (single occurrence): trailing u16 = element stride.
            return f"{base}[{idx}]"
        if op == 0x08:                               # GROUP M: int -> double conversion (handler 0x412850: dispatch S, fild qword, type tag 5)
            self.inferred("", "0x08 = implicit int->double conversion of the inner value (handler 0x412850; sample31 `function^ ... ret a/2`); not written in the source")
            return self.ex(pos + 1)
        if op == 0x38:                               # GROUP M: [38 a b] S  (handler 0x414e67; a=5 on a BSTR = SysStringLen)
            if c[pos + 1] == 5 and c[pos + 2] == 0 and c[pos + 3] in (0x1f, 0x21) and self.desc[self.u16(pos + 4)][1] == 0x0f:
                return self.inferred(self.ex(pos + 3) + ".len", "0x38 a=5 on a BSTR local = .len (handler 0x414e67 case 5 calls OLEAUT32!SysStringLen; sample33 `b.len`)")
            raise Todo(f"0x38 a={c[pos+1]} b={c[pos+2]}: only a=5 on BSTR evidenced")
        if op == 0x21 and self.u16(pos + 1) in self.thread:
            return self.local(self.u16(pos + 1))       # thread variable accessed through its by-reference slot
        if op == 0x20:                               # GROUP O: hidden global variable by res10 id (`int+ g`, `str+ g`)
            gid = self.u16(pos + 1)
            ent = self.tables["globals"].get(gid)
            if ent is None or ent["flags"] != 8 or (ent["size"], ent["type"]) not in ((4, 0), (0, 4)):
                raise Todo(f"opcode 0x20 id {gid}: res10 record {ent} is not an `int+`/`str+` global")
            GLOBALS_USED[gid] = ent
            return f"glob{gid}"
        if op == 0x16:                               # GROUP O: pointer indexing [16 S(pointer var) S(index) u16 stride] (sample34 p[0], pb[0], pw[0])
            base = self.ex(pos + 1)
            e1 = self.end(pos + 1)
            idx = self.ex(e1)
            stride = self.u16(self.end(e1))
            if stride not in (1, 2, 4):
                raise Todo(f"0x16 element stride {stride} not evidenced (1/2/4 = byte/word/int pointer)")
            return f"{base}[{idx}]"
        if op in (0x40, 0x42):                       # GROUP O: implicit VARIANT -> int / double conversion (handlers 0x413945 / 0x413be0; sample34)
            return self.ex(pos + 1)
        if op == 0x44:
            return "-" + self.ex(pos + 1)            # unary minus on VARIANT (handler 0x4136eb; sample34 `v=-v`)
        if op == 0x45:
            return "~" + self.ex(pos + 1)            # bitwise NOT on VARIANT (handler 0x413770; sample34 `v=~v`)
        if op == 0x46:
            return "!" + self.ex(pos + 1)            # logical NOT on VARIANT (handler 0x4137ab; sample34 `int nv=!v`)
        if op == 0x4e:                               # GROUP O: variable of the parent frame of a #sub (handler 0x412630; sample34 `#sub UseParent v` `pv`)
            return self.inferred(f"parent_loc{self.u16(pos + 1)}", "0x4e = variable of the PARENT frame by descriptor index of the parent function (handler 0x412630, "
                                 "sample34 `#sub UseParent v`); the parent's variable name is not stored: neutral name parent_loc<idx> = loc<idx> of the parent function")
        if op == 0x54:                               # GROUP O: address of a sub-function by res2 id `&sub.Foo` (handler 0x4126b0)
            return "&" + self.sub_name(self.u16(pos + 1))
        if op == 0x8e:                               # GROUP O: call(address [args]) (handler 0x42325d; sample34)
            n = c[pos + 1]
            fn = self.ex(pos + 2)
            q = self.end(pos + 2)
            args = []
            for _ in range(n):
                args.append(self.ex(q))
                q = self.end(q)
            return "call(" + " ".join([fn] + args) + ")"
        if op == 0xaa:                               # GROUP O: getopt(option [context]) (handler 0x422a21; sample34)
            n, opt = c[pos + 1], c[pos + 2]
            if n != 1 or opt not in GETOPT_NAMES:
                raise Todo(f"getopt n={n} option code {opt}: only the options of sample34 (n=1) are evidenced")
            return "getopt(" + GETOPT_NAMES[opt] + ")"
        if op == 0x21:
            return self.inferred(self.local(self.u16(pos + 1)), "0x21 = by-reference parameter slot (handler 0x412540 = 0x1f + one dereference), rendered as the variable")
        if op == 0x31:
            return self.wait_for(pos)
        if op == 0x49:
            return self.call_id(pos)
        if op == 0x37:
            return self.fstring(pos)
        raise Todo(f"expression opcode 0x{op:02x} has no validated semantics "
                   f"(raw {self.code[pos:self.end(pos)].hex(' ') if (1, pos) in self.ends else '?'})")

    def block(self, pos):
        c = self.code
        ln = self.u16(pos + 1)
        endb = pos + 1 + ln
        p = pos + 3
        s = self.ex(p)
        p = self.end(p)
        n = 0
        while p < endb:
            op = c[p]
            rhs = self.ex(p + 2 if op in T2_TYPED else p + 1)
            e2 = self.ends[(2, p)]
            if op in T2_OPS:
                txt, obs = T2_OPS[op]
                s = f"{s}{txt}{rhs}"                 # flat left-to-right operator list (no per-step parentheses: `a>b and (a<100)`)
                if not obs:
                    self.inferred("", f"table-2 operator 0x{op:02x} '{txt.strip()}' " +
                                  ("label from handler only" if op in HANDLER_LABELS else T2_WHY))
            else:
                s = f"op_0x{op:02x}({s} {rhs}) /*TODO(evidence): table-2 operator 0x{op:02x} no validated semantics*/"
                self.flag_todo = True
            p = e2
            n += 1
        if c[endb] in (5, 6) and c[endb + 1] == 0:
            self.inferred("", "block trailer type tag 5=double/6=long by source correlation (sample09/13)")
        elif c[endb] or c[endb + 1]:
            raise Todo(f"block trailer {c[endb]:02x}{c[endb+1]:02x} (type/flags) has no validated meaning")
        return f"({s})"

    def args_of(self, p, n):
        """arguments of 0x52 (ARGN): plain S, or 0x7c-prefixed (S + u16)."""
        out = []
        c = self.code
        for _ in range(n):
            b = c[p]
            if b < 0x7a:
                out.append(self.ex(p))
                p = self.end(p)
            elif b == 0x7c:
                out.append(self.inferred(self.ex(p + 1), "0x7c argument prefix"))
                p = self.end(p + 1) + 2
            else:
                raise Todo(f"argument prefix 0x{b:02x} has no validated semantics")
        return out, p

    def fname(self, fid):
        for r, nm in zip(self.names_recs, self.names):
            if r["id"] == fid:
                return nm
        raise Todo(f"function id {fid} not found in res2")

    def call_method(self, pos):
        c = self.code
        obj_end = self.end(pos + 1)
        n = c[obj_end]
        fid = self.u16(obj_end + 1)
        nm = self.fname(fid)
        meth = nm.split(".", 1)[1] if "." in nm else nm
        args, _ = self.args_of(obj_end + 3, n)
        obj = self.ex(pos + 1)
        return obj + "." + meth + ("(" + " ".join(args) + ")" if args else "")

    def call_id(self, pos):
        c = self.code
        argc = c[pos + 4]
        fid = self.u16(pos + 5)
        p = pos + 7
        args = []
        for _ in range(argc):
            args.append(self.ex(p))
            p = self.end(p)
        args.reverse()                               # last coded arg = first parameter
        ent = self.tables["ids"].get(fid)
        if ent is None:
            raise Todo(f"builtin id {fid} (opcode 0x49) is not in this exe's res9 table")
        nm = ent["name"]                             # observed: the exe's own res9 table (handler 0x4294d0)
        dll = ent.get("dll")
        if dll:                                      # DLL function: the declaration (`dll user32 #Name ...`,
            tag = f"dll: {dll}" + (", res9 flag 0x8000" if ent["flag"] else "")   # parameter types) is not stored
            if tag not in self.cmts:
                self.cmts.append(tag)
            if ROUNDTRIP:
                self.dll_decl(nm, dll, args)
        if nm == "ProcessNameToId":
            while len(args) > 1 and args[-1] == "0":      # trailing default (int const 0) parameters
                args.pop()
            if len(args) > 1:
                self.inferred("", "ProcessNameToId extra arguments in parameter order (last coded = first parameter)")
        elif nm in IMPLICIT_ZERO_ARG and args == ["0"]:
            self.inferred("", "implicit 0 argument of " + nm + " dropped (sample17 source correlation)")
            return nm
        return f"{nm}({' '.join(args)})" if args else nm

    def dll_decl(self, nm, dll, args):
        """--roundtrip: the exe stores only the res9 name + dll, not the `dll` declaration; QM needs it to compile the call.
        Parameter kinds are inferred from how THIS call codes its arguments: string constant -> `$`, `&local` of a known
        struct type -> `TYPE*`, double constant -> `^`, anything else -> plain int; return type `#` (int); parameter names
        p1.. are neutral. The declaration is hoisted to the function head and marked inferred."""
        kinds = []
        for k, a in enumerate(args):
            m = re.fullmatch(r"&loc(\d+)", a)
            if a.startswith('"'):
                kinds.append("$")
            elif m and int(m.group(1)) < self.nloc and self.desc[int(m.group(1))][1] in STRUCT_FIELDS:
                kinds.append(self.ltypes[self.desc[int(m.group(1))][1]] + "*")
            elif re.fullmatch(r"-?\d+\.\d+(e[+-]?\d+)?", a):
                kinds.append("^")
            elif re.fullmatch(r"-?(\d+|0x[0-9a-f]+)|&?loc\d+|[A-Za-z_]\w*", a):
                kinds.append("")                        # int (default type)
            else:
                kinds.append(None)
        kn = WIN32_KNOWN.get(nm)                    # well-known Win32 signature (MSDN): used when it fits the call (same count, no contradiction)
        src = "inferred from the call arguments (string constant -> $, &struct -> TYPE*, else int)"
        if kn is not None and len(kn) == len(kinds) and all(x is None or x == y or x == "" or (y == "$" and x == "") for x, y in zip(kinds, kn)):
            kinds, src = list(kn), "well-known Win32 signature"
        prev = self.dll_kinds.get(nm)
        if prev is not None:
            if prev != kinds and not any(x is None for x in kinds):
                self.hoisted.append(f"// TODO(evidence): conflicting argument kinds for dll function {nm}: {prev} vs {kinds}")
            return
        if any(x is None for x in kinds):
            self.hoisted.append(f"// TODO(evidence): parameter kinds of dll function {nm} cannot be inferred from the call arguments {args}")
            self.dll_kinds[nm] = kinds
            return
        self.dll_kinds[nm] = kinds
        params = " ".join(f"{t}p{k + 1}" for k, t in enumerate(kinds))
        self.hoisted.append(f"dll {dll} #{nm}" + (" " + params if params else "")
                            + "  /*inferred: the exe stores only the name and dll; return type `#` assumed; parameter kinds: " + src + "; parameter names are neutral*/")

    def sub_name(self, fid):
        nm = self.fname(fid)
        if nm.startswith("<") and ">" in nm:
            return "sub." + nm.split(">", 1)[1]
        return nm

    def call_user(self, pos, stmt=False):
        """0x01 argc u16(res2 function id) ARGN*argc  (opcode_semantics T1:0x01, observed)"""
        c = self.code
        argc = c[pos + 1]
        nm = self.sub_name(self.u16(pos + 2))
        args, q = self.args_of(pos + 4, argc)
        self.chk(pos, q)
        if argc > 1:       # arg loop of handler 0x429e70 (2.4.12) walks the callee's parameter table forward: code order = parameter order
            self.inferred("", f"call by id with argc={argc}: arguments in code order by the handler's forward parameter loop (source-observed only for argc 1)")
        if stmt:
            return nm + (" " + " ".join(args) if args else "")
        return nm + ("(" + " ".join(args) + ")" if args else "")

    def dedicated(self, pos):
        """builtin functions with a dedicated opcode (analysis/builtin_function_ids.json)"""
        c = self.code
        op = c[pos]
        names = {0x8c: "child", 0xb4: "id", 0x9b: "empty", 0xba: "len", 0xa7: "findb", 0xa0: "findc",
                 0xa6: "findl", 0xa8: "findrx", 0xa5: "findt", 0xa4: "findw", 0xc4: "matchw",
                 0xc5: "numlines", 0xe6: "val", 0xb2: "iif", 0xe2: "tok", 0xce: "perf",
                 0xcd: "pixel", 0x96: "dir"}
        nm = names[op]

        def S(q, k):
            out = []
            for _ in range(k):
                out.append(self.ex(q))
                q = self.end(q)
            return out, q

        def done(args, q, obs=True, why=""):
            self.chk(pos, q)
            if not obs:
                self.inferred("", why or f"builtin {nm} (opcode 0x{op:02x}): label/args by source order only")
            return nm + ("(" + " ".join(args) + ")" if args else "")

        if op == 0xce:
            return done([], pos + 1)
        if op == 0x8c:
            b = c[pos + 1]
            if b != 3:
                raise Todo(f"child with byte 0x{b:02x} (only 3 = class text parent evidenced)")
            a, q = S(pos + 2, 3)
            return done(a, q)
        if op == 0xb4:
            n = c[pos + 1]
            if n not in (2, 3):
                raise Todo(f"id with n={n}")
            a, q = S(pos + 2, n)
            return done(a, q)
        if op in (0x9b, 0xba):
            if c[pos + 1] != {0x9b: 0x65, 0xba: 0x6c}[op]:
                raise Todo(f"0x{op:02x} sub-byte 0x{c[pos+1]:02x} not evidenced")
            a, q = S(pos + 2, 1)
            return done(a, q)
        if op in (0xa7, 0xc4):
            n = c[pos + 1]
            if n != 2:
                raise Todo(f"{nm} with n={n} (only n=2 evidenced)")
            a, q = S(pos + 2, 2)
            return done(a, q)
        if op == 0xa0:
            fl = c[pos + 1]
            if fl != 4:
                raise Todo(f"findc flags 0x{fl:02x} (only 4 evidenced)")
            a, q = S(pos + 2, 2)
            return done(a, q)
        if op in (0xa6, 0xa5, 0x96):
            n = c[pos + 1]
            if (op == 0x96 and n != 1) or (op != 0x96 and n != 2):
                raise Todo(f"{nm} with n={n} not evidenced")
            a, q = S(pos + 4, n)
            return done(a, q, False, f"builtin {nm}: u16 operand 0x{self.u16(pos + 2):x} not rendered (meaning unknown)")
        if op == 0xa8:
            n = c[pos + 1]
            if n == 2:
                a, q = S(pos + 3, 2)
                return done(a, q, False, "builtin findrx (inferred label; option byte not rendered)")
            if 3 <= n <= 6 and c[pos + 2] == 0:
                # handler 0xa8 = 0x425790 (2.4.12; 2.4.2 0x4253c3): [a8][n][b] then n sub-expressions read in coded order =
                # string, pattern, [from (n>=3)], [flags (n>=4)], [result lvalue via 0x40ae1d (n>=5, skipped when b==7)], [submatch (n>=6)];
                # b = result type (4 str / 0xd ARRAY / <=7 scalar branch at 0x4258db); only b==0 (int result) is evidenced (2.4.2 sample, ref original-1 #40).
                # Order == help IDP_FINDRX `findrx(string pattern [from] [flags] [result] [submatch])`; no .qml source -> inferred.
                a, q = S(pos + 3, n)
                return done(a, q, False, "findrx n>=3: args in coded=written order by handler 0x425790 (from, flags, result, submatch) + help IDP_FINDRX; b=0 (int result); no .qml source")
            raise Todo(f"findrx n={n} / result-type byte 0x{c[pos+2]:02x} not evidenced")
        if op == 0xa4:
            n = c[pos + 1]
            if n != 1:
                raise Todo(f"findw with n={n} (only 1 evidenced)")
            a, q = S(pos + 2, 2)           # coded: word S, then the searched string
            return done([a[1], a[0]], q)
        if op == 0xc5:
            a, q = S(pos + 1, 1)
            return done(a, q)
        if op == 0xe6:
            if c[pos + 1] != 0:
                raise Todo(f"val sub-byte 0x{c[pos+1]:02x}")
            a, q = S(pos + 2, 1)
            return done(a, q, False, "builtin val (inferred label)")
        if op == 0xcd:
            n = c[pos + 1]
            if n != 2:
                raise Todo(f"pixel with n={n} (only 2 evidenced)")
            a, q = S(pos + 2, 2)
            return done(a, q)
        if op == 0xe2:
            ntok = c[pos + 1]
            if not 2 <= ntok <= 6 or c[pos + 2] != 5:
                raise Todo("tok with n outside 2..6 / flag byte other than 5 not evidenced")
            a, q = S(pos + 3, ntok)
            e2 = self.end(pos + 3)
            if c[e2] == 0x11 and c[e2 + 1] == 0x1f:
                self.arr_types.setdefault(self.u16(e2 + 2), "str")
                self.inferred("", "tok result ARRAY element type str (sample24 source)")
            if ntok > 2:
                # handler 0x4254f2 (2.4.12) / 0x42526c (2.4.2) -> arg-list helper 0x40af07 / 0x40b102(ctx,buf,1): [e2][n][b] then n x S stored in
                # coded order: string, arr, n (default -1), delim, flags, arr2 == help IDP_TOK `tok(string arr [n] [delim] [flags] [arr2])`;
                # b=5: (b&3)=1 and bit 4 passed on to 0x43dc48. Only n=2 has a source (sample24); n=4 (ref original-1 #28) is handler+help only.
                return done(a, q, False, f"tok n={ntok}: args in coded=written order by handler 0x4254f2/0x40af07 + help IDP_TOK; no .qml source (ref original-1 #28)")
            return done(a, q)
        if op == 0xb2:
            cond = self.ex(pos + 1)
            if cond.startswith("(") and self._balanced(cond):
                cond = cond[1:-1]
            q = self.end(pos + 1) + 4
            a, q = S(q, 2)
            return done([cond] + a, q + 2, False, "builtin iif (inferred label; two u16 jump operands not rendered)")
        raise Todo(f"dedicated builtin 0x{op:02x}")

    def group_n(self, pos):
        """GROUP N (sample35, known source): acc/acctest/childtest/findcr/findcs/findcn/htm/inpp/scan as functions."""
        c = self.code
        op = c[pos]
        nm = {0x83: "acc", 0x84: "acctest", 0x8d: "childtest", 0xa1: "findcr", 0xa2: "findcs", 0xa3: "findcn",
              0xac: "htm", 0xb6: "inpp", 0xdf: "scan"}[op]

        def S(q, k):
            out = []
            for _ in range(k):
                out.append(self.ex(q))
                q = self.end(q)
            return out, q

        def done(args, q):
            self.chk(pos, q)
            return nm + "(" + " ".join(args) + ")"

        b = c[pos + 1]
        if op == 0x83:
            if b != 3:
                raise Todo(f"acc form 0x{b:02x} (only `acc(name role window)` = 83 03 evidenced, sample35)")
            a, q = S(pos + 2, 3)
            return done(a, q)
        if op == 0x84:
            if b != 0x83 or c[pos + 2] != 0x11:
                raise Todo(f"acctest form 0x{b:02x} not evidenced")
            a, q = S(pos + 2, 3)
            if a[2] != '""' or c[q] != 0x1b or c[q + 1] != 0:
                raise Todo("acctest with explicit role / window operand not evidenced")
            self.inferred("", "acctest: coded `&acc name role(\"\") 1b 00`; the implicit empty role / default window are not written (sample35 `acctest(a \"OK\")`)")
            return done([a[0].lstrip("&"), a[1]], q + 2)
        if op == 0x8d:
            if b != 0x82:
                raise Todo(f"childtest form 0x{b:02x} (only 0x82 hwnd + 2 args evidenced)")
            a, q = S(pos + 2, 3)
            return done(a, q)
        if op in (0xa1,):
            if b not in (2, 6):
                raise Todo(f"findcr flags 0x{b:02x} not evidenced")
            a, q = S(pos + 2, 2)
            if not b & 4 and c[self.end(pos + 2)] == 0x1b:      # bit2 clear = 2nd argument is a character (handler 0x4252ca)
                ch = c[self.end(pos + 2) + 1]
                a[1] = "'" + chr(ch) + "'" if 0x20 <= ch < 0x7f else a[1]
            return done(a, q)
        if op in (0xa2, 0xa3):
            flag = c[pos + 2]
            if (op, flag) not in ((0xa2, 0), (0xa3, 1)) or b not in (1, 2):
                raise Todo(f"{nm} n={b} flag={flag} not evidenced")
            a, q = S(pos + 3, b + 1)
            return done([a[-1]] + a[:-1], q)          # coded: charset [from] then the string; written: string first
        if op == 0xac:
            if b != 2:
                raise Todo(f"htm n={b} not evidenced")
            a, q = S(pos + 2, 2)
            return done(a, q)
        if op == 0xb6:
            if not 2 <= b <= 3:
                raise Todo(f"inpp n={b} not evidenced")
            a, q = S(pos + 2, b)
            return done(a, q)
        if op == 0xdf:
            if b == 1:
                a, q = S(pos + 2, 1)
                return done(a, q)
            if b == 2:
                a, q = S(pos + 2, 2)
                return done(a, q)
            raise Todo(f"scan n={b} not evidenced")

    def wait_for(self, pos, stmt=False):
        c = self.code
        e = self.end(pos + 1)
        t, cc = c[e], c[e + 1]
        if t not in WAIT_KINDS:
            raise Todo(f"wait_for kind byte 0x{t:02x} not evidenced")
        nm, obs = WAIT_KINDS[t]
        if cc not in (2, 3):
            raise Todo(f"wait_for operand-count byte {cc} not evidenced")
        if not obs:
            self.inferred("", f"wait kind 0x{t:02x} = {nm} by source order (sample23)")
        # kind 0x82 is shared by WD and -WC (identical bytes); qmdec prints WD
        parts = [self.ex(pos + 1), nm]
        if cc == 3:
            arg = self.ex(e + 2)
            if nm == "K" and arg.startswith('"') and arg.endswith('"'):
                arg = arg[1:-1]                      # key name is stored as a string
            parts.append(arg)
        txt = " ".join(parts)
        return ("wait " + txt) if stmt else "wait(" + txt + ")"

    def fstring(self, pos):
        c = self.code
        d = pos + 1
        p0 = self.end(d)
        if c[p0] != 5:
            return self.str_method(pos)                 # GROUP L: value-returning str methods (sample28 `n=t.beg("he")`)
        if c[p0] == 0x34:
            return self.cmp_method(pos, d, p0)
        if c[d] != 0x1f:
            raise Todo("fmt_into destination is not a local")
        self.hidden.add(self.u16(d + 1))
        p = self.end(d)
        if c[p] != 5:
            raise Todo(f"fmt_into selector b=0x{c[p]:02x} (only 5 evidenced)")
        fmtpos = p + 2
        fmt = self.ex(fmtpos)
        if not (c[fmtpos] == 0x1e and fmt.startswith('"')):
            raise Todo("F-string format is not a pool constant")
        q = self.end(fmtpos)
        args = []
        while c[q] != 0:
            args.append(self.ex(q))
            q = self.end(q)
        text = fmt[1:-1]
        if "{" in text or "}" in text or "\\" in text:
            raise Todo("F-string text contains braces / backslash (escape form not evidenced)")
        specs = re.findall(r"%.", text)
        if any(s not in ("%i", "%s") for s in specs) or len(specs) != len(args) \
                or text.count("%") != len(specs):
            raise Todo(f"F-string format {text!r}: only %i / %s with matching args evidenced")
        it = iter(args)
        text = re.sub(r"%[is]", lambda m: "{" + next(it) + "}", text)
        return 'F"' + text + '"'

    def cmp_method(self, pos, d, p0):
        """0x37 selector 0x34 (T3 key 0x84, handler 0x4241b5 in 2.4.2): beg/begi/end/endi/mid/midi.
        Handler-only evidence (no corpus source line): layout [sel b e S ([b&4] S) ([e>1] S)]; flag bits from the
        handler's dispatch: b&1 = case-insensitive (strnicmp), b&2 = end, b&4 = mid (from index)."""
        c = self.code
        b, e = c[p0 + 1], c[p0 + 2]
        if b != 0:
            raise Todo(f"0x37 selector 0x34 with flag byte 0x{b:02x}: name from the flags not evidenced for this selector")
        if e not in (1, 2):
            raise Todo(f"0x37 selector 0x34 with count {e} not evidenced")
        q = p0 + 3
        args = []
        for _ in range(e):
            args.append(self.ex(q))
            q = self.end(q)
        self.chk(pos, q)
        return self.inferred(f"{self.ex(d)}.beg({' '.join(args)})",
                             "0x37 sel 0x34 flags 0 = str.beg by handler 0x4241b5 + QM help IDP_S_BEG (no corpus source line)")

    # -- helpers for source-correlated constructs (samples/set2) ------------
    def note_arr(self, base_pos, tail):
        if self.code[base_pos] == 0x1f and tail in ARR_ELEM:
            self.arr_types.setdefault(self.u16(base_pos + 1), ARR_ELEM[tail])

    def spe_text(self, pos, stmt=False):
        c = self.code
        fl = c[pos + 1]
        if fl == 0:
            return "spe"
        if fl == 1:
            return ("spe " if stmt else "spe(") + self.ex(pos + 2) + ("" if stmt else ")")
        raise Todo(f"spe flag 0x{fl:02x}")

    def member_ofs(self, pos):
        c = self.code
        e = self.end(pos + 1)
        t1, t2 = c[e], c[e + 1]
        ofs = self.u16(e + 2)
        if (t1, t2) == (0, 0) and c[pos + 1] == 0x3b:        # GROUP M: member of a struct array element (sample33 `ap[1].y=6`)
            base = self.ex(pos + 1)
            ty = self.last3b_tail
            if ty in STRUCT_FIELDS and ofs % 4 == 0 and ofs // 4 < len(STRUCT_FIELDS[ty]):
                return self.inferred(base + "." + STRUCT_FIELDS[ty][ofs // 4],
                                     "member of an ARRAY(POINT/RECT) element by offset order (sample33 `ap[1].y=6`: elem type word 0x14, offset 4)")
        if (t1, t2) == (0, 0) and c[pos + 1] in (0x1f, 0x21) and self.u16(pos + 2) < self.nloc:
            ty = self.desc[self.u16(pos + 2)][1]
            if ty == 4 and ofs == 4:
                return self.inferred(self.ex(pos + 1) + ".len", "str .len = member +4 (sample11)")
            if ty == 0x13 and ofs == 8:
                return self.inferred(self.ex(pos + 1) + ".lVal", "VARIANT member at offset 8 = .lVal; source System.qml ShutDownProcess `pid=hwndOrExename.lVal`")
            if ty in STRUCT_FIELDS and ofs % 4 == 0 and ofs // 4 < len(STRUCT_FIELDS[ty]):
                return self.inferred(self.ex(pos + 1) + "." + STRUCT_FIELDS[ty][ofs // 4],
                                     "struct member name from field order (sample12)")
        if c[pos + 1] == 0x1f and self.u16(pos + 2) < self.nloc and self.desc[self.u16(pos + 2)][1] >= 0x100:
            # GROUP L: user type (sample30 `type MYT int'a double'b str's byte'c[4]`): t1 = member type, t2 = array flag
            return self.inferred(self.ex(pos + 1) + f".m{ofs}", f"member of a user-defined type at offset {ofs} (type/flags {t1:02x}/{t2:02x}); member names are not stored in the exe, neutral name m<offset> (sample30)")
        raise Todo(f"member+offset type {t1:02x}/{t2:02x} ofs {ofs}: member name not evidenced")

    def obj_call(self, pos):
        c = self.code
        argc = c[pos + 4]
        obj_end = self.end(pos + 6)
        mid = self.u16(obj_end)
        cls = self.u16(obj_end + 2)
        oty = self.desc[self.u16(pos + 7)][1] if c[pos + 6] == 0x1f and self.u16(pos + 7) < self.nloc else None
        nm = INTF_METHODS.get(oty, {}).get(mid) or OBJ_METHODS.get((cls, mid))
        if nm is None:
            raise Todo(f"object method id 0x{mid:02x} of class {cls}: name not evidenced")
        p = obj_end + 4
        args = []
        for _ in range(argc):
            args.append(self.ex(p))
            p = self.end(p)
        args.reverse()                               # last coded arg = first parameter (as 0x49)
        self.inferred("", "COM object method name by (interface type, id) from source correlation (sample17, sample33)")
        if oty == 0x9a and mid == 0x48 and argc == 3:      # ICsv.Cell(r c)="z": the assigned value is coded first
            self.inferred("", "ICsv property set Cell(r c)=v: vtable id 0x48 with the value as extra first-coded argument (sample33)")
            return self.ex(pos + 6) + ".Cell(" + " ".join(args[:2]) + ")=" + args[2]
        return self.ex(pos + 6) + "." + nm + ("(" + " ".join(args) + ")" if args else "")

    def key_text(self, pos):
        c = self.code
        fl = c[pos + 1]
        if fl not in (0, 1, 2):
            raise Todo(f"key flags 0x{fl:02x} not evidenced")
        p = pos + 2
        parts = []
        while c[p] != 0:
            tag = c[p]
            p += 1
            if tag == 1:
                toks = []
                while c[p] > 5:
                    k = c[p]
                    p += 1
                    if c[p] == 4:
                        raise Todo("key repeat-count form not evidenced")
                    if k in KEY_MODS:
                        toks.append((KEY_MODS[k], True))
                        self.inferred("", "key modifier letters A/C/S/W from source correlation")
                    elif k in KEY_NAMED:
                        toks.append((KEY_NAMED[k], False))
                        self.inferred("", "key names T/Y/F<n>/N<n> from source correlation")
                    elif 0x41 <= k <= 0x5a:
                        toks.append((chr(k + 32), False))
                    elif 0x30 <= k <= 0x39:
                        toks.append((chr(k), False))
                    elif 0x70 <= k <= 0x87:
                        toks.append((f"F{k - 0x6f}", False))
                        self.inferred("", "key names T/Y/F<n>/N<n> from source correlation")
                    elif 0x60 <= k <= 0x69:
                        toks.append((f"N{k - 0x60}", False))
                        self.inferred("", "key names T/Y/F<n>/N<n> from source correlation")
                    elif k == 0xbf:
                        toks.append(("/", False))
                        self.inferred("", "key / = VK 0xbf from source correlation")
                    elif k in (6, 7):
                        toks.append(("{" if k == 6 else "}", False))
                        self.inferred("", "key group braces 6/7 from source correlation")
                    else:
                        raise Todo(f"key code 0x{k:02x} has no evidenced name")
                txt, prev = "", None
                for nm, ismod in toks:
                    if prev is not None and not prev[1] and prev[0] != "{" and nm[0].isupper():
                        txt += " "
                    txt += nm
                    prev = (nm, ismod)
                parts.append(txt)
            elif tag == 2:
                parts.append(self.ex(p))
                p = self.end(p)
            elif tag == 3:
                mode = c[p]
                if mode != 2:
                    raise Todo(f"key tag3 mode {mode} not evidenced")
                v = self.ex(p + 1)
                p = self.end(p + 1)
                parts.append(v if v.startswith('F"') else "(" + v + ")")
            else:
                raise Todo(f"key tag {tag} not evidenced")
        if not parts:
            raise Todo("key with empty tag stream")
        return "key" + "+-"[fl - 1] * (fl > 0) + " " + " ".join(parts)

    def str_method(self, pos):
        c = self.code
        dst = pos + 1
        e = self.end(dst)
        b = c[e]
        d = self.ex(dst)
        r = self.str_method_l(pos, e, b, d)
        if r is not None:
            return r
        if b == 5:
            q = e + 2
            fmt = self.ex(q)
            q = self.end(q)
            args = []
            while c[q] != 0:
                args.append(self.ex(q))
                q = self.end(q)
            self.chk(pos, q + 1)
            return self.inferred(f"{d}.format({' '.join([fmt] + args)})", "str.format via 0x37/0x55 by source correlation (sample11)")
        if b in STR_METHODS0:
            self.chk(pos, e + 3)
            return f"{d}.{STR_METHODS0[b]}"             # lcase/ucase/getclip/setclip/trim: order-swap test sample27 CONFIRMED
        if b in (0x0e, 0x0f):
            s1 = self.ex(e + 2)
            s2 = self.ex(self.end(e + 2))
            self.chk(pos, self.end(self.end(e + 2)))
            return f"{d}.{'left' if b == 0x0e else 'right'}({s2} {s1})"      # left/right: order-swap test sample27 CONFIRMED
        if b == 0x0c:
            q1 = e + 2
            q2 = self.end(q1)
            q3 = self.end(q2)
            self.chk(pos, self.end(q3))
            return self.inferred(f"{d}.get({self.ex(q3)} {self.ex(q1)} {self.ex(q2)})", "str method 0x0c get from source correlation")
        if b == 0x10:
            # T3 0x10 = [opbyte, b, n, n x S] (handler 0x424ab1 / helper 0x40b033); source-observed only for n=2 (sample11)
            if c[e + 1] != 0:
                raise Todo(f"str method 0x10 with b=0x{c[e+1]:02x} not evidenced")
            n = c[e + 2]
            q, parts = e + 3, []
            for _ in range(n):
                parts.append(self.ex(q))
                q = self.end(q)
            self.chk(pos, q)
            why = "str method 0x10 from() from source correlation"
            if n != 2:
                why += f"; n={n} args by the handler's count loop (source-observed only for n=2, sample11)"
            return self.inferred(f"{d}.from({' '.join(parts)})", why)
        if b == 0x18:
            a = self.ex(e + 1)
            self.chk(pos, self.end(e + 1))
            return self.inferred(f"{d}.getwintext({'win()' if a == 'win' else a})", "str method 0x18 getwintext from source correlation (sample26)")
        if b == 0x3c:
            self.chk(pos, self.end(e + 2))
            return self.inferred(f"{d}.addline({self.ex(e + 2)})", "str method 0x3c addline from source correlation")
        if b == 0x14:
            # T3 0x14 = [opbyte, n, n x S] (handler 0x4238d1; remove handler in 2.4.12 is 0x423b64 -> 0x42be9b, 0x42bb4b is the 2.4.2 address: erases nc chars at index `from`;
            # matches QM help IDP_S_REMOVE s.remove(from [nc])). Handler-only: no corpus source line.
            n = c[e + 1]
            if n != 2:
                raise Todo(f"str method 0x14 (remove) with n={n}: default-nc form not evidenced")
            a1 = self.ex(e + 2)
            q = self.end(e + 2)
            a2 = self.ex(q)
            self.chk(pos, self.end(q))
            return self.inferred(f"{d}.remove({a1} {a2})", "str method 0x14 = remove(from nc) by handler 0x423b64 -> 0x42be9b (2.4.12) + QM help IDP_S_REMOVE (no corpus source line)")
        raise Todo(f"0x37 method selector 0x{b:02x} has no evidenced name")

    def _sargs(self, q, n):
        parts = []
        for _ in range(n):
            parts.append(self.ex(q))
            q = self.end(q)
        return parts, q

    def str_method_l(self, pos, e, b, d):
        """GROUP L: 0x37 selectors named by sample28 (known source, one statement per selector, statement order == stream
        order; layouts from handlers via X_LF/X_L61/X_84...). Returns None when the selector is not handled here."""
        c = self.code

        def fin(name, parts, q, bare_ok=True):
            self.chk(pos, q)
            return f"{d}.{name}" + ("(" + " ".join(parts) + ")" if parts or not bare_ok else "")
        if b in STR_CNT and b != 0x3c or b == 0x3c:
            n = c[e + 1]
            parts, q = self._sargs(e + 2, n)
            return fin(STR_CNT[b], parts, q)
        if 0x34 <= b <= 0x39:
            fl, n = c[e + 1], c[e + 2]
            if fl != b - 0x34:
                raise Todo(f"0x37 sel 0x{b:02x} flags 0x{fl:02x}: flag/selector pairing not evidenced")
            parts, q = self._sargs(e + 3, n)
            return fin(STR_CMP[fl], parts, q, False)
        if b == 0x07:
            fl, n = c[e + 1], c[e + 2]
            parts, q = self._sargs(e + 3, n)
            return fin("trim", parts, q)
        if (b, c[e + 1]) in STR_MODE:
            n = c[e + 2]
            parts, q = self._sargs(e + 3, n)
            return fin(STR_MODE[(b, c[e + 1])], parts, q, False)
        if b == 0x3a:
            return fin("swap", [self.ex(e + 1)], self.end(e + 1), False)
        if b == 0x11:
            n = c[e + 1]
            parts, q = self._sargs(e + 2, 2 * n)
            return fin("fromn", parts, q, False)
        if b in (0x32, 0x33):
            n = c[e + 1]
            parts, q = self._sargs(e + 4, n)
            return fin("gett" if b == 0x32 else "getl", parts, q, False)
        if b == 0x0d:
            if c[e + 1] != 3:
                raise Todo(f"geta with flag byte 0x{c[e+1]:02x} not evidenced")
            q1 = e + 2
            q2 = self.end(q1)
            q3 = self.end(q2)
            self.chk(pos, self.end(q3))
            return self.inferred(f"{d}.geta({self.ex(q3)} {self.ex(q1)} {self.ex(q2)})", "str method 0x0d geta: layout as get (0x0c) with flag byte 3, source sample28 `t.geta(s 1 1)` (single occurrence)")
        return None

    def chk(self, pos, mine):
        if mine != self.end(pos):
            raise Todo(f"operand layout of 0x{self.code[pos]:02x} differs from the evidenced form (parsed end {mine} != {self.end(pos)})")

    def arr_stmt(self, pos):
        c = self.code
        a, b = c[pos + 1], c[pos + 2]
        arr = self.ex(pos + 3)
        q = self.end(pos + 3)
        names = {1: "create", 3: "redim", 5: "remove", 12: "sort"}
        if a not in names:
            raise Todo(f"arr_op a={a} not mapped")
        if a in (1, 3):
            sel = c[q]
            q += 1
            if sel in (3, 0xff, 0x14):
                if c[pos + 3] == 0x1f:
                    self.arr_types.setdefault(self.u16(pos + 4), {3: "int", 0xff: "str", 0x14: "long"}[sel])
            elif sel == 0 and a in (1, 3):               # GROUP M: struct element, u16 = element size (8 = POINT); type name from the elem tail word
                q += 2
                self.inferred("", "arr_op create selector 0x00 + u16 element size (sample33 ARRAY(POINT): 8); element type name only from the later elem tail word 0x14")
            else:
                raise Todo(f"arr_op create/redim element selector 0x{sel:02x} not evidenced")
        args = []
        if a == 12:
            q += 1
        else:
            for _ in range(b):
                args.append(self.ex(q))
                q = self.end(q)
        self.chk(pos, q)
        return self.inferred(f"{arr}.{names[a]}" + ("(" + " ".join(args) + ")" if args else ""),
                             "ARRAY method name from arr_op selector by source correlation (sample12)")

    # -- statements -----------------------------------------------------------
    def unused_locals(self):
        """descriptors that no instruction of the stream refers to (operand 0x1f / 0x21 / by id) and that have a declarable type:
        user variables declared but never used (the source needs the bare declaration to keep the descriptor numbering).
        Internal temporaries have non-declarable type codes (0x21, 0x22) and are allocated by QM itself."""
        used = set(self.seen_explicit) | set(self.hidden) | set(self.thread) | set(self.declared)
        for (t, p) in list(self.ends):
            if t == 1 and p < len(self.code) and self.code[p] in (0x1f, 0x21) and p + 3 <= len(self.code):
                used.add(struct.unpack_from("<H", self.code, p + 1)[0])
        for rec in self.thread_recs:
            if rec is not None:
                used.add(rec["didx"])
        return {i for i in range(self.nloc) if i not in used and self.desc[i][1] in self.ltypes
                and self.desc[i][1] in (0, 1, 2, 4, 5, 6) and self.desc[i][2] in (0, 1)}

    def predecl(self, idx, text):
        """declaration prefix for the first assignment of local idx; in --roundtrip mode the declaration moves to the function head"""
        if ROUNDTRIP:
            self.stmt_decl.append(idx)
        return text + " "

    def decl_text(self, idx):
        """GROUP L: declaration type text of a local from its descriptor (type, pointer flag)."""
        ty, b1 = self.desc[idx][1], self.desc[idx][2]
        star = "*" if b1 == 1 else ""
        if ty in self.ltypes and ty in (0, 1, 2, 3, 4, 5, 6):
            return self.ltypes[ty] + star
        if ty >= 0x100:
            return f"type_{ty:x}{star}"
        raise Todo(f"pointer local of descriptor type 0x{ty:x}")

    def stmt_text(self, i):
        """-> (text, kind) for simple statements; raises Todo."""
        c = self.code
        pos = self.stream[i]
        op = c[pos]
        if op == 0x50:                               # GROUP O: thread-variable declaration + initialiser (handler 0x40f3fd; sample34)
            k = self.u16(pos + 1)
            rec = self.thread_recs[k] if k < len(self.thread_recs) else None
            if rec is None or i + 1 >= len(self.stream):
                raise Todo(f"0x50 thread-variable record {k} not found / not a plain thread-variable record")
            p2 = self.stream[i + 1]
            self.dec.instr(p2, 1)                    # (records the end positions of the initialiser statement)
            if c[p2] != 0x24 or c[p2 + 1] != 0x21 or self.u16(p2 + 2) != rec["didx"]:
                raise Todo("0x50 is not followed by the store into its own thread variable")
            inner = self.stmt_text(i + 1)
            ty = self.desc[rec["didx"]][1]
            if ty not in self.ltypes or ty not in (0, 1, 2, 4, 5, 6):
                raise Todo(f"thread variable descriptor type 0x{ty:x} has no validated spelling")
            if ROUNDTRIP:                            # thread records are numbered in declaration order: no-initialiser records sit next to the inline ones
                inline = {self.u16(self.stream[m] + 1) for m in range(len(self.stream)) if self.code[self.stream[m]] == 0x50}
                def tdecl(r2):
                    t2 = self.desc[r2["didx"]][1]
                    if t2 in self.ltypes and t2 in (0, 1, 2, 4, 5, 6):
                        self.thread_declared.add(r2["k"])
                        return (self.ltypes[t2] + ("--" if r2["flags"] & 2 else "-") + " " + r2["name"]
                                + "  /*inferred: declaration without initialiser compiles to no statement; placed next to the neighbouring thread-variable declaration (records are numbered in declaration order)*/")
                    return None
                if not any(m < k for m in inline):   # the run of no-initialiser records in front of the first inline one
                    for j in range(k):
                        r2 = self.thread_recs[j] if j < len(self.thread_recs) else None
                        if r2 is not None and r2["k"] not in self.thread_declared and (ln := tdecl(r2)):
                            self.pending_lines.append(ln)
                j = k + 1                            # the run directly after it
                while j < len(self.thread_recs) and j not in inline and self.thread_recs[j] is not None:
                    if self.thread_recs[j]["k"] not in self.thread_declared and (ln := tdecl(self.thread_recs[j])):
                        self.post_lines.append(ln)
                    j += 1
            self.thread_declared.add(k)
            self.skip_next = 1
            return self.ltypes[ty] + ("--" if rec["flags"] & 2 else "-") + " " + inner
        if op in STORE_WANT:
            dst = pos + 1
            src = self.end(dst)
            rhs = self.ex(src)
            lhs = self.ex(dst)
            pre = ""
            want = STORE_WANT[op]
            if c[dst] == 0x3b and self.last3b_tail in STRUCT_FIELDS:      # GROUP M: bare struct element addressed = member at offset 0 (sample33 `ap[0].x=5`)
                lhs = self.inferred(lhs + "." + STRUCT_FIELDS[self.last3b_tail][0], "bare ARRAY(POINT/RECT) element store = member at offset 0 (sample33 `ap[0].x=5`)")
            if c[dst] == 0x1f:
                idx = self.u16(dst + 1)
                dty = self.desc[idx][1] if idx < self.nloc else None
                if dty in STRUCT_FIELDS:
                    lhs = self.inferred(lhs + "." + STRUCT_FIELDS[dty][0], "struct member name from field order (sample12)")
                elif dty is not None and dty >= 0x100:            # GROUP L: bare local of a user type = member at offset 0
                    lhs = self.inferred(lhs + ".m0", "user-type local addressed without offset = member at offset 0 (sample30 `t.a=1`); member names are not stored in the exe")
                elif idx not in self.declared and dty == want:
                    pre = self.predecl(idx, self.ltypes[want])
                    self.declared.add(idx)
                    if want in NEW_TYPES:
                        self.inferred("", "type code of byte/word/double/long local by source correlation")
            if op in (0x26, 0x27, 0x28, 0x29):
                self.inferred("", f"typed store 0x{op:02x} by source correlation (sample09/13)")
            return f"{pre}{lhs}={rhs}"
        if op == 0x25:                               # GROUP L: pointer / lpstr store (sample30 `int* p=&i`, `lpstr ls="abc"`)
            dst = pos + 1
            src = self.end(dst)
            if c[src] == 0x11:
                rhs = "&" + self.ex(src + 1)
            else:
                rhs = self.ex(src)
            if c[dst] != 0x1f:
                raise Todo("pointer store with non-local destination not evidenced")
            idx = self.u16(dst + 1)
            lhs = self.ex(dst)
            pre = ""
            if idx not in self.declared:
                pre = self.predecl(idx, self.decl_text(idx))
                self.declared.add(idx)
                self.inferred("", "lpstr / T* pointer declaration proven only by single statements (sample30)")
                if self.desc[idx][1] >= 0x100:
                    self.inferred("", "user-defined type id: type name not stored in the exe (neutral name type_<id>)")
            return f"{pre}{lhs}={rhs}"
        if op == 0x3d:                               # GROUP N: `Acc a=acc(...)` = `3d dst src u16(type 0x24)` (sample35)
            dst = pos + 1
            src = self.end(dst)
            if c[dst] != 0x1f or self.u16(self.end(src)) != 0x24:
                raise Todo("0x3d form other than local Acc assignment not evidenced")
            idx = self.u16(dst + 1)
            if self.desc[idx][1] != 0x24:
                raise Todo("0x3d destination is not an Acc local")
            rhs = self.ex(src)
            pre = ""
            if idx not in self.declared:
                pre = self.predecl(idx, "Acc")
                self.declared.add(idx)
            return f"{pre}{self.ex(dst)}={rhs}"
        if op == 0x3e:
            dst = pos + 1
            src = self.end(dst)
            rhs = self.ex(src)
            if c[dst] != 0x1f:
                raise Todo("object assign with non-local destination")
            idx = self.u16(dst + 1)
            dty = self.desc[idx][1] if idx < self.nloc else None
            pre = ""
            lhs = self.ex(dst)
            if dty in (0x9d, 0x99, 0x9a, 0x9c, 0x09) and dty in self.ltypes and idx not in self.declared:
                pre = self.predecl(idx, self.ltypes[dty])
                self.declared.add(idx)
            self.inferred("", "COM object type codes / assign 0x3e by source correlation (sample17)")
            return f"{pre}{lhs}={rhs}"
        if op == 0x3f:                               # GROUP M: typed assignment into a VARIANT / BSTR local (sample33)
            ty = c[pos + 1]
            if ty not in (0x13, 0x0f) or c[pos + 2] != 0x1f:
                raise Todo(f"0x3f type 0x{ty:02x} assignment form not evidenced")
            idx = self.u16(pos + 3)
            if idx >= self.nloc or self.desc[idx][1] != ty:
                raise Todo("0x3f destination descriptor type differs from the type byte")
            lhs = self.ex(pos + 2)
            rhs = self.ex(self.end(pos + 2))
            pre = ""
            if idx not in self.declared:
                pre = self.predecl(idx, self.ltypes[ty])
                self.declared.add(idx)
                self.inferred("", "type code of VARIANT (0x13) / BSTR (0x0f) local by source correlation (sample33)")
            self.inferred("", "0x3f = typed assignment `v=expr` into a VARIANT (0x13: trailing word = source type, 3 = int) or BSTR (0x0f) local; handler 0x415673 -> 0x4140d7 + source sample33")
            return f"{pre}{lhs}={rhs}"
        if op == 0x35:
            return self.inferred(self.ex(pos + 1) + "+" + self.ex(self.end(pos + 1)), "str append 0x35 by source correlation (sample11/18)")
        if op == 0x37:
            return self.str_method(pos)
        if op == 0x3a:
            return self.arr_stmt(pos)
        if op == 0x4a:
            return self.inferred(self.ex(pos + 3), "0x4a wrapper (u16 + S) around object call by source correlation")
        if op == 0x47:
            return self.ex(pos)
        if op == 0x80:
            if c[pos + 1] != 1:
                raise Todo(f"act with n={c[pos+1]} (only n=1 evidenced)")
            return "act " + self.ex(pos + 2)
        if op in (0xbc, 0xbd, 0xd3):
            want = {0xbc: 0x6e, 0xbd: 0x78, 0xd3: 0x73}[op]
            if c[pos + 1] != want:
                raise Todo(f"min/max/res mode byte 0x{c[pos+1]:02x} not evidenced")
            return {0xbc: "min ", 0xbd: "max ", 0xd3: "res "}[op] + self.ex(pos + 2)
        if op == 0x8a:
            if c[pos + 1] != 0x20:
                raise Todo(f"clo mode 0x{c[pos+1]:02x} not evidenced")
            return "clo " + self.ex(pos + 2)
        if op == 0xc0:
            md, n = c[pos + 1], c[pos + 2]
            if md not in (0, 0x2b, 0x2d) or n not in (0, 2, 3):
                # mode '*' (0x2a) = recorded-text form `mou "text"` (help IDP_MOU syntax 3): handler 0x41e9d1 reads S(text) then S(double)
                # (0x40adcc, 0x40ade6) and parses the text characters ('.', ':' ...); layout/meaning of the 2nd operand not evidenced,
                # no sample. Needed .qml line: `mou "<text recorded by the QM recorder>"`.
                raise Todo("mou mode/arg count other than 0,+,- / 0,2,3 not evidenced (mode '*' = recorded text, handler 0x41e9d1, no sample)")
            parts, q = self._sargs(pos + 3, n)          # sample27: mou 5 6 / mou 5 6 w / mou+ 1 2 / mou- 3 4 / mou
            self.chk(pos, q)
            return ("mou" + {0: "", 0x2b: "+", 0x2d: "-"}[md] + (" " + " ".join(parts) if parts else ""))
        if op == 0xc2:
            argc, fl = c[pos + 1], c[pos + 2]
            if argc not in (1, 2, 3) or fl not in (0, 2):
                raise Todo("mes with argc/flags other than 1..3 / 0,2 not evidenced")
            parts, q = self._sargs(pos + 3, argc)       # sample27/29: coded order = caption, flags, TEXT (text last)
            self.chk(pos, q)
            parts = parts[-1:] + parts[:-1]             # written order: text caption flags
            # handler 0xc2 = 0x420192 (2.4.12): [argc][flag byte]; MSGBOXPARAMS (0x28 bytes) filled from caption (argc>=2), style (argc>=3), then
            # the text last (flag bit 0 = numeric text via 0x42422f, else string 0x424906); result id mapped through the button-letter table
            # 0x4630e8 (help: returns 'O','Y',...); flag bit 1 (byte 2) = `mes-`: macro ends on Cancel(2)/No(7)/OK-only (0x420337..0x42035b);
            # observed: sample27 `mes- "three"` flag 2, `mes "two" "cap" "OC"` flag 0.
            return "mes" + ("-" if fl == 2 else "") + " " + " ".join(parts)
        if op == 0xcb:                               # GROUP L: ont / ont- (sample29)
            if c[pos + 1] not in (0x20, 0x2d):
                raise Todo(f"ont mode 0x{c[pos+1]:02x} not evidenced")
            return "ont" + "-" * (c[pos + 1] == 0x2d) + " " + self.ex(pos + 2)
        if op in (0xea, 0xde):                       # web S / shutdown S (sample29)
            if c[pos + 1] != 1:
                raise Todo(f"0x{op:02x} with n={c[pos+1]} not evidenced")
            return ("web " if op == 0xea else "shutdown ") + self.ex(pos + 2)
        if op == 0xed:                               # zip / zip- (sample29)
            if c[pos + 1] != 2 or c[pos + 2] not in (0, 1):
                raise Todo("zip form not evidenced")
            return "zip" + "-" * c[pos + 2] + " " + self.ex(pos + 3) + " " + self.ex(self.end(pos + 3))
        if op == 0xb7:
            return self.key_text(pos)
        if op == 0xc8:
            mask = struct.unpack_from("<I", c, pos + 1)[0]
            if mask == 0xffffffff:
                return "opt save"
            if mask == 0xfffffffe:
                return "opt restore"
            if mask not in OPT_MASKS:
                raise Todo(f"opt mask 0x{mask:x} not evidenced")
            return "opt " + OPT_MASKS[mask] + " " + self.ex(pos + 5)
        if op == 0xda:
            return self.spe_text(pos, True)
        if op == 0xa9:
            t = struct.unpack_from("<h", c, pos + 1)[0]
            return "goto " + self.label_name(t + 1)
        if op in RMW_OPS:
            dst = pos + 1
            t2 = self.end(dst)
            o = c[t2]
            if o not in T2_OPS:
                raise Todo(f"rmw with table-2 operator 0x{o:02x} has no validated semantics")
            txt, obs = T2_OPS[o]
            if o == 0x0c:
                raise Todo("rmw with 'and' not evidenced")
            rhs = self.ex(t2 + 2 if o in T2_TYPED else t2 + 1)
            s = self.ex(dst) + txt.strip() + rhs
            if not obs:
                self.inferred("", f"rmw operator 0x{o:02x} label " + ("inferred" if o in HANDLER_LABELS else T2_WHY))
            if op != 0x2a:
                self.inferred("", f"typed rmw 0x{op:02x} by source correlation (sample09/13)")
            return s
        if op == 0x30:
            v = self.ex(pos + 1)
            if c[pos + 1] in (0x1b, 0x19, 0x1c):
                return "wait " + v              # bare number statement = wait seconds (same opcode as `wait N`)
            raise Todo("wait_sec with non-constant operand: source form not evidenced")
        if op == 0x31:
            return self.wait_for(pos, True)
        if op == 0x01:
            return self.call_user(pos, True)
        if op in (0x52, 0x49, 0x9f) or op in DEDICATED:
            return self.ex(pos)
        if op == 0x00:
            if self.end(pos) != pos + 1:
                raise Todo("0x00 with operands")
            return self.inferred("end", "bare `end` = single byte 0x00 (sample22, inferred)")
        if op == 0x9a:
            fl = c[pos + 1]
            if fl == 0:
                return "end " + self.ex(pos + 2)
            if fl == 2:
                a2 = self.ex(pos + 2)
                return "end " + self.ex(self.end(pos + 2)) + " " + a2
            if fl == 4:
                # handler 0x421960 bit 4 (no bit 1/0): operand is the error object `_error` (copies its text/flags)
                if c[pos + 2] == 0x11 and c[pos + 3] == 0x21 and self.desc[self.u16(pos + 4)][1] == 0x1b:
                    self.inferred("", "end flag 4 = `end _error` (handler 0x421960 bit 4 reads the error object); source System.qml ShutDownProcess `err+ end _error`")
                    return "end _error"
                raise Todo("end flag 0x04 with an operand that is not the hidden _error local (type 0x1b)")
            raise Todo(f"end flag 0x{fl:02x} not evidenced")
        if op == 0xd5:
            if c[pos + 1] != 0 or not 1 <= c[pos + 2] <= 5:
                raise Todo("run with flag byte != 0 / argument count outside 1..5 not evidenced")
            # OBSERVED (sample29 .qml lines `run "notepad.exe"`, `run "notepad.exe" "c:.txt"`, `run "c:.txt" "" "print"`,
            # `run "notepad.exe" "" "" "c:	emp"`; bytes `d5 00 n` + n x S, string pool offsets ascending = written order):
            # byte2 = argument count n (1..4), NOT a mode; arguments in written order file, par, verb, dir (help IDP_RUN).
            # Handler 0x41f41d (2.4.12): [d5][b1 = 0 or '-'(0x2d)][n], then S1..Sn in this order: file; n>=2 par; n>=3 verb; n>=4 dir
            # (a lone "*" = extract from file); n>=5 flags (int); n>=6 window (0x32 = omitted, else S); n>=7 hwnd-like slot (1b 00 or lvalue).
            parts, q = self._sargs(pos + 3, c[pos + 2])
            self.chk(pos, q)
            if c[pos + 2] == 5:
                self.inferred("", "run n=5 (flags): handler 0x41f41d only, no sample; n=1..4 observed in sample29")
            return "run " + " ".join(parts)
        if op == 0x82:
            fl = c[pos + 1]
            if fl & 0x80:
                raise Todo("atend with flag bit 7 (helper 0x429520 id form) not evidenced")
            if fl & 0x7f:                            # GROUP M: handler 0x422730 evaluates ONE S when flag&0x7f (sample31 `atend sub.AtEnd 7`: 82 01 id16 1b 07)
                self.chk(pos, self.end(pos + 4))
                return "atend " + self.sub_name(self.u16(pos + 2)) + " " + self.ex(pos + 4)
            return "atend " + self.sub_name(self.u16(pos + 2))
        if op == 0x85:
            b = c[pos + 1]
            if b == 0:
                v = self.ex(pos + 2)
                return "bee" if v == "0" else "bee " + v
            if b == 4:
                return "bee " + self.ex(pos + 2) + " " + self.ex(self.end(pos + 2))
            raise Todo(f"bee mode 0x{b:02x} (sound-file form) not evidenced")
        if op == 0xe3:
            if c[pos + 1] != 1 or c[pos + 2] != 0x08:
                raise Todo("tim with n!=1 / no to_dbl wrapper not evidenced")
            return "tim " + self.ex(pos + 3)
        if op in MOUSE_CMDS:
            if c[pos + 1] != ord(MOUSE_CMDS[op][0]) or c[pos + 2] != 0x20 or c[pos + 3] != 3:
                raise Todo("mouse click form other than `cmd x y window` not evidenced")
            a = []
            q = pos + 4
            for _ in range(3):
                a.append(self.ex(q))
                q = self.end(q)
            self.chk(pos, q)
            return MOUSE_CMDS[op] + " " + " ".join(a)
        if op == 0xab:
            if c[pos + 1] not in (0x20, 0x2d):
                raise Todo(f"hid flag 0x{c[pos+1]:02x} not evidenced")
            return "hid" + "-" * (c[pos + 1] == 0x2d) + " " + self.ex(pos + 2)
        if op in (0xdb, 0xbf):
            # `mov+ 1 2 3 4 w` is `bf 03 03`, so 0xbf = mov, 0xdb = siz by elimination; both share handler 0x427985, only the mode byte differs
            m, n = c[pos + 1], c[pos + 2]
            if (op, m, n) not in ((0xdb, 2, 3), (0xbf, 1, 3), (0xbf, 3, 3)):
                raise Todo(f"siz/mov mode {m} n {n} not evidenced")
            a, q = [], pos + 3
            for _ in range(5 if m == 3 else 3):          # mode 3 = `mov+ x y w h win` (sample27)
                a.append(self.ex(q))
                q = self.end(q)
            self.chk(pos, q)
            return ("siz " if op == 0xdb else "mov+ " if m == 3 else "mov ") + " ".join(a)
        if op == 0xbe:
            if c[pos + 1] != 1:
                raise Todo("men with mode != 1 not evidenced")
            a = self.ex(pos + 2)
            w = self.ex(self.end(pos + 2))
            return f"men {a} {w}"
        if op == 0x87:
            if c[pos + 1] != 0 or c[pos + 2] != 1:
                raise Todo("but form other than `but text window` not evidenced")
            a = self.ex(pos + 3)
            w = self.ex(self.end(pos + 3))
            return f"but {a} {w}"
        if op == 0xcc:
            if c[pos + 1] != 1:
                raise Todo("0xcc flag != 1 not evidenced")
            return "paste " + self.ex(pos + 2)          # paste == outp (QM help IDP_PASTE); bytes identical
        if op == 0xc3:
            if c[pos + 1] not in (1, 2):
                raise Todo("mkdir with mode other than 1 (path) / 2 (path parent) not evidenced")
            parts, q = self._sargs(pos + 2, c[pos + 1])   # sample27: mkdir "c:\temp\qmtest" "c:\temp"
            self.chk(pos, q)
            return "mkdir " + " ".join(parts)
        if op == 0x95:
            if c[pos + 1] != 1 or c[pos + 2] != 0:
                raise Todo("del with mode/flag other than 1/0 not evidenced")
            return "del " + self.ex(pos + 3)
        if op == 0xd2:
            if c[pos + 1] != 1 or c[pos + 2] != 2 or c[pos + 3] not in (0, 0x2a):
                raise Todo("ren form other than `ren[*] from to` not evidenced")
            a = self.ex(pos + 4)
            b2 = self.ex(self.end(pos + 4))
            self.chk(pos, self.end(self.end(pos + 4)))
            return "ren" + ("*" if c[pos + 3] else "") + f" {a} {b2}"
        if op == 0xb6:
            if not 2 <= c[pos + 1] <= 3:
                raise Todo("inpp n not evidenced")
            parts, q = self._sargs(pos + 2, c[pos + 1])
            self.chk(pos, q)
            return "inpp " + " ".join(parts)
        if op == 0x8b:
            if (c[pos + 1], c[pos + 2], c[pos + 3]) != (2, 2, 0):
                raise Todo("cop form other than `cop src dst` not evidenced")
            a = self.ex(pos + 4)
            return f"cop {a} {self.ex(self.end(pos + 4))}"
        if op == 0xbb:
            if c[pos + 1] != 0x80 or c[pos + 2] != 1:
                raise Todo("mac form other than `mac name` not evidenced")
            self.inferred("", "mac by source order (single occurrence)")
            return "mac " + self.ex(pos + 3)
        if op == 0xb9:
            if c[pos + 1] != 0 or c[pos + 2] not in (0, 0x2d):
                raise Todo("lock form not evidenced")
            return "lock" + "-" * (c[pos + 2] == 0x2d)
        if op == 0xc9:
            fl = c[pos + 1]
            if fl == 0:
                return "out " + self.ex(pos + 2)
            if fl == 2:
                p = pos + 3
                fmt = self.ex(p)
                p = self.end(p)
                args = []
                while c[p] != 0:
                    args.append(self.ex(p))
                    p = self.end(p)
                return "out " + " ".join([fmt] + args)
            raise Todo(f"out flag 0x{fl:02x} (only 0 and 2 evidenced)")
        if op == 0xd0:
            fl = c[pos + 1]
            if fl == 0:
                return "ret"
            if fl == 1:
                return self.inferred("ret " + self.ex(pos + 2), "ret with value (flag 1) handler-only")
            raise Todo(f"ret flag 0x{fl:02x}")
        if op == 0x89:
            return "continue"
        if op == 0x86:
            return "break"
        raise Todo(f"statement opcode 0x{op:02x} has no validated semantics")

    # -- range / structure emission ------------------------------------------
    def flush_decls(self, ind, out, upto_refs_from, simple=False):
        new = []
        for r in self.refs[upto_refs_from:]:
            if r not in self.declared and r not in self.hidden and r not in new:
                new.append(r)
        if ROUNDTRIP:
            self.flush_decls_rt(ind, out, new, simple)
            return
        # declarations first needed inside a nested block are hoisted to the function head
        # (QM locals are function-scoped; the first-use position is not stored)
        tgt = self.hoisted if ind else out
        ind = ""
        for r in new:
            self.declared.add(r)
            tgt.append(self.decl_line(r, ind))

    def follow_unused(self, r, ind):
        """declared-but-unused locals numbered right after r: QM allocates their descriptors in declaration order, i.e. before any later declaration"""
        res = []
        q = r + 1
        while q in self.unused and q not in self.declared:
            self.declared.add(q)
            res.append(ind + self.decl_line(q, ""))
            q += 1
        return res

    def decl_line(self, r, ind=""):
        ty = self.desc[r][1]
        star = "*" if self.desc[r][2] == 1 and ty in (0, 1, 2, 3, 4, 5, 6) else ""     # GROUP L: pointer flag (sample30)
        if ty in self.ltypes:
            return f"{ind}{self.ltypes[ty]}{star} loc{r}" + ("  /*inferred: type code from source correlation*/" if ty in NEW_TYPES else "")
        if ty >= 0x100 and ty != 0x10d + 0x1000:
            return f"{ind}type_{ty:x}{'*' if self.desc[r][2] == 1 else ''} loc{r}  /*inferred: user-defined type id 0x{ty:x}; type and member names are not stored in the exe (sample30)*/"
        if ty == 0x0d and r in self.arr_types:
            return f"{ind}ARRAY({self.arr_types[r]}) loc{r}  /*inferred: element type from create selector / arr_elem tail*/"
        if ty == 0x0d:
            return f"{ind}ARRAY loc{r} /*TODO(evidence): element type is not in the descriptor*/"
        return f"{ind}/*TODO(evidence): local loc{r} descriptor type 0x{ty:02x}*/ loc{r}"

    def flush_decls_rt(self, ind, out, new, simple=False):
        """--roundtrip: QM numbers descriptors in DECLARATION order. The usual merged form (`int loc3=7` at first assignment) is kept; but when a
        statement declares local N while a lower-numbered NAMED local is still undeclared (it was declared earlier in the source without
        initialiser, e.g. `double r`), those lower locals are declared first, in index order, as their own line
        (a declaration without initialiser compiles to no statement)."""
        for ln in self.pending_lines:
            out.append(ind + ln)
        self.pending_lines = []
        here = set(new) | set(self.stmt_decl)
        self.stmt_decl = []
        lower = []
        if here:
            top = max(here)
            lower = [r for r in sorted(self.explicit_all | self.unused)
                     if r < top and r not in self.declared and r not in self.hidden and r not in here and r < self.nloc and r not in self.thread]
        for r in lower:
            self.declared.add(r)
            out.append(ind + self.decl_line(r, ""))
        for r in new:                                 # nested first uses are declared in place (not hoisted): the declaration position fixes the descriptor number
            self.declared.add(r)
            out.append(ind + self.decl_line(r, ""))
            out += self.follow_unused(r, ind)
        for r in sorted(here - set(new)):             # merged declarations (`int loc=..`): the unused locals that follow go right after the statement
            tgt = self.post_lines if simple else out
            tgt += self.follow_unused(r, ind)

    def note(self):
        r = "".join(f"  /*{c}*/" for c in self.cmts)
        return r + ("  /*inferred: " + "; ".join(self.notes) + "*/" if self.notes else "")

    def raw(self, i):
        a = self.stream[i]
        b = self.stream[i + 1] if i + 1 < len(self.stream) else len(self.code)
        return a, b, self.code[a:b].hex(" ")

    def record(self, i, op, status, reason=""):
        self.stats.append((i, op, status, reason))

    def emit(self, lo, hi, ind, out):
        i = lo
        n = len(self.stream)
        while i <= hi:
            pos = self.stream[i]
            op = self.code[pos]
            a, b, rawhex = self.raw(i)
            if i in self.labels:
                out.append(f"{ind}// inferred: label position from goto target; name not stored")
                out.append(f" {self.labels[i]}")
            r0 = len(self.refs)
            self.flag_inferred = self.flag_todo = False
            self.notes = []
            self.cmts = []
            tag = f"#{i} @{a}-{b}"
            try:
                end = self.dec.instr(pos, 1)
                if i + 1 < n and end != self.stream[i + 1]:
                    raise Todo(f"layout does not tile: decoded end {end} != next entry {self.stream[i+1]}")
            except qmlayout.Unresolved as e:
                out.append(f"{ind}// TODO(evidence): {tag} op 0x{op:02x} layout unresolved: {e}; raw {rawhex}")
                self.record(i, op, "todo", f"layout unresolved: {e}")
                i += 1
                continue
            except Todo as e:
                out.append(f"{ind}// TODO(evidence): {tag} op 0x{op:02x}: {e}; raw {rawhex}")
                self.record(i, op, "todo", str(e))
                i += 1
                continue
            try:
                if op in (0xad, 0x9c, 0xd1, 0x33, 0x99, 0xd9, 0x9d, 0xae, 0xaf, 0xb0):
                    i = self.structured(i, op, hi, ind, out, r0)
                    continue
                if op == 0x98:
                    raise Todo("stray jump (else-jump not attached to an if)")
                self.skip_next = 0
                txt = self.stmt_text(i)
            except (Todo, KeyError, IndexError, struct.error) as e:
                del self.refs[r0:]
                out.append(f"{ind}// TODO(evidence): {tag} op 0x{op:02x}: {e if isinstance(e, Todo) else 'operand layout differs from the evidenced form (' + type(e).__name__ + ')'}; raw {rawhex}")
                self.record(i, op, "todo", str(e))
                i += 1
                continue
            self.flush_decls(ind, out, r0, True)
            out.append(ind + txt + self.note())
            if self.post_lines:
                out += self.post_lines
                self.post_lines = []
            st = "ok"
            if self.flag_todo:
                st = "partial"
            elif self.flag_inferred or op not in OBSERVED_STMT:
                st = "inferred"
            self.record(i, op, st, "")
            i += 1
            if self.skip_next:                       # statement consumed as the initialiser of a thread variable declaration
                self.skip_next = 0
                self.record(i, self.code[self.stream[i]], st, "initialiser of the thread-variable declaration")
                i += 1

    def structured(self, i, op, hi, ind, out, r0):
        c = self.code
        pos = self.stream[i]
        a, b, rawhex = self.raw(i)
        tag = f"#{i} @{a}-{b}"
        u = self.u16(pos + 1)
        if not (i <= u <= hi):
            raise Todo(f"jump target stream index {u} outside enclosing range {i}..{hi}")
        if op == 0xd9:
            return self.sel_block(i, u, ind, out, r0)
        # header text; on failure the TODO is emitted and the body is still
        # emitted INDENTED (structure comes from validated jump indices only)
        head = None
        try:
            if op == 0xad:
                cond = self.ex(pos + 3)
                if cond.startswith("(") and self._balanced(cond):
                    cond = cond[1:-1]
                head = f"if({cond})"
            elif op == 0x33:
                fl = c[pos + 3]
                if fl not in (0, 1):
                    raise Todo(f"for flag 0x{fl:02x} not evidenced")
                v = pos + 4
                parts = []
                q = v
                for _ in range(4 if fl else 3):
                    parts.append(self.ex(q))
                    q = self.end(q)
                head = "for " + " ".join(parts)
                self.inferred("", "0x33 = for with step by source correlation (sample10)")
            elif op == 0x99:
                fl = c[pos + 3]
                if fl == 1:
                    head = "err+"                    # u == i: no handler block, u > i: handler block follows
                elif fl == 2 and u == i:
                    head = "err-"
                elif fl == 0 and u > i:
                    head = "err"
                elif fl == 0 and u == i:
                    head = "err"                     # empty handler: System.qml Softly `... -WC h; err`
                    self.inferred("", "err with empty handler block (flag 0, jump == own index); source System.qml Softly, single occurrence")
                else:
                    raise Todo(f"0x99 flag {fl} u16 {u}: only err+/err-/err-block forms evidenced")
            elif op == 0x9d:
                if c[pos + 3] != 0x81:
                    raise Todo(f"foreach flag 0x{c[pos+3]:02x} not evidenced (only 0x81)")
                srcp = pos + 4
                varp = self.end(srcp)
                src = self.ex(srcp)
                head = f"foreach {self.ex(varp)} {src}"
            elif op in (0xae, 0xaf, 0xb0):                 # GROUP L: ifk / iff / ifa (handler 0x420a22: letter byte k/f/a, flags bit7 = '-')
                letter, fl = c[pos + 4], c[pos + 5]
                if c[pos + 3] != 1 or {0xae: 0x6b, 0xaf: 0x66, 0xb0: 0x61}[op] != letter or fl not in (0, 0x80):
                    raise Todo(f"if{chr(letter)} header form not evidenced")
                arg = self.ex(pos + 6)
                if op == 0xae and re.fullmatch(r'-?[0-9]+', arg):
                    arg = "(" + arg + ")"                  # integer operand = virtual-key code / mouse button, source `ifk- (1)` (help IDP_IFK)
                elif op == 0xae and re.fullmatch(r'"[A-Za-z0-9]+"', arg):
                    arg = arg[1:-1]
                    self.inferred("", "ifk key name is stored as a string constant; sample29 source spelled `ifk F2` unquoted")
                head = {0xae: "ifk", 0xaf: "iff", 0xb0: "ifa"}[op] + ("-" if fl & 0x80 else "") + " " + arg
            elif op == 0x9c:
                if c[pos + 3] != 0:
                    raise Todo(f"for with flag byte 0x{c[pos+3]:02x} (only 0 evidenced)")
                v = pos + 4
                f = self.end(v)
                t = self.end(f)
                head = f"for {self.ex(v)} {self.ex(f)} {self.ex(t)}"
            else:
                fl = c[pos + 1 + 2]
                if fl == 1:
                    head = "rep " + self.ex(pos + 4)
                    self.inferred("", "rep N count form (flag 1) by source correlation (sample10)")
                elif fl != 0:
                    raise Todo(f"rep flag 0x{fl:02x}: only flags 0 and 1 evidenced")
                else:
                    head = "rep"
        except Todo as e:
            del self.refs[r0:]
            out.append(f"{ind}// TODO(evidence): {tag} op 0x{op:02x} header: {e}; raw {rawhex}")
            out.append(f"{ind}// (statements below are the enclosed body of the undecodable 0x{op:02x} header; structure from its jump index {u})")
            self.record(i, op, "todo", str(e))
        else:
            self.flush_decls(ind, out, r0)
            out.append(ind + head + self.note())
            self.record(i, op, "inferred" if self.flag_inferred else "ok")
        tlo, thi, elo, ehi = i + 1, u, None, None
        if op in (0xad, 0xae, 0xaf, 0xb0) and u > i and c[self.stream[u]] == 0x98:
            tgt = self.u16(self.stream[u] + 1)
            if u <= tgt <= hi:
                thi, elo, ehi = u - 1, u + 1, tgt
            else:
                out.append(f"{ind}// TODO(evidence): else-jump target {tgt} outside range {i}..{hi}")
        self.emit(tlo, thi, ind + "	", out)
        nxt = u + 1
        if elo is not None:
            # GROUP M: `else if` chain (sample32). The compiler lays it out as  ad(c1) B1 98->T1 | ad(c2) B2 98->T2 | ... | Belse
            # where each 98 targets the LAST statement of the next link's body, i.e. the next link's `ad` jump index is
            # tgt+1 (the 98 of that link). Rendered as `else if(...)` (inferred: `else` + nested `if` is bytewise identical).
            while True:
                e0 = self.stream[elo] if elo <= ehi else None
                if (e0 is not None and self.code[e0] == 0xad and elo < ehi
                        and self.u16(e0 + 1) == ehi + 1 and ehi + 1 < len(self.stream) and self.code[self.stream[ehi + 1]] == 0x98):
                    u2 = ehi + 1
                    tgt2 = self.u16(self.stream[u2] + 1)
                    if not (u2 <= tgt2 <= hi):
                        break
                    r1 = len(self.refs)
                    self.flag_inferred = self.flag_todo = False
                    self.notes = []
                    self.dec.instr(e0, 1)
                    cond = self.ex(e0 + 3)
                    if cond.startswith("(") and self._balanced(cond):
                        cond = cond[1:-1]
                    self.inferred("", "else-if chain: nested ad whose jump index = previous else-jump target + 1 (sample32)")
                    self.flush_decls(ind, out, r1)
                    out.append(f"{ind}else if({cond})" + self.note())
                    self.record(elo, 0xad, "inferred")
                    self.emit(elo + 1, u2 - 1, ind + "	", out)
                    elo, ehi = u2 + 1, tgt2
                    nxt = u2 + 1
                    continue
                break
            out.append(f"{ind}else")
            self.emit(elo, ehi, ind + "	", out)
            nxt = ehi + 1
        return nxt

    def sel_block(self, i, u, ind, out, r0):
        c = self.code
        pos = self.stream[i]
        kind = c[pos + 4]                     # GROUP M: handler 0x420790: 0 = int sel, 1 = string sel, 2 = string sel + flags S
        if kind not in (0, 1, 2):
            raise Todo(f"sel kind byte 0x{kind:02x} not evidenced")
        head = "sel " + self.ex(pos + 5)
        if kind == 2:
            head += " " + self.ex(self.end(pos + 5))
            self.inferred("", "sel string flags S (d9 kind 2): handler 0x420790 evaluates a 2nd S as the compare flags (help IDP_SEL: 1 icase, 2 wildcards); sample32 `sel s 3`")
        self.inferred("", "0xd9 = sel, 0x88 = case by source correlation (sample15)")
        self.flush_decls(ind, out, r0)
        out.append(ind + head + self.note())
        self.record(i, 0xd9, "inferred")
        j = i + 1
        starts = [k for k in range(i + 1, u + 1) if c[self.stream[k]] == 0x88 and c[self.stream[k] + 3] == c[pos + 3]]
        if not starts or starts[0] != i + 1:
            raise Todo("sel body does not start with a case entry")
        for n, k in enumerate(starts):
            p = self.stream[k]
            nv = c[p + 4]
            if self.u16(p + 1) != pos + 1:
                raise Todo("case entry form not evidenced")
            if nv == 0:
                out.append(f"{ind}	case else  /*inferred: 0x88 case entry, n=0*/")
            else:
                vals = []
                for m in range(nv):
                    v = struct.unpack_from("<I", c, p + 5 + 4 * m)[0]
                    if kind:
                        vals.append('"' + self.string_at(v) + '"')
                    else:
                        vals.append(str(struct.unpack_from("<i", c, p + 5 + 4 * m)[0]))
                txt = vals[0] if nv == 1 else "[" + ",".join(vals) + "]"
                note = "0x88 case entry" + (" (string constants = pool offsets)" if kind else "") + ("; list `case [a,b]`: n = number of values (handler 0x420790 loops n x u32)" if nv > 1 else "")
                out.append(f"{ind}	case {txt}  /*inferred: {note}*/")
            self.record(k, 0x88, "inferred")
            nxt = starts[n + 1] - 1 if n + 1 < len(starts) else u
            self.emit(k + 1, nxt, ind + "		", out)
        return u + 1

    def label_name(self, idx):
        self.labels[idx] = f"lab{idx}"
        return self.labels[idx]

    @staticmethod
    def _balanced(s):
        d = 0
        for k, ch in enumerate(s):
            d += ch == "("
            d -= ch == ")"
            if d == 0 and k < len(s) - 1:
                return False
        return d == 0

    def run(self):
        out = []
        for k, p in enumerate(self.stream):
            if self.code[p] == 0xa9 and p + 3 <= len(self.code):
                self.label_name(struct.unpack_from("<h", self.code, p + 1)[0] + 1)
        sig = self.signature()
        self.emit(0, len(self.stream) - 1, "", out)
        if ROUNDTRIP:                                # declared-but-unused locals never reached by the numbering rule: at the end
            out += [self.decl_line(q) for q in sorted(self.unused - self.declared)]
        for rec in self.thread_recs:                 # thread variables declared without initialiser have no statement: hoist
            if rec is not None and rec["k"] not in self.thread_declared:
                ty = self.desc[rec["didx"]][1]
                if ty in self.ltypes and ty in (0, 1, 2, 4, 5, 6):
                    self.hoisted.append(self.ltypes[ty] + ("--" if rec["flags"] & 2 else "-") + " " + rec["name"]
                                        + "  /*inferred: declaration without initialiser compiles to no statement; its position is not stored, hoisted to the function head*/")
        if sig is not None:
            has_val = any(re.match(r"\s*ret\s+\S", l) for l in out)
            sig = sig.replace("function", "function#" if has_val else "function", 1) if not sig.startswith("function^") else sig
            return self.rename([sig] + self.hoisted + out)
        return self.rename(self.hoisted + out)

    def rename(self, lines):
        """names: (1) System.qml strict alignment (inferred), (2) only with --guess-names the remaining locals (guessed)."""
        try:
            sysn = system_names(self)
        except Exception:
            sysn = None
        if sysn:
            lines = apply_names(lines, sysn, NAME_MARK)
            lines = [l.replace("param names not stored", "param names from System.qml") for l in lines]
        if GUESS_NAMES:
            g = guess_names(self, lines)
            g = {i: n for i, n in g.items() if not (sysn and i in sysn)}
            if g:
                lines = apply_names(lines, g, "/*guessed name*/")
        return lines

    def signature(self):
        """GROUP M: parameter list of a #sub (sample31). Block header (b = block offset): u16 at b+0x30 = return type code (0 = int/none,
        5 = double), byte b+0x38 = number of parameters (= the first descriptors), byte b+0x39 = number of required ones (Opt: 2/1)."""
        if self.rec["kind"] != 2:
            return None
        r4, b = self.r4, self.b
        ret, npar, nreq = struct.unpack_from("<H", r4, b + 0x30)[0], r4[b + 0x38], r4[b + 0x39]
        if npar > self.nloc or nreq > npar or ret not in (0, 5):
            return None
        parts = []
        for k in range(npar):
            ty, fl = self.desc[k][1], self.desc[k][2]
            nm = f"loc{k}"
            if ty == 4 and fl == 4:
                nm = f"str&{nm}"
            elif ty in self.ltypes and ty != 0:
                nm = f"{self.ltypes[ty]}'{nm}"
            elif ty != 0:
                return None
            parts.append(("[" + nm + "]") if k >= nreq else nm)
            self.declared.add(k)
        return ("function^ " if ret == 5 else "function ") + " ".join(parts) + "  /*inferred: signature from block header (u16 +0x30 return type 5=double; byte +0x38 params, +0x39 required, sample31); `#` (int return) is shown when the body has `ret value`; param names not stored*/"


def decompile(path: Path):
    """-> (header lines, [(func name, rec, lines, stats)])"""
    recs, names, r4 = load_container(path)
    lay = tile_check.load_layout()
    GLOBALS_USED.clear()
    funcs = []
    for rec, nm in zip(recs, names):
        if rec["kind"] == 7:
            funcs.append((nm, rec, [f"// library stub {nm} (res2 id {rec['id']}, kind 7) - not user code, skipped"], []))
            continue
        fd = FuncDecoder(nm, rec, names, r4, lay)
        fd.names_recs = recs
        try:
            # pass 1 only collects ARRAY element types (arr_elem tails / create selectors seen AFTER the first use);
            # its output is discarded, pass 2 declares with the full knowledge
            pre = FuncDecoder(nm, rec, names, r4, lay)
            pre.names_recs = recs
            try:
                pre.run()
            except Exception:
                pass
            fd.arr_types.update(pre.arr_types)
            fd.explicit_all = set(pre.seen_explicit)
            if ROUNDTRIP:
                fd.unused = pre.unused_locals()
            lines = fd.run()
        except Exception as e:                              # never crash a whole file
            lines = [f"// TODO(evidence): function body not decompiled: {type(e).__name__}: {e}"]
        funcs.append((nm, rec, lines, fd.stats))
    return funcs


HEADER = """// qmdec output for {src}
// Local-variable names are NOT stored in the exe: neutral names loc<i> (i = descriptor index) are used.
// Annotations are trailing `;;` comments (QM syntax): `;;inferred` = semantics inferred only (handler/correlation, not observed);
// `TODO(evidence ...)` = no validated semantics / layout for that opcode, nothing guessed."""


def finalize_comments(lines):
    """Single place where decompiler notes become valid QM comments.
    Internally notes are rendered as /*...*/ tokens (possibly inside nested expressions);
    here every such token outside a string literal is removed and the notes of one line are
    emitted once at its end as `;;note1 | note2`. Full lines starting with // become `;` lines."""
    out = []
    for ln in lines:
        st = ln.lstrip()
        if st.startswith("//"):
            out.append(";" + st[2:])
            continue
        if "/*" not in ln:
            out.append(ln)
            continue
        buf, notes, i, instr = [], [], 0, False
        while i < len(ln):
            c = ln[i]
            if instr:
                buf.append(c)
                if c == '"':
                    instr = False
                i += 1
            elif c == '"':
                instr = True
                buf.append(c)
                i += 1
            elif ln.startswith("/*", i) and ln.find("*/", i + 2) >= 0:
                j = ln.find("*/", i + 2)
                n = " ".join(ln[i + 2:j].split()).replace(";;", ";")
                if n:
                    notes.append(n)
                while buf and buf[-1] in " 	" and (j + 2 >= len(ln) or ln[j + 2] in " 	"):
                    buf.pop()
                i = j + 2
            else:
                buf.append(c)
                i += 1
        body = "".join(buf).rstrip()
        if body.strip():
            out.append(body + ";;" + " | ".join(notes) if notes else body)
        else:
            out.append(";" + " | ".join(notes))
    return out


def main():
    ap = argparse.ArgumentParser(description="QM bytecode decompiler (validated constructs only)")
    ap.add_argument("target", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    ap.add_argument("--guess-names", action="store_true",
                    help="cosmetic local names from type/usage (hwnd/i/s/...), each declaration marked /*guessed name*/ (default: off)")
    ap.add_argument("--roundtrip", action="store_true",
                    help="round-trip mode: declare every local without initialiser at the function head in descriptor order")
    a = ap.parse_args()
    global GUESS_NAMES, ROUNDTRIP
    GUESS_NAMES = a.guess_names
    ROUNDTRIP = a.roundtrip
    if a.target.is_dir() and list(a.target.glob("*.exe")):
        # batch: every exe in the directory -> <output dir>/<name>.qmdec.qml
        od = a.output or a.target
        od.mkdir(parents=True, exist_ok=True)
        for exe in sorted(a.target.glob("*.exe")):
            sys.argv = [sys.argv[0], str(exe), "-o", str(od / (exe.stem + ".qmdec.qml"))] + (["--guess-names"] if GUESS_NAMES else []) + (["--roundtrip"] if ROUNDTRIP else [])
            main()
        return 0
    funcs = decompile(a.target)
    lines = HEADER.format(src=a.target.name).split("\n")
    nst = {"ok": 0, "inferred": 0, "partial": 0, "todo": 0}
    ust = dict(nst)                                  # user code only (macro + its #subs), rest = embedded stdlib
    main_id = next((r["id"] for r, *_ in [(f[1],) for f in funcs] if r["kind"] == 1), None)
    for nm, rec, body, stats in funcs:
        m = re.match(r"<(\d+)>", nm)
        is_user = rec["kind"] == 1 or (m is not None and int(m.group(1)) == main_id)
        for s_ in stats:
            if is_user:
                ust[s_[2]] += 1
        if rec["kind"] != 7:
            lines.append("")
        if rec["kind"] != 7:
            lines.append(f"// ---- function {nm} (res2 id {rec['id']}, kind {rec['kind']}) ----")
        lines += body
        for s in stats:
            nst[s[2]] += 1
    lines.append("")
    lines.append(f"// statements: {nst['ok']} ok, {nst['inferred']} inferred, "
                 f"{nst['partial']} partial, {nst['todo']} TODO")
    lines.append(f"// user code only (macro + its #subs): {ust['ok']} ok, {ust['inferred']} inferred, "
                 f"{ust['partial']} partial, {ust['todo']} TODO")
    if any(re.search(r"\btype_[0-9a-f]+\b", l) for l in lines if not l.lstrip().startswith("//")):
        lines.insert(len(HEADER.format(src=a.target.name).split("\n")),
                     "// NOTE: `type MYT ...` declarations (user type names and member names) are not stored in the exe; "
                     "type_<id> / member names are neutral and the declaration itself cannot be recovered.")
    hl = len(HEADER.format(src=a.target.name).split("\n"))
    if GLOBALS_USED:                                 # GROUP O: hidden globals (res10) referenced by the code; declared once, before the functions
        decl = ["// hidden global variables `int+` / `str+` declared at load (res10 records; their names are NOT stored in the exe: neutral glob<id>);",
                "// the initial value of `int+ g=5` is a plain assignment statement in the code (no separate declaration statement)"]
        for gid, ent in sorted(GLOBALS_USED.items()):
            decl.append(("int+ " if ent["type"] == 0 else "str+ ") + f"glob{gid}  /*observed: res10 record id {gid} size {ent['size']} type {ent['type']} flags {ent['flags']}*/")
        lines[hl:hl] = decl
    if any(re.match(r"(int|str|byte|word|long|double)--? \w", l) for l in lines if not l.lstrip().startswith("//")):
        lines.insert(hl, "// NOTE: thread variables (`int- t`, `int-- t`) keep their real names (string pool, referenced from the 12-byte thread-variable record).")
    if any(NAME_MARK in l for l in lines):
        lines.insert(hl, "// NOTE: names marked `" + NAME_MARK + "` are NOT stored in the exe: they come from System.qml (QM 2.4.12) by strict alignment of the "
                         "declared parameters/locals with this function's descriptor table (equal count, equal types in order).")
    if GUESS_NAMES:
        lines.insert(hl, "// NOTE: --guess-names is ON: names marked /*guessed name*/ are cosmetic guesses from type/usage, not evidence.")
    txt = chr(10).join(finalize_comments(lines)) + chr(10)
    if a.output:
        a.output.write_text(txt, encoding="utf-8")
    else:
        sys.stdout.write(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
