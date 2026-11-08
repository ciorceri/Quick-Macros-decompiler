#!/usr/bin/env python3
"""compare_roundtrip.py - strict bytecode comparer for the decompile -> recompile round trip.

    python compare_roundtrip.py <original.exe> <roundtrip.exe>
    python compare_roundtrip.py --all roundtrip/          (each roundtrip/<n>.exe vs corpus/**/<n>.exe)
    python compare_roundtrip.py --selftest                (validates the comparer itself)

Verdict per pair
  IDENTICAL   every resource (res1..res10) is byte-equal (res1 only after masking its {GUID}).
  EQUIVALENT  the resources differ only by what legitimately differs between two compilations,
              each listed in the report:
                * res1 GUID
                * res2 function ids / function order (functions are matched by res3 name)
                * string-pool offsets: operands of table-1 0x1e (string constant), 0x88 case values of a
                  string `sel` (0xd9 kind 1/2) and the name field of 12-byte thread-variable records are
                  compared by the pooled STRING VALUE; the pool itself as a multiset of strings
                * function-id operands (table-1 0x01 call u16 id at +2, 0x52 method call u16 id after the object,
                  0x49 builtin id at +5) are compared by the NAME the id resolves to in the exe's own res2/res3/res9
  DIFFERENT   anything else (first difference is printed with both byte strings and both decoded forms).
No alpha-renaming of local descriptor indices and no other fuzzy matching is done: a different local
numbering is reported as DIFFERENT.
"""
import argparse, re, struct, sys
from pathlib import Path

import qmdis, qmlayout, qmtool, tile_check

ROOT = Path(__file__).resolve().parent
GUID_RE = re.compile(rb"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")
LAYOUT = None


def layout():
    global LAYOUT
    if LAYOUT is None:
        LAYOUT = tile_check.load_layout()
    return LAYOUT


# ----------------------------------------------------------------------------- loading
class Stmt:
    pass


class Func:
    pass


class Exe:
    def __init__(self, label, res):
        self.label, self.res = label, res
        self.r4 = res[4]
        self.names = [x.decode("latin-1") for x in qmtool.qm_decrypt(res[3]).split(b"\0") if x]
        self.recs = qmtool.parse_bytecode_index(res[2])
        self.tables = qmtool.parse_builtin_tables(res)
        self.glob_rank = {}
        for k, gid in enumerate(sorted(self.tables["globals"])):
            g = self.tables["globals"][gid]
            self.glob_rank[gid] = (k, g["size"], g["type"], g["flags"])
        self.id2name = {}
        for r, nm in zip(self.recs, self.names):
            self.id2name.setdefault(r["id"], nm)
        offs = sorted({r["block_off"] for r in self.recs} | {len(self.r4)})
        self.funcs = {}
        self.order = []
        seen = {}
        for r, nm in zip(self.recs, self.names):
            k = seen.get(nm, 0)
            seen[nm] = k + 1
            key = nm if k == 0 else f"{nm}#{k}"
            nxt = min(o for o in offs if o > r["block_off"])
            self.funcs[key] = self.load_func(key, r, nxt)
            self.order.append(key)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        return cls(path.name, qmtool.parse_pe_resources_named(path.read_bytes())[252])

    def load_func(self, key, rec, blk_end):
        f = Func()
        r4, b = self.r4, rec["block_off"]
        f.key, f.rec, f.b, f.end = key, rec, b, blk_end
        f.block = r4[b:blk_end]
        f.stmts, f.err = [], None
        try:
            f.ptrs = struct.unpack_from("<9I", r4, b)
            loc = qmdis.locate_stream_from_header(r4, b)
            if loc is None:
                raise ValueError("no stream located")
            so, cnt = loc
            f.code = r4[b + 0x48:so]
            f.stream = list(struct.unpack_from("<%dH" % cnt, r4, so))
            f.rel = [x - f.ptrs[0] for x in f.ptrs]
            f.pool_at = b + 0x48 + f.rel[5]
            f.pool = r4[f.pool_at:blk_end]
            f.nloc = struct.unpack_from("<H", r4, b + 0x2a)[0]
            dt = b + 0x48 + f.rel[2]
            f.desc = [struct.unpack_from("<IHBB", r4, dt + 8 * i) for i in range(f.nloc)]
        except Exception as e:
            f.err = f"{type(e).__name__}: {e}"
            return f
        for i in range(len(f.stream)):
            f.stmts.append(self.decode_stmt(f, i))
        return f

    # -- pool / id helpers ---------------------------------------------------
    def pool_str(self, f, off):
        a = f.pool_at + off
        if off < 0 or a >= f.end:
            return None
        z = self.r4.find(b"\0", a, f.end)
        return None if z < 0 else self.r4[a:z]

    def decode_stmt(self, f, i):
        code, stream = f.code, f.stream
        s = Stmt()
        e = stream[i]
        s.start = e
        s.stop = stream[i + 1] if i + 1 < len(stream) else len(code)
        s.stop = max(s.stop, e)
        s.raw = code[e:s.stop]
        s.instrs, s.err = {}, None
        s.norm_notes = 0
        if e >= len(code):
            s.err = "stream entry beyond code"
            s.norm = s.norm_full = tuple(s.raw)
            return s
        d = qmlayout.Decoder(code, layout())
        d.stream = stream
        orig = d.instr

        def rec_instr(pos, table, _o=orig):
            end = _o(pos, table)
            s.instrs[(table, pos)] = end
            return end
        d.instr = rec_instr
        s.dend = None
        try:
            s.dend = d.instr(e, 1)
        except qmlayout.Unresolved as x:
            s.err = str(x)
        except Exception as x:
            s.err = f"{type(x).__name__}: {x}"
        # operand masks: abs pos -> (length, resolved value)
        masks = {}
        for (t, p), end in s.instrs.items():
            if t != 1 or p >= s.stop:
                continue
            op = code[p]
            try:
                if op == 0x1e and p + 5 <= s.stop:
                    v = self.pool_str(f, struct.unpack_from("<I", code, p + 1)[0])
                    if v is not None:
                        masks[p + 1] = (4, ("str", v))
                elif op == 0x88:
                    kind = self.sel_kind(f, i, code[p + 3])
                    nv = code[p + 4]
                    if kind:
                        vals = [self.pool_str(f, struct.unpack_from("<I", code, p + 5 + 4 * m)[0]) for m in range(nv)]
                        if all(v is not None for v in vals):
                            for m, v in enumerate(vals):
                                masks[p + 5 + 4 * m] = (4, ("str", v))
                elif op == 0x01 and p + 4 <= s.stop:
                    fid = struct.unpack_from("<H", code, p + 2)[0]
                    if fid in self.id2name:
                        masks[p + 2] = (2, ("fn", self.id2name[fid]))
                elif op == 0x52 and (1, p + 1) in s.instrs:
                    q = s.instrs[(1, p + 1)] + 1
                    fid = struct.unpack_from("<H", code, q)[0]
                    if q + 2 <= s.stop and fid in self.id2name:
                        masks[q] = (2, ("fn", self.id2name[fid]))
                elif op == 0x54 and p + 3 <= s.stop:
                    # `54 <u16>`: the u16 equals the res2 id of a function in BOTH exes (sample02: 1437 = <00257>Callback in the
                    # original, 1444 in the recompile); compared by the resolved function name only when it resolves
                    fid = struct.unpack_from("<H", code, p + 1)[0]
                    if fid in self.id2name:
                        masks[p + 1] = (2, ("fn", self.id2name[fid]))
                elif op == 0x82 and p + 4 <= s.stop and not code[p + 1] & 0x80:
                    # `82 flag u16`: atend, u16 = res2 function id (QM numbers res2 ids per compile); masked only when it resolves
                    fid = struct.unpack_from("<H", code, p + 2)[0]
                    if fid in self.id2name:
                        masks[p + 2] = (2, ("fn", self.id2name[fid]))
                elif op == 0xbb and p + 8 <= s.stop and code[p + 3] == 0x19:
                    # `bb 00 n 19 <i32 res2 function id> ...` (mac as function, first S = function id)
                    fid = struct.unpack_from("<i", code, p + 4)[0]
                    if fid in self.id2name:
                        masks[p + 4] = (4, ("fn", self.id2name[fid]))
                elif op == 0x20 and p + 3 <= s.stop:
                    # `20 <u16>`: res10 record id of a hidden global; QM allocates global ids per compile -> compared by the
                    # rank of the record in this exe's res10 table (sorted by id) plus its fields; only when the id is in res10
                    gid = struct.unpack_from("<H", code, p + 1)[0]
                    if gid in self.glob_rank:
                        masks[p + 1] = (2, ("gl", self.glob_rank[gid]))
                elif op == 0x49 and p + 7 <= s.stop:
                    fid = struct.unpack_from("<H", code, p + 5)[0]
                    ent = self.tables["ids"].get(fid)
                    if ent is not None:
                        masks[p + 5] = (2, ("bi", ent["name"], ent.get("dll", "")))
            except (struct.error, IndexError):
                pass
        s.masks = masks
        norm, p = [], e
        while p < s.stop:
            if p in masks:
                ln, val = masks[p]
                norm.append(val)
                p += ln
            else:
                norm.append(code[p])
                p += 1
        s.norm_full = tuple(norm)
        # semantic form: only the bytes the layout decoder consumed; <=3 trailing bytes are alignment padding
        # (anything longer, or any decode error, stays in the compared form -> strict)
        dend = s.dend if (s.err is None and s.dend is not None) else s.stop
        dend = min(dend, s.stop)
        if s.stop - dend > 3:
            dend = s.stop
        s.dend_used = dend
        sem, p = [], e
        while p < dend:
            if p in masks:
                ln, val = masks[p]
                sem.append(val)
                p += ln
            else:
                sem.append(code[p])
                p += 1
        s.norm = tuple(sem)
        return s

    def sel_kind(self, f, i, case_id):
        """kind byte of the nearest preceding top-level 0xd9 `sel` with the same id byte (qmdec.sel_block: kind = c[pos+4], id = c[pos+3])"""
        c = f.code
        for k in range(i - 1, -1, -1):
            p = f.stream[k]
            if p + 5 <= len(c) and c[p] == 0xd9 and c[p + 3] == case_id:
                return c[p + 4]
        return 0

    # -- thread record / descriptor helpers ---------------------------------
    def thread_norm(self, f, seg):
        """segment [ptr8, ptr5) as a tuple of records; a 12-byte record is name-normalised ONLY under qmdec's acceptance rule"""
        if len(seg) % 12:
            return ("raw", bytes(seg))
        out = []
        for k in range(len(seg) // 12):
            no, size, b6, b7, didx, fl = struct.unpack_from("<IHBB HH".replace(" ", ""), seg, 12 * k)
            nm = self.pool_str(f, no)
            if (nm is not None and re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]*", nm) and didx < f.nloc
                    and f.desc[didx][2] == 4 and size and fl < 4):
                out.append(("thr", nm, bytes(seg[12 * k + 4:12 * k + 12])))
            else:
                out.append(("raw", bytes(seg[12 * k:12 * k + 12])))
        return tuple(out)


# ----------------------------------------------------------------------------- rendering
def res_norm(e, k, x):
    """res10 compared by rank + fields (ids are per-compile); everything else raw"""
    if k == 10 and x is not None:
        return ("res10", tuple(sorted(e.glob_rank.values())))
    if k == 9 and x is not None:       # res9 ids are per-compile; the 0x49 operands are compared by (name, dll) via the mask
        return ("res9", tuple(sorted((v["name"], v.get("dll") or "", v["dll_index"], v["flag"]) for v in e.tables["ids"].values())))
    return x


def hx(b):
    return " ".join(f"{x:02x}" for x in b)


def show_norm(norm):
    return " ".join(f"{x:02x}" if isinstance(x, int) else ("%s:%r" % (x[0], x[1].decode("latin-1") if isinstance(x[1], bytes) else x[1])) for x in norm)


def render(st, code):
    """decoded form: one line per decoded instruction (own operand bytes; nested instructions as ..), masked operands as values"""
    lines = []
    ins = sorted(st.instrs.items(), key=lambda kv: (kv[0][1], -kv[1]))
    for (t, p), end in ins:
        kids = [(q, qe) for (tq, q), qe in st.instrs.items() if (tq, q) != (t, p) and p < q and qe <= end]
        top = [k for k in kids if not any(o != k and o[0] <= k[0] and k[1] <= o[1] for o in kids)]
        out, q = [], p
        while q < end:
            kid = next((k for k in top if k[0] == q), None)
            if kid:
                out.append("<..>")
                q = kid[1]
            elif q in st.masks:
                ln, val = st.masks[q]
                out.append("%s=%r" % (val[0], val[1].decode("latin-1") if isinstance(val[1], bytes) else val[1:]))
                q += ln
            else:
                out.append(f"{code[q]:02x}")
                q += 1
        lines.append(f"T{t} @{p - st.start} op 0x{code[p]:02x}: " + " ".join(out))
    if st.err:
        lines.append("DECODE ERROR: " + st.err)
    return lines


# ----------------------------------------------------------------------------- comparison
class Result:
    def __init__(self):
        self.diffs, self.notes = [], []

    def diff(self, msg):
        self.diffs.append(msg)

    def note(self, msg):
        if msg not in self.notes:
            self.notes.append(msg)


def stmt_diff_text(fa, fb, i, ea, eb, sem=False):
    a, b = fa.stmts[i], fb.stmts[i]
    la, lb = render(a, fa.code), render(b, fb.code)
    first = next((k for k in range(max(len(la), len(lb)))
                  if (la[k] if k < len(la) else None) != (lb[k] if k < len(lb) else None)), 0)
    return (f"function {fa.key}, statement #{i} (code @{a.start}):\n"
            f"      original  bytes: {hx(a.raw)}\n      roundtrip bytes: {hx(b.raw)}\n"
            f"      original  norm : {show_norm(a.norm)}\n      roundtrip norm : {show_norm(b.norm)}\n"
            f"      first differing decoded instruction:\n"
            f"        original : {la[first] if first < len(la) else '(none)'}\n"
            f"        roundtrip: {lb[first] if first < len(lb) else '(none)'}")


def first_byte_diff(x, y):
    n = min(len(x), len(y))
    k = next((j for j in range(n) if x[j] != y[j]), n)
    return k


def seg_bounds(f):
    """segments of the block after the 0x48 header, split at the header pointers (relative to ptr0 = code start)"""
    bl = f.end - f.b - 0x48
    cuts = sorted({x for x in f.rel if 0 <= x <= bl} | {0, bl})
    return list(zip(cuts, cuts[1:]))


def cmp_func(ea, eb, fa, fb, res):
    nm = fa.key
    if fa.err or fb.err:
        if fa.err != fb.err or fa.block != fb.block:
            res.diff(f"function {nm}: block not decodable ({fa.err} / {fb.err}) and bytes differ")
        return
    ra, rb = fa.rec, fb.rec
    for k in ("kind", "flags", "flags2", "blob_off"):
        if ra[k] != rb[k]:
            res.diff(f"function {nm}: res2 {k} {ra[k]} != {rb[k]}")
    if ra["id"] != rb["id"]:
        res.note(f"res2 function ids differ (matched by res3 name; e.g. {nm}: {ra['id']} -> {rb['id']})")
    if fa.rel != fb.rel:
        res.diff(f"function {nm}: header section pointers (relative) differ: {fa.rel} vs {fb.rel}")
        return
    ha, hb = fa.block[0x24:0x48], fb.block[0x24:0x48]
    if ha != hb:
        k = first_byte_diff(ha, hb)
        res.diff(f"function {nm}: header byte +0x{0x24 + k:02x} differs: orig {hx(ha)} | new {hx(hb)}")
    # code: statements
    if len(fa.stream) != len(fb.stream):
        res.diff(f"function {nm}: statement count {len(fa.stream)} != {len(fb.stream)}")
    if fa.stream != fb.stream:
        res.diff(f"function {nm}: instruction stream (statement start offsets) differ: {fa.stream} vs {fb.stream}")
    for i in range(min(len(fa.stmts), len(fb.stmts))):
        a, b = fa.stmts[i], fb.stmts[i]
        if a.norm_full != b.norm_full:
            res.diff(stmt_diff_text(fa, fb, i, ea, eb))
            break
        if a.raw != b.raw:
            res.note("string-pool offsets / function-id operands compared by resolved value (raw operand bytes differ)")
    if fa.code[:fa.stream[0] if fa.stream else len(fa.code)] != fb.code[:fb.stream[0] if fb.stream else len(fb.code)]:
        res.diff(f"function {nm}: code bytes before the first statement differ")
    if len(fa.code) != len(fb.code):
        res.diff(f"function {nm}: code length {len(fa.code)} != {len(fb.code)}")
    # other segments
    ba, bb = seg_bounds(fa), seg_bounds(fb)
    p5, p8 = fa.rel[5], fa.rel[8]
    base_a, base_b = fa.b + 0x48, fb.b + 0x48
    for (s0, s1) in ba:
        if s0 == 0:                                     # code (handled above)
            continue
        if s0 >= p5:                                    # string pool, compared as a multiset of strings
            pa = sorted(x for x in fa.block[0x48 + s0:].split(b"\0") if x)
            sb = next((x for x in bb if x[0] == s0), None)
            pb = sorted(x for x in fb.block[0x48 + s0:].split(b"\0") if x) if sb else None
            if pa != pb:
                res.diff(f"function {nm}: string pool contents differ: {pa[:6]} vs {pb[:6] if pb else None}")
            elif fa.block[0x48 + s0:] != fb.block[0x48 + s0:]:
                res.note("string pool bytes / order / padding differ (same strings)")
            continue
        sa_ = fa.block[0x48 + s0:0x48 + s1]
        sb_ = fb.block[0x48 + s0:0x48 + s1]
        if s0 == p8 and s1 == p5 and sa_ != sb_:
            ta, tb = ea.thread_norm(fa, sa_), eb.thread_norm(fb, sb_)
            if ta != tb:
                res.diff(f"function {nm}: thread-variable records differ: {ta} vs {tb}")
            else:
                res.note("thread-variable record name offsets compared by pooled name")
            continue
        if sa_ != sb_:
            k = first_byte_diff(sa_, sb_)
            res.diff(f"function {nm}: block segment +0x{0x48 + s0:x}..0x{0x48 + s1:x} differs at +{k}: "
                     f"orig {hx(sa_[max(0, k - 8):k + 16])} | new {hx(sb_[max(0, k - 8):k + 16])}")
    # last block segment ends at the pool: compare tail beyond when no segment >= p5 exists
    if not any(s0 >= p5 for s0, _ in ba) and fa.block != fb.block:
        res.diff(f"function {nm}: block bytes differ")


def cmp_func_sem(ea, eb, fa, fb):
    """LEVEL A for one function: returns None or a text with the first semantic difference"""
    nm = fa.key
    if fa.err or fb.err:
        if fa.err != fb.err or fa.block != fb.block:
            return f"function {nm}: block not decodable ({fa.err} / {fb.err}) and bytes differ"
        return None
    ra, rb = fa.rec, fb.rec
    for k in ("kind", "flags", "flags2"):
        if ra[k] != rb[k]:
            return f"function {nm}: res2 {k} {ra[k]} != {rb[k]}"
    if fa.nloc != fb.nloc or fa.desc != fb.desc:
        k = next((j for j in range(min(fa.nloc, fb.nloc)) if fa.desc[j] != fb.desc[j]), None)
        return (f"function {nm}: local descriptor table differs ({fa.nloc} vs {fb.nloc} entries"
                + (f"; first at index {k}: orig {fa.desc[k]} new {fb.desc[k]})" if k is not None else ")"))
    if len(fa.stmts) != len(fb.stmts):
        return f"function {nm}: statement count {len(fa.stmts)} != {len(fb.stmts)}"
    for i in range(len(fa.stmts)):
        if fa.stmts[i].norm != fb.stmts[i].norm:
            return stmt_diff_text(fa, fb, i, ea, eb, sem=True)
    sa, sb = fa.block[0x48 + fa.rel[8]:0x48 + fa.rel[5]], fb.block[0x48 + fb.rel[8]:0x48 + fb.rel[5]]
    if ea.thread_norm(fa, sa) != eb.thread_norm(fb, sb):
        return f"function {nm}: thread-variable records differ: {ea.thread_norm(fa, sa)} vs {eb.thread_norm(fb, sb)}"
    return None


def semantic(ea, eb):
    """LEVEL A. returns (verdict, first_difference_text, notes)"""
    notes = []
    if sorted(ea.names) != sorted(eb.names):
        return ("SEMANTICALLY DIFFERENT",
                f"function name sets differ: only original {sorted(set(ea.names) - set(eb.names))[:6]}, "
                f"only roundtrip {sorted(set(eb.names) - set(ea.names))[:6]}", notes)
    for key in ea.order:
        if key not in eb.funcs:
            return "SEMANTICALLY DIFFERENT", f"function {key} missing in roundtrip", notes
        d = cmp_func_sem(ea, eb, ea.funcs[key], eb.funcs[key])
        if d:
            return "SEMANTICALLY DIFFERENT", d, notes
    for k in sorted(set(ea.res) | set(eb.res)):
        if k in (2, 3, 4):
            continue
        x, y = ea.res.get(k), eb.res.get(k)
        if k == 1 and x is not None and y is not None:
            x, y = GUID_RE.sub(b"{GUID}", x), GUID_RE.sub(b"{GUID}", y)
        if k in (9, 10):
            if res_norm(ea, k, x) != res_norm(eb, k, y):
                return ("SEMANTICALLY DIFFERENT", f"res{k} tables differ after id normalisation", notes)
            continue
        if x != y:
            j = first_byte_diff(x or b"", y or b"")
            return ("SEMANTICALLY DIFFERENT",
                    f"res{k} differs at byte {j} (len {len(x or b'')} vs {len(y or b'')}): "
                    f"orig {hx((x or b'')[max(0, j - 8):j + 16])} | new {hx((y or b'')[max(0, j - 8):j + 16])}"
                    " (not proven non-semantic)", notes)
    return "SEMANTICALLY IDENTICAL", None, notes


def compare(ea, eb):
    res = Result()
    # resource-level raw equality
    keys = sorted(set(ea.res) | set(eb.res))
    raw_equal = True
    for k in keys:
        x, y = ea.res.get(k), eb.res.get(k)
        if k == 1 and x is not None and y is not None:
            gx, gy = GUID_RE.findall(x), GUID_RE.findall(y)
            if gx != gy:
                res.note("res1 GUID differs")
            x, y = GUID_RE.sub(b"{GUID}", x), GUID_RE.sub(b"{GUID}", y)
        if x != y:
            raw_equal = False
    if raw_equal:
        return "IDENTICAL", res
    # structured comparison
    if ea.names != eb.names:
        if sorted(ea.names) == sorted(eb.names):
            res.note("function order in res2/res3 differs (matched by name)")
        else:
            res.diff(f"function name sets differ: only original {sorted(set(ea.names) - set(eb.names))[:6]}, "
                     f"only roundtrip {sorted(set(eb.names) - set(ea.names))[:6]}")
    for key in ea.order:
        if key in eb.funcs:
            cmp_func(ea, eb, ea.funcs[key], eb.funcs[key], res)
    for k in sorted(set(ea.res) | set(eb.res)):
        if k in (2, 3, 4):
            continue
        x, y = ea.res.get(k), eb.res.get(k)
        if k == 1 and x is not None and y is not None:
            x, y = GUID_RE.sub(b"{GUID}", x), GUID_RE.sub(b"{GUID}", y)
        if k in (9, 10):
            if res_norm(ea, k, x) != res_norm(eb, k, y):
                res.diff(f"res{k} tables differ after id normalisation")
            continue
        if x != y:
            j = first_byte_diff(x or b"", y or b"")
            res.diff(f"res{k} differs at byte {j} (len {len(x or b'')} vs {len(y or b'')}): "
                     f"orig {hx((x or b'')[max(0, j - 8):j + 16])} | new {hx((y or b'')[max(0, j - 8):j + 16])}")
    if res.diffs:
        return "DIFFERENT", res
    res.note("no unexplained difference: all functions equal after the normalisations listed")
    return "EQUIVALENT", res


def report(label, ea, eb, verbose=True):
    sv, sd, sn = semantic(ea, eb)
    bv, br = compare(ea, eb)
    print(f"{label}: LEVEL A {sv}   | LEVEL B binary layout: {bv}")
    if verbose:
        if sd:
            print("    first semantic difference:", sd)
        if sv.endswith("IDENTICAL") and bv == "DIFFERENT":
            print("    level B differs but is not decisive; non-semantic candidates (string-pool order/offsets, section sizes/pointers):")
            for d in br.diffs[:3]:
                print("      B:", d.split(chr(10))[0][:230])
            if len(br.diffs) > 3:
                print(f"      (+{len(br.diffs) - 3} more)")
        for n in br.notes:
            print("    note:", n)
    return sv, bv


# ----------------------------------------------------------------------------- modes
CORPUS = None            # set from --corpus


def originals():
    """{stem: path} of the sample exes found in the corpus (see qmcorpus.py)."""
    import qmcorpus
    return {p.stem: p for p in qmcorpus.find_exes(CORPUS) if p.stem.startswith("sample")}


def selftest():
    org = originals()
    names = list(org)
    exes = {n: Exe.from_file(p) for n, p in org.items()}
    bad = 0
    for i, n in enumerate(names):
        v, _ = compare(exes[n], exes[n])
        other = names[(i + 1) % len(names)]
        v2, r2 = compare(exes[n], exes[other])
        # mutation: flip the low bit of the first int constant (0x19 / 0x1b) of the macro; must be DIFFERENT and located
        v3 = "n/a"
        mut = dict(exes[n].res)
        f0 = exes[n].funcs[exes[n].order[0]]
        for st in f0.stmts:
            q = next((p for (t, p) in st.instrs if t == 1 and f0.code[p] in (0x19, 0x1b)), None)
            if q is not None:
                r4 = bytearray(mut[4])
                r4[f0.b + 0x48 + q + 1] ^= 0x01
                mut[4] = bytes(r4)
                v3, r3 = compare(exes[n], Exe(n + "+mut", mut))
                break
        # padding mutation: flip trailing alignment bytes (after the decoder-consumed end) of every statement
        v4 = "n/a"
        pm = dict(exes[n].res)
        r4 = bytearray(pm[4])
        npad = 0
        for fk in exes[n].order:
            f = exes[n].funcs[fk]
            for st in f.stmts:
                if st.err is None and st.dend is not None and 0 < st.stop - st.dend <= 3:
                    for q in range(st.dend, st.stop):
                        r4[f.b + 0x48 + q] ^= 0xA5
                        npad += 1
        if npad:
            pm[4] = bytes(r4)
            v4 = semantic(exes[n], Exe(n + "+pad", pm))[0]
        v5 = v6 = "n/a"
        # mutation: a function-id operand (0x82 / 0x54 / 0x01) -> id of ANOTHER valid function (different name) must be DIFFERENT
        e0 = exes[n]
        for fk in e0.order:
            f = e0.funcs[fk]
            hit = None
            for st in f.stmts:
                for (t, p) in st.instrs:
                    if t == 1 and (p + 1) in st.masks or (t == 1 and (p + 2) in st.masks and st.masks[p + 2][1][0] == "fn"):
                        for off in (p + 1, p + 2):
                            if off in st.masks and st.masks[off][0] == 2 and st.masks[off][1][0] == "fn":
                                hit = off
                                break
                    if hit:
                        break
                if hit:
                    break
            if hit:
                cur = struct.unpack_from("<H", f.code, hit)[0]
                oth = next((i for i, nm in e0.id2name.items() if nm != e0.id2name[cur]), None)
                if oth is not None:
                    pm5 = dict(e0.res)
                    r4 = bytearray(pm5[4])
                    struct.pack_into("<H", r4, f.b + 0x48 + hit, oth)
                    pm5[4] = bytes(r4)
                    v5 = semantic(e0, Exe(n + "+fid", pm5))[0]
                break
        # mutation: a global id -> id of a record with different type/size must be DIFFERENT
        gl = e0.tables["globals"]
        for fk in e0.order:
            f = e0.funcs[fk]
            hit = next((p + 1 for st in f.stmts for (t, p) in st.instrs if t == 1 and f.code[p] == 0x20 and (p + 1) in st.masks), None)
            if hit is None:
                continue
            cur = struct.unpack_from("<H", f.code, hit)[0]
            oth = next((g for g, r in gl.items() if (r["size"], r["type"]) != (gl[cur]["size"], gl[cur]["type"])), None)
            if oth is not None:
                pm6 = dict(e0.res)
                r4 = bytearray(pm6[4])
                struct.pack_into("<H", r4, f.b + 0x48 + hit, oth)
                pm6[4] = bytes(r4)
                v6 = semantic(e0, Exe(n + "+gid", pm6))[0]
            break
        ok = (v5 in ("SEMANTICALLY DIFFERENT", "n/a") and v6 in ("SEMANTICALLY DIFFERENT", "n/a")
              and v == "IDENTICAL" and v2 == "DIFFERENT" and v3 in ("DIFFERENT", "n/a")
              and semantic(exes[n], exes[n])[0] == "SEMANTICALLY IDENTICAL"
              and semantic(exes[n], exes[other])[0] == "SEMANTICALLY DIFFERENT"
              and (v3 == "n/a" or semantic(exes[n], Exe(n + "+mut", mut))[0] == "SEMANTICALLY DIFFERENT")
              and v4 in ("SEMANTICALLY IDENTICAL", "n/a"))
        bad += not ok
        print(f"{'PASS' if ok else 'FAIL'} {n}: self={v}; vs {other}={v2}; 1-byte mutation={v3}; padding mutation({npad} bytes)={v4}; fid mut={v5}; gid mut={v6}")
    print(f"selftest: {len(names) - bad}/{len(names)} PASS")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("original", nargs="?", type=Path)
    ap.add_argument("roundtrip", nargs="?", type=Path)
    ap.add_argument("--all", type=Path, metavar="DIR")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--corpus", help="directory holding the original sample exes (default ./corpus or $QM_CORPUS)")
    a = ap.parse_args()
    global CORPUS
    CORPUS = a.corpus
    if a.selftest:
        return selftest()
    if a.all:
        org = originals()
        counts = {}
        for p in sorted(a.all.glob("*.exe")):
            if p.stem not in org:
                print(f"{p.name}: no original sample of that name")
                continue
            sv, bv = report(p.stem, Exe.from_file(org[p.stem]), Exe.from_file(p))
            counts[sv] = counts.get(sv, 0) + 1
        print("summary:", counts)
        return 0
    if not (a.original and a.roundtrip):
        ap.error("need <original.exe> <roundtrip.exe>, --all DIR or --selftest")
    sv, bv = report(a.roundtrip.stem, Exe.from_file(a.original), Exe.from_file(a.roundtrip))
    return 0 if sv == "SEMANTICALLY IDENTICAL" else 1


if __name__ == "__main__":
    sys.exit(main())
