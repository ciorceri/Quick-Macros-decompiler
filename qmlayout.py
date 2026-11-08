#!/usr/bin/env python3
"""qmlayout.py - exact recursive decoder for QM bytecode, built from the
handler layouts derived by handler_layout.py (REA-verified handler bytes).

Model (verified against the runtime, see docs/research-log.md "Level 2 full
re-validation"):

  * Two dispatch tables per runtime. TABLE 1 (expression/statement
    instructions, 86 handlers 0x00-0x55) and TABLE 2 (binary-operator /
    block-continuation instructions, handlers 0x00-0x4e and 0x54-0x8e).
  * Layout tokens:   B(n)  n raw bytes (opcode byte included)
                     S     one nested TABLE-1 instruction (a dispatch point)
                     T2    one TABLE-2 instruction (operator byte + its own
                           layout; a dispatch point)
  * Every dispatched instruction start is a "start". The compiler's
    uint16 instruction stream lists exactly those starts, which gives a
    falsifiable check of the layouts against real bytecode:
        decoded starts  ==  stream entries.

Usage as a library: decode_function(code, stream) -> result dict.
"""

from __future__ import annotations

import struct

# --- TABLE 1 layouts: opcode -> list of tokens ------------------------------
# tokens: int n = B(n); "S"; "T2"; "BLOCK"; "CALLARGS"; None = unresolved
T1 = {
    0x00: [1],
    0x01: [4],
    0x02: [7],
    0x03: ["BLOCK"],
    0x04: [1, "S"],
    0x05: [1, "S"],
    0x06: [1, "S"],
    0x07: [1, "S"],
    0x08: [1, "S"],
    0x09: [1, "S"],
    0x0A: [1, "S"],
    0x0B: [1, "S"],
    0x0C: [1, "S"],
    0x0D: [1, "S"],
    0x0E: [1, "S"],
    0x0F: [1, "S"],
    0x10: [1, "S"],
    0x11: [1, "S"],
    0x12: [1, "S", 4],
    0x13: [1, "S", 2],
    0x14: [1, "S", 4],
    0x15: [1, "S", 2],
    0x16: [1, "S", "S", 2],
    0x17: [1, "S", "S"],
    0x18: [1, "S", "S", 2],
    0x19: [5],
    0x1A: [5],
    0x1B: [2],
    0x1C: [9],
    0x1D: [9],
    0x1E: [5],
    0x1F: [3],
    0x20: [3],
    0x21: [3],
    0x22: [3],
    0x23: [1, "S", "S"],
    0x24: [1, "S", "S"],
    0x25: [1, "S", "S"],
    0x26: [1, "S", "S"],
    0x27: [1, "S", "S"],
    0x28: [1, "S", "S"],
    0x29: [1, "S", "S"],
    0x2A: [1, "S", "T2"],
    0x2B: [1, "S", "T2"],
    0x2C: [1, "S", "T2"],
    0x2D: [1, "S", "T2"],
    0x2E: [1, "S", "T2"],
    0x2F: [1, "S", "T2"],
    0x30: [1, "S"],
    0x34: [1, "S", "S"],
    0x33: ["FOR"],
    0x37: [1, "S", 1],
    0x38: [3, "S"],
    0x3C: [1, "S", "S", 2],
    0x3D: [1, "S", "S", 2],
    0x3E: [1, "S", "S"],
    0x3F: [2, "S"],
    0x40: [1, "S"],
    0x41: [1, "S"],
    0x42: [1, "S"],
    0x43: [3, "S"],
    0x44: [1, "S"],
    0x45: [1, "S"],
    0x46: [1, "S"],
    0x4A: [3, "S"],
    0x4C: [5],
    0x4D: [5],
    0x4E: [3],
    0x4F: [3],
    0x50: [3],
    0x52: [1, "S"],
    0x54: [3],
    0x55: [3],
}

# --- TABLE 2 layouts --------------------------------------------------------
T2_BINOP = set(list(range(0x00, 0x39)))  # op byte + RHS sub-expression
T2_TYPED = set(range(0x39, 0x4C))  # op byte + type byte + RHS


# --- groupC extension: table-2 layout overrides (key "t2:0xNN" in the json) ---
T2_EXTRA: dict = {}


def t2_layout(op: int) -> list[int | str] | None:
    """Returns the layout list of a table-2 opcode.

    Args:
      op: The table-2 opcode.

    Returns:
      The layout token list, or None when the layout is unknown.
    """
    if op in T2_EXTRA:  # groupC extension (explicit wins)
        return T2_EXTRA[op]
    if op in T2_BINOP:
        return [1, "S"]
    if op in T2_TYPED:
        return [2, "S"]
    return None


# ---- GROUP A ADDITION: layouts for the 0x461578 table used by opcode 0x37 ----
# key = byte read by 0x37 after its S operand (table-2 key = byte + 0x50)
T3 = {
    0x05: [
        1,
        1,
        "S",
        "SZ",
        # key 0x55 @0x4243a0 -> 0x423f9c(.,0): opbyte, b, S, S* until 0x00, 0x00
    ],
    0x06: [1, 1, "S", "SZ"],  # key 0x56 @0x4243ae -> 0x423f9c(.,1): same bytes
    0x10: [1, 1, "ARGS"],  # key 0x60 @0x424ab1: opbyte, b, n, n x S
    0x14: [
        1,
        "ARGS",
    ],  # key 0x64 @0x4238d1: opbyte, n, n x S   (helper 0x40b033)
    # keys 0x84-0x89 @0x4241b5: opbyte, flag b, count e, S, [b&4: S, e-=1],
    # [e>1: S]
    0x34: [1, "FLAGCNT"],
    0x35: [1, "FLAGCNT"],
    0x36: [1, "FLAGCNT"],
    0x37: [1, "FLAGCNT"],
    0x38: [1, "FLAGCNT"],
    0x39: [1, "FLAGCNT"],
    0x17: [
        1,
        "ARGS",
    ],  # key 0x67 @0x4239bf: opbyte, n, n x S   (helper 0x40b033)
    0x29: [1, "ARGS"],  # key 0x79 @0x423d90: opbyte, n(<=3), n x S
    0x3C: [
        1,
        "ARGS",
    ],  # key 0x8c @0x423785: opbyte, n, n x S   (helper 0x40b033)
}


class Unresolved(Exception):
    """Raised when an instruction layout cannot be determined."""

    pass


class Decoder:
    """Walks QM bytecode and computes instruction extents from layouts.

    Attributes:
      code: The bytecode buffer being decoded.
      t1: Table-1 layout map (opcode to layout token list).
      starts: Offsets of every instruction start decoded so far.
      unresolved: Count of unresolved opcodes keyed by (table, opcode).
      opcount: Count of decoded opcodes keyed by (table, opcode).
      stream: Optional list of instruction start offsets (set by callers;
        used to type the selector of a 0x88 case-else).
    """

    def __init__(self, code: bytes, t1: dict[int, list] = T1) -> None:
        """Initializes the decoder over a code buffer.

        Args:
          code: The bytecode of one function.
          t1: Table-1 layout map to use.
        """
        self.code = code
        self.t1 = t1
        self.starts: list[int] = []
        self.unresolved: dict[tuple[int, int], int] = {}
        self.opcount: dict[tuple[int, int], int] = {}
        # GROUP M: optional stream list (needed to type the sel of a 0x88
        # case-else)
        self.stream = None

    def need(self, pos: int, n: int = 1) -> None:
        """Raises Unresolved if n bytes at pos overrun the code.

        Args:
          pos: Offset of the first byte needed.
          n: Number of bytes needed.

        Raises:
          Unresolved: If pos + n is past the end of the code.
        """
        if pos + n > len(self.code):
            raise Unresolved(f"overrun at {pos}")

    def instr(self, pos: int, table: int) -> int:
        """Decode one instruction at pos; return end offset.

        Args:
          pos: Offset of the instruction's opcode byte.
          table: Dispatch table to use (1 or 2).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the layout is unknown or the code is truncated.
        """
        self.need(pos)
        self._depth = getattr(self, "_depth", 0) + 1
        try:
            return self._instr(pos, table)
        finally:
            self._depth -= 1

    def _instr(self, pos: int, table: int) -> int:
        """Decodes one instruction at pos and returns the next offset.

        Args:
          pos: Offset of the instruction's opcode byte.
          table: Dispatch table to use (1 or 2).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the layout is unknown or nesting is too deep.
        """
        if self._depth > 40:
            raise Unresolved("nesting too deep")
        op = self.code[pos]
        self.starts.append(pos)
        key = (table, op)
        self.opcount[key] = self.opcount.get(key, 0) + 1
        lay = self.t1.get(op) if table == 1 else t2_layout(op)
        if lay is None:
            self.unresolved[key] = self.unresolved.get(key, 0) + 1
            raise Unresolved(
                f"table{table} op 0x{op:02x} layout unknown at {pos}"
            )
        p = pos
        for tok in lay:
            if isinstance(tok, int):
                self.need(p, tok)
                p += tok
            elif tok == "S":
                p = self.instr(p, 1)
            elif tok == "T2":
                p = self.instr(p, 2)
            elif tok == "BLOCK":
                # 03 <u16 len> <S> <T2>* <type><flags>; total = len + 3
                self.need(p, 3)
                (ln,) = struct.unpack_from("<H", self.code, p + 1)
                end = p + 1 + ln
                p += 3
                p = self.instr(p, 1)
                while p < end:
                    p = self.instr(p, 2)
                self.need(end, 2)
                p = end + 2
            elif tok == "FOR":
                # 33 <u16 label> <flag> S S S [S]  (flag bit0 = step present)
                self.need(p, 4)
                flag = self.code[p + 3]
                p += 4
                for _ in range(4 if flag & 1 else 3):
                    p = self.instr(p, 1)
            elif isinstance(tok, list):
                # --- groupB extension (new token kinds; existing behaviour
                # unchanged) ---
                p = self._cond(pos, p, tok)
            # ---- GROUP A ADDITIONS (new token kinds; existing behaviour
            # unchanged) ----
            elif tok == "ARGS":
                # count byte n, then n x S           (helper 0x40b033 /
                # 0x40b07c)
                self.need(p, 1)
                n = self.code[p]
                p += 1
                for _ in range(n):
                    p = self.instr(p, 1)
            elif tok == "ARGN":
                # n = count byte located 3 bytes before p (layout [..,3,"ARGN"]
                # /
                # [4,"ARGN"]: op/n/word-id header); n x ARG (helpers
                # 0x429ab0/0x4299f8)
                n = self.code[p - 3]
                for _ in range(n):
                    p = self._arg(p)
            elif tok == "OP3A":
                # 0x3a tail after [op, a, b, S]; a=code[p_start+1],
                # b=code[p_start+2]
                # handler 0x4161ef (see report): sel byte only for a<=4
                a, b = self.code[pos + 1], self.code[pos + 2]
                nS = 0
                if a <= 4:
                    self.need(p, 1)
                    sel = self.code[p]
                    p += 1
                    if sel in (0x00, 0x24):
                        p += 2
                    if a == 0:
                        nS = 1
                    elif a == 1:
                        nS = b
                    elif a == 2:
                        nS = 2 * (b // 2)
                    elif a == 3:
                        nS = 0 if b == 0 else (2 if b > 1 else 1)
                    else:
                        nS = 0 if b == 0 else 1
                elif a == 5:
                    nS = 1
                elif a in (8, 9, 10):
                    nS = 1 if b else 0
                elif a == 12:
                    p += 1
                    nS = min(b, 3)
                for _ in range(nS):
                    p = self.instr(p, 1)
            elif tok == "OP3F":
                # 0x3f tail after [op, type, S]: second S dispatched inside
                # 0x413cd0, then a
                # type-dependent tail. Evidenced types only: 0x13 -> S + word;
                # 0x0d -> S.
                ty = self.code[pos + 1]
                if ty not in (
                    0x13,
                    0x0D,
                    0x0F,
                ):
                    # GROUP M: 0x0f (BSTR) -> S (handler 0x4142c8: helper
                    # 0x424906 dispatches it; sample33 `BSTR b="bstr"`)
                    self.unresolved[(0x3F, ty)] = (
                        self.unresolved.get((0x3F, ty), 0) + 1
                    )
                    raise Unresolved(f"0x3f type 0x{ty:02x} unresolved at {p}")
                p = self.instr(p, 1)
                if ty == 0x13:
                    p += 2
            elif tok == "OP31":
                # 0x31 tail after [op, S]: t, c, then kind-dependent S list.
                # Only kind 0x0f is evidenced (1 S); others unresolved.
                self.need(p, 2)
                kind = self.code[p] & 0x1F
                p += 2
                if kind == 0x0F:
                    p = self.instr(p, 1)
                else:
                    self.unresolved[(31, kind)] = (
                        self.unresolved.get((31, kind), 0) + 1
                    )
                    raise Unresolved(
                        f"0x31 kind 0x{kind:02x} unresolved at {p}"
                    )
            elif tok == "T3":
                # table at 0x461578 (= TABLE-2 key byte+0x50), used by 0x37
                self.need(p, 1)
                lay3 = T3.get(self.code[p])
                if lay3 is None:
                    self.unresolved[(3, self.code[p])] = (
                        self.unresolved.get((3, self.code[p]), 0) + 1
                    )
                    raise Unresolved(
                        f"table3 op 0x{self.code[p]:02x} layout unknown at {p}"
                    )
                for t3 in lay3:
                    if isinstance(t3, int):
                        self.need(p, t3)
                        p += t3
                    elif t3 == "ARGS":
                        self.need(p, 1)
                        n = self.code[p]
                        p += 1
                        for _ in range(n):
                            p = self.instr(p, 1)
                    elif t3 == "S":
                        p = self.instr(p, 1)
                    elif t3 == "FLAGCNT":
                        self.need(p, 2)
                        fb, e = self.code[p], self.code[p + 1]
                        p = self.instr(p + 2, 1)
                        if fb & 4:
                            p = self.instr(p, 1)
                            e -= 1
                        if e > 1:
                            p = self.instr(p, 1)
                    elif (
                        t3 == "SZ"
                    ):  # S repeated while next byte != 0, then 0 terminator
                        while True:
                            self.need(p, 1)
                            if self.code[p] == 0:
                                p += 1
                                break
                            p = self.instr(p, 1)
                    else:
                        raise Unresolved(f"bad T3 token {t3}")
            # ---- END GROUP A ADDITIONS ----
            elif isinstance(tok, str) and tok.startswith("X_"):
                # --- groupC extension (variable-length handlers); see
                # analysis/layout_overrides_groupC.json. Existing tokens above
                # are unchanged. `pos` = opcode byte offset, p = current offset.
                p = self._ext(tok, pos, p)
            else:
                raise Unresolved(f"bad token {tok}")
        return p

    def _instr_t2_at(self, pos: int, op: int) -> int:
        """Decodes a table-2 handler whose operator byte was already read.

        Decode table-2 handler `op` whose operator byte was already consumed
        (pos = first byte after it). Layout tokens count the op byte as 1 byte,
        so shift back by one: the byte before pos is the (relative) index.

        Args:
          pos: Offset of the first byte after the operator byte.
          op: The table-2 opcode.

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the layout is unknown.
        """
        lay = t2_layout(op)
        key = (2, op)
        self.opcount[key] = self.opcount.get(key, 0) + 1
        if lay is None:
            self.unresolved[key] = self.unresolved.get(key, 0) + 1
            raise Unresolved(
                f"table2 op 0x{op:02x} (via 0x37) layout unknown at {pos}"
            )
        p = pos - 1
        for tok in lay:
            if isinstance(tok, int):
                p += tok
            elif tok == "S":
                p = self.instr(p, 1)
            elif tok == "T2":
                p = self.instr(p, 2)
            elif isinstance(tok, str) and tok.startswith("X_"):
                p = self._ext(tok, p if False else pos - 1, p)
            else:
                raise Unresolved(f"bad token {tok} in t2 via 0x37")
        return p

    # ---- groupC extension tokens (handler-derived, see discoveries R-groupC)
    # --
    def _ext(self, tok: str, pos: int, p: int) -> int:
        """Handles extension tokens; returns the next offset.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        if tok == "X_ARGC4":  # 0x49: N = code[pos+4] sub-expressions
            for _ in range(byte(pos + 4)):
                p = self.instr(p, 1)
            return p
        if tok == "X_C9":  # 0xc9: [flag] ; flag&2 ? cnt S S* 00 : S
            fl = byte(pos + 1)
            if fl & 0x80:
                return p
            if fl & 2:
                p += 1  # count byte (alloca size only)
                p = self.instr(p, 1)  # first S (0x40afc7)
                while byte(p) != 0:
                    p = self.instr(p, 1)
                return p + 1  # terminating 0
            return self.instr(p, 1)
        if tok == "X_47":
            # 0x47: 47 b1 b2 b3 argc flags ; see handler 0x415a3d
            fl = byte(pos + 5)
            if not fl & 0x20:
                p = self.instr(p, 1)
            p += 4  # two u16
            for _ in range(byte(pos + 4)):  # args parsed by 0x428f45
                m = byte(p)
                sm = m - 256 if m >= 128 else m
                if sm < 0x7A:
                    p = self.instr(p, 1)
                else:
                    p += 1
                    if m == 0x7E:
                        p = self.instr(p, 1)
                    elif (
                        m == 0x7C
                    ):  # b1 b2 + S (helper 0x413cd0 arg5=0 dispatches)
                        ty = byte(p + 1)
                        p += 2
                        p = self.instr(p, 1)
                        if ty == 0x13:  # 0x413f21: ip += 2 (u16 type word)
                            p += 2
                        elif (
                            ty != 0xF
                        ):  # 0xd / others: type-dependent, not resolved
                            raise Unresolved(
                                f"0x47 arg 0x7c type 0x{ty:02x} unresolved"
                            )
                    elif m == 0x7F:
                        p += 1
                    else:  # 0x7a 0x7b 0x7d: n byte + S
                        p += 1
                        p = self.instr(p, 1)
            if fl & 0x10:
                p = self.instr(p, 1)
            return p
        if tok == "X_FMT":  # 0xb7 tail: helper 0x41fa7c tag stream
            fl = byte(pos + 1)
            if fl & 0x40:
                return p
            while True:
                tag = byte(p)
                p += 1
                if tag == 0:
                    return p
                if tag == 1:
                    while byte(p) > 5:
                        p += 1
                        if byte(p) == 4:
                            p = self.instr(p + 1, 1)
                elif tag == 2:
                    p = self.instr(p, 1)
                elif tag == 3:
                    m = byte(p)
                    p += 1
                    p = self.instr(p, 1)
                    if m == 1 and byte(p) == 4:
                        p = self.instr(p + 1, 1)
        if tok == "X_D5":  # 0xd5: mode = code[pos+2]; up to 7 sub-exprs
            mode = byte(pos + 2)
            for k in range(1, 6):  # S_A..S_E
                p = self.instr(p, 1)
                if mode == k:
                    return p
            if byte(p) == 0x32:
                p += 1
            else:
                p = self.instr(p, 1)
            if mode == 6:
                return p
            if byte(p) == 0x1B and byte(p + 1) == 0:
                return p + 2
            return self.instr(p, 1)
        if (
            tok == "X_ARGLIST"
        ):  # helper 0x423f9c: count S S* 00 (also T2 0x55/0x56)
            p += 1
            p = self.instr(p, 1)
            while byte(p) != 0:
                p = self.instr(p, 1)
            return p + 1
        if tok == "X_T2P50":  # 0x37 tail: byte b -> table-2 handler [0x50+b]
            b = byte(p)
            return self._instr_t2_at(p + 1, 0x50 + b)
        if tok == "X_CNTS":  # helper 0x40b033: count byte, then count x S
            n = byte(p)
            p += 1
            for _ in range(n):
                p = self.instr(p, 1)
            return p
        if tok == "X_ARGC2":  # T2 0x60: n = code[pos+2] sub-expressions
            for _ in range(byte(pos + 2)):
                p = self.instr(p, 1)
            return p
        if tok == "X_N3":  # T2 0x79: n = code[pos+1]; min(n,3) x S
            for _ in range(min(byte(pos + 1), 3)):
                p = self.instr(p, 1)
            return p
        if tok == "X_84":  # T2 0x84: flags=code[pos+1], cnt=code[pos+2]
            fl, cnt = byte(pos + 1), byte(pos + 2)
            p = self.instr(p, 1)
            if fl & 4:
                p = self.instr(p, 1)
                cnt -= 1
            if cnt > 1:
                p = self.instr(p, 1)
            return p
        if tok == "X_80":  # 0x80: n ; n==2 -> S ; then (0x32 | S)
            if byte(pos + 1) == 2:
                p = self.instr(p, 1)
            if byte(p) == 0x32:
                return p + 1
            return self.instr(p, 1)
        if tok == "X_C8":  # 0xc8: dword; S unless dword in (-1,-2)
            v = struct.unpack_from("<i", c, pos + 1)[0]
            return p if v in (-1, -2) else self.instr(p, 1)
        if tok in ("X_3B", "X_83", "X_BB"):  # GROUP D hook
            return self._extD(tok, pos, p)
        if tok in ("X_GC0", "X_GC2", "X_G5A", "X_G5C", "X_G6C"):
            # GROUP G hook
            return self._extG(tok, pos, p)
        if tok in (
            "X_E7",
            "X_E2",
            "X_E31",
            "X_E82",
            "X_E59",
            "X_E38",
        ):  # GROUP E hook
            return self._extE(tok, pos, p)
        if tok.startswith("X_K"):  # GROUP K hook
            return self._extK(tok, pos, p)
        if tok.startswith("X_L"):  # GROUP L hook
            return self._extL(tok, pos, p)
        if tok.startswith("X_J"):  # GROUP J hook
            return self._extJ(tok, pos, p)
        if tok.startswith("X_I"):  # GROUP I hook
            return self._extI(tok, pos, p)
        if tok.startswith("X_N") and tok != "X_NONE":  # GROUP N hook
            return self._extN(tok, pos, p)
        if tok.startswith("X_O"):  # GROUP O hook
            return self._extO(tok, pos, p)
        raise Unresolved(f"bad ext token {tok}")

    # ---- GROUP K ADDITIONS (new token X_KWIN; nothing existing changed)
    # --------------------------------
    def _extK(self, tok: str, pos: int, p: int) -> int:
        """Decodes the X_KWIN token (0xe8 window handler).

        0xe8 shares the win handler (2.4.2 0x42859a, 2.4.12 0x428895):
        [op][v]; v&0x80 -> one hwnd S FIRST
        (helper 0x40afc7), then k = v&0x1f drives the same argument count as
        0xe7 (k 1..4: k S; k>=6: +1/+2 S;
        k==7: +1 S; k 8..11: 2/3 S). Evidence: `e8 82 <hwnd> <"" > <"Ghost">` in
        ShutDownProcess of the three
        QM 2.4.2 builds (System.qml: WinTest(hwnd "Ghost")). Only occurrence in
        the corpus, and it sits inside a
        0x03 block, so tiling does not exercise it (the block length is
        authoritative).

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return self.code[o]

        if tok != "X_KWIN":
            raise Unresolved(f"bad ext token {tok}")
        v = byte(pos + 1)
        if v & 0x80:
            p = self.instr(p, 1)
        k = v & 0x1F
        n = 0
        if 1 <= k <= 7:
            n = min(k, 4)
            if k >= 6:
                n += 1 if v & 0x20 else 2
            if k == 7:
                n += 1
        elif 8 <= k <= 11:
            n = 2 + (1 if k == 11 else 0)
        for _ in range(n):
            p = self.instr(p, 1)
        return p

    # ---- END GROUP K ADDITIONS ----

    # ---- GROUP L ADDITIONS (tokens X_L*; samples 27-30; nothing existing
    # changed) --------------------
    def _extL(self, tok: str, pos: int, p: int) -> int:
        """Decodes the group L tokens (X_LF:<fmt>, X_L61, X_L7E).

        X_LF:<fmt> = helper 0x40af67 (format-string argument reader, 2.4.12):
        [count byte] then per fmt char:
        letters a/d/i/s/w/z consume one count and one S (z/w evidenced by
        sample28 0x63/0x78 bytes; loop ends when
        count is exhausted); non-letters consume NO count: '!' 1 byte, '#' 4
        bytes, '&' u16 var id (helper 0x40adb0),
        '@' u16. Formats: 0x46329c "zii" (T2 0x63/0x65/0x78), 0x46328c "&iiii"
        (T2 0x82), 0x463294 "&iii" (T2 0x83).
        X_L61 = T2 0x61 (handler 0x4239be): count n, then 2n S. X_L7E = T2 0x7e
        (0x424342): count n, S if n>=1;
        n>=2 has peek/typed sub-paths that no sample exercises -> Unresolved.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        if tok.startswith("X_LF:"):
            n = byte(p)
            p += 1
            for ch in tok[5:]:
                if ch.isalpha():
                    if n <= 0:
                        break
                    n -= 1
                    p = self.instr(p, 1)
                elif ch in "&@":
                    self.need(p, 2)
                    p += 2
                elif ch == "!":
                    self.need(p, 1)
                    p += 1
                elif ch == "#":
                    self.need(p, 4)
                    p += 4
                else:
                    raise Unresolved(f"X_LF fmt char {ch!r}")
            return p
        if tok == "X_L61":
            n = byte(p)
            p += 1
            for _ in range(2 * n):
                p = self.instr(p, 1)
            return p
        if tok == "X_L7E":
            # handler 0x424342 (timeformat, 2.4.12): [n] n>=1: S(format); n>=2:
            # `1b 00` (omitted, 2 bytes) or S (lvalue via 0x40ae1d);
            # n>=3, >=4, >=5: S each (0x40adcc); no more than 5 are read. Only
            # n=1 is exercised by a sample (sample28).
            n = byte(p)
            p += 1
            if n > 5:
                raise Unresolved(f"T2 0x7e n={n} unresolved at {p}")
            for k in range(1, n + 1):
                if k == 2 and byte(p) == 0x1B and byte(p + 1) == 0:
                    p += 2
                else:
                    p = self.instr(p, 1)
            return p
        if tok == "X_LXM":
            # 0xeb/0xec xm/ym handler 0x421ff0: [op][flag][n] n==0 none; S;
            # n>=2: (1b 00 -> 2 bytes | S); n>2: S
            n = byte(p)
            p += 1
            if n == 0:
                return p
            p = self.instr(p, 1)
            if n == 1:
                return p
            if byte(p) == 0x1B and byte(p + 1) == 0:
                p += 2
            else:
                p = self.instr(p, 1)
            if n > 2:
                p = self.instr(p, 1)
            return p
        if tok in (
            "X_LD6",
            "X_LD7",
        ):
            # 0xd6 rget (0x4221b2, n<=6 slots) / 0xd7 rset (0x422470, <=5):
            # [op][b1: n=b1&15][b2] S [b2==0xff: +4] S, n>=3: S ...
            n = byte(pos + 1) & 0xF
            b2 = byte(pos + 2)
            p = self.instr(p, 1)
            if b2 == 0xFF:
                self.need(p, 4)
                p += 4
            p = self.instr(p, 1)
            for _ in range(3, min(n, 6 if tok == "X_LD6" else 5) + 1):
                p = self.instr(p, 1)
            return p
        if tok == "X_LB3":
            # 0xb3 inp handler 0x42037b: [op][flags][n] S(target) [byte] then
            # slots 2..8 (n>=k), slots 5/7 skipped if flags&2 / flags&4
            fl, n = byte(pos + 1), byte(pos + 2)
            p = self.instr(p, 1)
            self.need(p, 1)
            p += 1
            for k in range(2, 9):
                if n < k:
                    break
                if (k == 5 and fl & 2) or (k == 7 and fl & 4):
                    continue
                p = self.instr(p, 1)
            return p
        if tok == "X_LA8":
            # 0xa8 findrx (2.4.12 handler 0x425790, 2.4.2 0x4253c3): [a8][n][b]
            # then n x S (n>=2: string, pattern, from, flags, result, submatch)
            for _ in range(byte(pos + 1)):
                p = self.instr(p, 1)
            return p
        raise Unresolved(f"bad GROUP L token {tok}")

    # ---- END GROUP L ADDITIONS ----

    # ---- GROUP A ADDITION: argument decoder of helper 0x4299f8 (op >= 0x7a)
    # ----
    def _arg(self, p: int) -> int:
        """Decodes one argument at p; returns the next offset.

        Args:
          p: Offset of the argument.

        Returns:
          The offset just past the argument.

        Raises:
          Unresolved: If the code is truncated.
        """
        self.need(p)
        b = self.code[p]
        if b < 0x7A:
            return self.instr(p, 1)
        self.starts.append(p)
        if b == 0x7A:  # op, byte, S
            self.need(p, 2)
            return self.instr(p + 2, 1)
        if b == 0x7B:  # op, word, S
            self.need(p, 3)
            return self.instr(p + 3, 1)
        if b == 0x7D:  # op, S
            return self.instr(p + 1, 1)
        if b == 0x7C:  # op, S, then 413cd0 type-tail (type 0x13: word)
            return self.instr(p + 1, 1) + 2
        return p + 1  # other >= 0x7e: op only (no sample seen)

    # ---- GROUP E ADDITIONS (new tokens X_E7 / X_E2 / X_E31 / X_E82; nothing
    # existing changed) ----
    def _extE(self, tok: str, pos: int, p: int) -> int:
        """Handles group E tokens; returns the next offset.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        if tok == "X_E7":
            # 0xe7 handler 0x42859a: [e7][v]; v&0x80 -> 1 S; else k=v&0x1f:
            # k 1..7: min(k,4) S (helper 0x40b07c); k>=6: bit5 ? 1 S : 2 S
            # (0x40afc7 / 0x40b3ef);
            # k==7: +1 S (dispatch at 0x4286d0). k 8..11: 2 S (0x40b3ef); k==11:
            # +1 S. else none.
            v = byte(pos + 1)
            if v & 0x80:
                return self.instr(p, 1)
            k = v & 0x1F
            n = 0
            if 1 <= k <= 7:
                n = min(k, 4)
                if k >= 6:
                    n += 1 if v & 0x20 else 2
                if k == 7:
                    n += 1
            elif 8 <= k <= 11:
                n = 2 + (1 if k == 11 else 0)
            for _ in range(n):
                p = self.instr(p, 1)
            return p
        if tok == "X_E2":
            # 0xe2 handler 0x42526c -> 0x40b102(ctx,buf,1): [e2][n][b] then n x
            # S
            for _ in range(byte(pos + 1)):
                p = self.instr(p, 1)
            return p
        if tok == "X_E82":
            # 0x82 handler 0x422496: [82][f][u16 (4 bytes total)] then S iff (f
            # & 0x7f) != 0
            return self.instr(p, 1) if byte(pos + 1) & 0x7F else p
        if tok == "X_E31":
            # 0x31 tail after [31 S]: t=code[p] c=code[p+1] (handler 0x4269da);
            # k=t&0x1f
            t, cc = byte(p), byte(p + 1)
            p += 2
            k = t & 0x1F
            n = None
            if 1 <= k <= 5 or k == 7:
                n = 1
            elif k == 6:
                n = 2 + (1 if cc > 4 else 0)
            elif k in (8, 9):
                n = 1 if cc == 3 else 0
            elif 10 <= k <= 13:
                n = 0
            elif k == 14:
                n = 1 if cc > 2 else 0
            elif k == 15:
                n = 1
            elif k in (0x10, 0x11):
                n = max(cc - 2, 0)
            elif k == 0x16:
                # helper 0x421c26 with n=c-2: S, (1b 00 | S), (1b 00 | S), S, S,
                # S; stops after n elements
                nn = cc - 2

                def opt(q: int) -> int:
                    """Skips an omitted operand (1b 00) or one S."""
                    if byte(q) == 0x1B and byte(q + 1) == 0:
                        return q + 2
                    return self.instr(q, 1)

                p = self.instr(p, 1)
                if nn == 1:
                    return p
                p = opt(p)
                if nn == 2:
                    return p
                p = opt(p)
                if nn == 3:
                    return p
                p = self.instr(p, 1)
                if nn == 4:
                    return p
                p = self.instr(p, 1)
                if nn == 5:
                    return p
                return self.instr(p, 1)
            if n is None:
                self.unresolved[(31, k)] = self.unresolved.get((31, k), 0) + 1
                raise Unresolved(f"0x31 kind 0x{k:02x} unresolved at {p}")
            for _ in range(n):
                p = self.instr(p, 1)
            return p
        if tok == "X_E59":
            # table-2 keys 0x58/0x59 (reached via 0x37) handler 0x4234a2:
            # [op][flags][has] S iff has != 0
            return self.instr(p, 1) if byte(pos + 2) else p
        if tok == "X_E38":
            # 0x38 handler 0x414a60: [38][b1][b2] S(object) then, per runtime
            # type, b2 argument S
            # (cmp [ebp-0x1c],1/2 at 0x414cd8..). Only b2==1 is evidenced by
            # samples.
            for _ in range(byte(pos + 2)):
                p = self.instr(p, 1)
            return p
        raise Unresolved(f"bad GROUP E token {tok}")

    # ---- END GROUP E ADDITIONS ----

    # ---- GROUP G ADDITIONS (tokens X_GC0/X_GC2/X_G5A/X_G5C/X_G6C; nothing
    # existing changed) ----
    def _extG(self, tok: str, pos: int, p: int) -> int:
        """Handles group G tokens; returns the next offset.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        if tok == "X_GC0":
            # 0xc0 (mou) handler 0x41e9d1 -> helpers 0x40bb4c/0x40b50d/0x40b175.
            # [c0][mode] then
            # byte n: n==0 -> no operands; else n byte + 2 S (x,y; helper
            # 0x40b175 loops 2x 0x40adcc).
            # Only n==0 and n==2 are evidenced/resolved; mode byte '*' (0x2a)
            # path not handled.
            if byte(pos + 1) == 0x2A:
                raise Unresolved("0xc0 mode '*' unresolved")
            n = byte(p)
            p += 1
            if n == 0:
                return p
            if n not in (
                2,
                3,
            ):
                # GROUP L: n=3 = `mou x y win` (sample27: c0 00 03 1b05 1b06 09
                # 1f0300)
                raise Unresolved(f"0xc0 n={n} unresolved at {p}")
            p = self.instr(p, 1)
            p = self.instr(p, 1)
            return self.instr(p, 1) if n == 3 else p
        if tok == "X_GC2":
            # 0xc2 (mes) handler 0x420192: [c2][argc][flags] then argc S
            # (argc>=2: S via 0x40adcc,
            # argc>=3: one more via 0x40adcc, message S via 0x424906/0x42422f).
            # argc>3 unresolved.
            argc = byte(pos + 1)
            if not 1 <= argc <= 3:
                raise Unresolved(f"0xc2 argc={argc} unresolved at {p}")
            for _ in range(argc):
                p = self.instr(p, 1)
            return p
        if tok == "X_G5A":
            # T2 keys 0x5a/0x5b (via 0x37) handler 0x423775: [b][flags][kind]
            # kind==1 -> 1 S, kind==2 -> 2 S
            kind = byte(pos + 2)
            for _ in range(kind if kind in (1, 2) else 0):
                p = self.instr(p, 1)
            return p
        if tok == "X_G5C":
            # T2 keys 0x5c/0x5d (via 0x37) handler 0x4237e9: [b][flags] S,
            # (flags&1: S), S (inline dispatch)
            fl = byte(pos + 1)
            p = self.instr(p, 1)
            if fl & 1:
                p = self.instr(p, 1)
            return self.instr(p, 1)
        if tok == "X_G6C":
            # T2 keys 0x6c/0x6d (via 0x37) handler 0x423d15 + format "!iS" of
            # helper 0x40af67:
            # [b][n][!-byte (unconditional)] then 'i' (lower-case, count-gated):
            # S iff n>=1; 'S' consumes nothing.
            return self.instr(p, 1) if byte(pos + 1) >= 1 else p
        raise Unresolved(f"bad GROUP G token {tok}")

    # ---- END GROUP G ADDITIONS ----

    # ---- GROUP D ADDITIONS (new tokens X_3B / X_83 / X_BB; nothing existing
    # changed) ----
    def _extD(self, tok: str, pos: int, p: int) -> int:
        """Handles group D tokens; returns the next offset.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        if tok == "X_3B":
            # 0x3b @0x416855 (2.4.2): [3b] S n ; n!=0: n x S ; n==0: k [k in
            # (0,0x24): +2] ;
            # then 2 bytes (type, flags).  `p` = just after the first S.
            n = byte(p)
            p += 1
            if n:
                for _ in range(n):
                    p = self.instr(p, 1)
            else:
                k = byte(p)
                p += 1
                if k in (0, 0x24):
                    p += 2
            self.need(p, 2)
            return p + 2
        if tok == "X_83":
            # 0x83 @0x419b99: [83][tb] S S ; tb bit7 (and 1b 00 follows) -> skip
            # 2 else 1 S ;
            # t = tb & 0x3f: t>=4:S  t>=5:S  t>=6:S  t>=7:2S (0x40b370)  t>8:S
            # t>9:S  t>0xa:S
            # t >= 0x14 (0x41a413 branch) not evidenced -> Unresolved.
            tb = byte(pos + 1)
            t = tb & 0x3F
            if tb & 0x80:  # 0x419beb: sign bit -> one S first
                p = self.instr(p, 1)
            if t >= 0x14:
                # branch 0x41a413 (S,S prologue skipped). 0x14/0x15: 2S
                # (0x40b370), then 1b 00 | S,
                # 0x15 adds one S; 0x18: S (@0x41a6b0, TILING-EVIDENCED); 0x19:
                # 2S; 0x1a: S
                # (0x14/0x15/0x19/0x1a handler-only); 0x16/0x17 not traced ->
                # Unresolved.
                if t in (0x14, 0x15):
                    p = self.instr(self.instr(p, 1), 1)
                    if byte(p) == 0x1B and byte(p + 1) == 0:
                        p += 2
                    else:
                        p = self.instr(p, 1)
                    return self.instr(p, 1) if t == 0x15 else p
                if t in (0x18, 0x1A):
                    return self.instr(p, 1)
                if t == 0x19:
                    return self.instr(self.instr(p, 1), 1)
                raise Unresolved(f"0x83 type 0x{tb:02x} unresolved at {pos}")
            p = self.instr(p, 1)
            p = self.instr(p, 1)
            if (tb & 0x80) and byte(p) == 0x1B and byte(p + 1) == 0:
                p += 2
            else:
                p = self.instr(p, 1)
            nS = 0
            if t >= 4:
                nS += 1
            if t >= 5:
                nS += 1
            if t >= 6:
                nS += 1
            if t >= 7:
                nS += 2
            if t > 8:
                nS += 1
            if t > 9:
                nS += 1
            if t > 10:
                nS += 1
            for _ in range(nS):
                p = self.instr(p, 1)
            return p
        if tok == "X_BB":
            # 0xbb @0x4230c6: [bb][b1][n] S then max(n-1,0) x S (helper
            # 0x42468d, flag 0 -> dispatch)
            n = byte(pos + 2)
            p = self.instr(p, 1)
            for _ in range(max(n - 1, 0)):
                p = self.instr(p, 1)
            return p
        raise Unresolved(f"bad GROUP D token {tok}")

    # ---- END GROUP D ADDITIONS ----

    # ---- GROUP I ADDITIONS (tokens
    # X_I31/X_I87/X_I8B/X_IAB/X_IMOUSE/X_IMOV/X_IE3; nothing existing changed)
    # ----
    def _extI(self, tok: str, pos: int, p: int) -> int:
        """Handles group I tokens; returns the next offset.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        S = lambda q: self.instr(q, 1)
        if tok == "X_I31":
            # 0x31 kind 0x12 (wait for variable `V`): handler 0x42700f
            # @0x427596: call 0x40ae1d
            # (dispatches ONE S, returns ctx+0x14 = address). Other kinds ->
            # X_E31.
            if byte(p) & 0x1F == 0x12:
                return S(p + 2)
            return self._extE("X_E31", pos, p)
        if tok == "X_I87":
            # 0x87 (but) handler 0x428570: [87][b1][n]; n==1: S(0x40adcc)
            # S(window 0x40ada4);
            # n==0: S(window); else IP-- then S (not evidenced -> Unresolved)
            n = byte(pos + 2)
            if n == 1:
                return S(S(p))
            if n == 0:
                return S(p)
            raise Unresolved(f"0x87 n={n} unresolved at {pos}")
        if tok == "X_I8B":
            # 0x8b (cop) handler 0x41f806: [8b][b1][b2][b3] S S (0x424906 x2);
            # b2>2: +S (0x40adcc)
            p = S(S(p))
            return S(p) if byte(pos + 2) > 2 else p
        if tok == "X_IAB":
            # 0xab (hid) handler 0x4281d8: [ab][flag] S(window 0x40ada4); flag
            # '-' and next byte 0x32
            # -> no S (0x428272; 0x32 consumed as in X_80; only the S path is
            # evidenced)
            if byte(pos + 1) == 0x2D and byte(p) == 0x32:
                return p + 1
            return S(p)
        if tok == "X_IMOUSE":
            # 0x93/0xb8/0xc1/0xd4 (dou/lef/mid/rig click) shared handler
            # 0x41e7f3 -> 0x40ba98 -> 0x40b50d:
            # [op][letter][flag][n]; n==0 -> nothing; else S(x) S(y) (0x40b175);
            # n>2: (1b 00 | S window 0x40b325)
            # ; n>3: +S (0x40adcc). `p` = after the 3 header bytes (n byte at
            # p).
            n = byte(p)
            p += 1
            if n == 0:
                return p
            p = S(S(p))
            if n > 2:
                if byte(p) == 0x1B and byte(p + 1) == 0:
                    p += 2
                else:
                    p = S(p)
                if n > 3:
                    p = S(p)
            return p
        if tok == "X_IMOV":
            # 0xbf/0xdb (mov/siz) handler 0x427985: [op][m][n]; S S (0x40b175);
            # m==3: +S S; S(window 0x40ada4);
            # n>3: +S (0x40adcc)
            m, n = byte(pos + 1), byte(pos + 2)
            for _ in range(4 if m == 3 else 2):
                p = S(p)
            p = S(p)
            return S(p) if n > 3 else p
        if tok == "X_IE3":
            # 0xe3 (tim) handler 0x426b8e: helper 0x40af67 format "*dii":
            # [e3][n] then min(n,3) S (count-gated)
            for _ in range(min(byte(pos + 1), 3)):
                p = S(p)
            return p
        raise Unresolved(f"bad GROUP I token {tok}")

    # ---- END GROUP I ADDITIONS ----

    # ---- GROUP J ADDITIONS (tokens X_J*; builtin-function opcodes of sample24;
    # nothing existing changed) ----
    def _extJ(self, tok: str, pos: int, p: int) -> int:
        """Handles group J tokens; returns the next offset.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        n = byte(pos + 1)
        if tok == "X_JN":
            # 0xa4 / 0xc4: helper 0x40aebb reads count n at pos+1, then n x S
            # (a4 handler adds one more S via 0x40adcc)
            for _ in range(n):
                p = self.instr(p, 1)
            return p
        if tok in ("X_JF2", "X_JF4"):
            # 0x96 / 0xa6 (format "*&ii") and 0xa5 (format "*&iiii"), helper
            # 0x40af67: [op][n][u16 '&' via 0x40adb0] then
            # one S per 'i' while the count n lasts (only 'i' consumes n; '&'
            # does not). Caller layout has int 4 before.
            for _ in range(min(n, 2 if tok == "X_JF2" else 4)):
                p = self.instr(p, 1)
            return p
        if tok == "X_JB4":
            # 0xb4 handler 0x429260: [b4][n] S S, and a third S iff n > 2
            # (0x40b14b, 0x40adcc, 0x40ada4, cmp n,2)
            p = self.instr(p, 1)
            p = self.instr(p, 1)
            return self.instr(p, 1) if n > 2 else p
        if tok == "X_JCD":
            # 0xcd handler 0x421f69 -> 0x40b50d(4,..): [cd][n] then helper
            # 0x40b175 = 2 x S; n>2: `1b 00` skipped (2 bytes),
            # then n>3: S. A non-`1b 00` third argument takes the 0x40b5c0 path
            # (not evidenced) -> unresolved.
            p = self.instr(p, 1)
            p = self.instr(p, 1)
            if n > 2:
                if byte(p) == 0x1B and byte(p + 1) == 0:
                    p += 2
                    if n > 3:
                        p = self.instr(p, 1)
                else:
                    raise Unresolved(
                        f"0xcd n={n} non-default 3rd arg not evidenced at {pos}"
                    )
            return p
        if tok == "X_J8C":
            # 0x8c handler 0x428de6: [8c][b]; b&0x80 -> S, b&0x40 -> S (before
            # the count part); m=b&0x1f;
            # m>=1 S, m>=2 S, m>=3 (`1b 00` if b&0x80 else S). Only m<=3
            # evidenced (sample24 m=3).
            # m>=4 (helpers 0x40b175/0x4290dc): no evidence for the extra
            # operands in this repo -> Unresolved (documented).
            m = n & 0x1F
            if m > 3:
                raise Unresolved(f"0x8c m={m} not evidenced at {pos}")
            if n & 0x80:
                p = self.instr(p, 1)
            if n & 0x40:
                p = self.instr(p, 1)
            for i in range(m):
                if (
                    i == 2
                    and (n & 0x80)
                    and byte(p) == 0x1B
                    and byte(p + 1) == 0
                ):
                    p += 2
                else:
                    p = self.instr(p, 1)
            return p
        if tok == "X_J9F":
            # 0x9f handler 0x425208: [9f][n] S S, n>2: S, n>3: S (cmp ebp,2 /
            # cmp ebp,3 at 0x425250 / 0x42526d)
            p = self.instr(p, 1)
            p = self.instr(p, 1)
            if n > 2:
                p = self.instr(p, 1)
            if n > 3:
                p = self.instr(p, 1)
            return p
        if tok == "X_JA7":
            # 0xa7 handler 0x425556: [a7][n] S S; only n==2 evidenced (n!=2 goes
            # through helper 0x40b15d: not analysed)
            # Validator report (2026-11-08, handler re-read, NOT re-verified
            # here, unobserved): n!=2 = S S S [S if n>3].
            # Kept Unresolved on purpose: no sample has n!=2 and the rule was
            # not checked against bytes.
            if n != 2:
                raise Unresolved(f"0xa7 n={n} not evidenced at {pos}")
            p = self.instr(p, 1)
            return self.instr(p, 1)
        if tok == "X_JA0":
            # 0xa0 handler 0x4252ca: [a0][flags] S S, flags&1 -> third S
            # (0x425322); flags&4 = 2nd arg taken as a char
            p = self.instr(p, 1)
            p = self.instr(p, 1)
            return self.instr(p, 1) if n & 1 else p
        raise Unresolved(f"bad GROUP J token {tok}")

    # ---- END GROUP J ADDITIONS ----

    # ---- GROUP N ADDITIONS (tokens X_NA2/X_NAC/X_NB6/X_NDF; sample35 opcodes;
    # nothing existing changed) ----
    def _extN(self, tok: str, pos: int, p: int) -> int:
        """Handles group N tokens; returns the next offset.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        c = self.code

        def byte(o: int) -> int:
            """Returns the checked code byte at offset o."""
            self.need(o)
            return c[o]

        S = lambda q: self.instr(q, 1)
        n = byte(pos + 1)
        if tok == "X_NA2":
            # 0xa2/0xa3 (findcs/findcn) handler 0x4253a3 -> 0x40af07:
            # [op][n][flag] then n x S (charset, [from]) + 1 S (the string).
            # flag 0 = findcs (0xa2), 1 = findcn (0xa3) (sample35).  `p` = after
            # the 3 header bytes.
            for _ in range(n + 1):
                p = S(p)
            return p
        if tok == "X_NAC":
            # 0xac (htm) handler 0x41e4ed: [ac][n] then n x S; only n==2
            # observed (sample35) -> other n unresolved
            if n != 2:
                raise Unresolved(f"0xac n={n} not evidenced at {pos}")
            return S(S(p))
        if tok == "X_NB6":
            # 0xb6 (inpp) handler 0x420532: [b6][n] then n x S (text, caption,
            # flags, owner for n>1..4); n=2,3 observed (sample35)
            if not 1 <= n <= 5:
                raise Unresolved(f"0xb6 n={n} out of range at {pos}")
            for _ in range(n):
                p = S(p)
            return p
        if tok == "X_NDF":
            # 0xdf (scan) handler 0x421fa8: [df][n] S(image); n>=2: `1b 00`
            # (default window) or S; n==1,2 observed (sample35);
            # n>=3 (rect, flags, colordiff, index via 0x40ae1d/0x40adcc) not
            # evidenced -> unresolved
            if n > 2:
                raise Unresolved(f"0xdf n={n} not evidenced at {pos}")
            p = S(p)
            if n == 2:
                if byte(p) == 0x1B and byte(p + 1) == 0:
                    return p + 2
                p = S(p)
            return p
        raise Unresolved(f"bad GROUP N token {tok}")

    # ---- END GROUP N ADDITIONS ----

    # ---- GROUP O ADDITIONS (token X_O8E; sample34 `call(...)`; nothing
    # existing changed) ----
    def _extO(self, tok: str, pos: int, p: int) -> int:
        """Decodes the X_O8E token (0x8e call).

        0x8e = call(address [a1 ...]) (handler 0x42325d, 2.4.2 0x422ff4):
        [8e][n] S(function: id, name or &sub.X) then n x S
        arguments (handler -> 0x4292f8(ctx, fn, n,...) evaluates n operands).
        Observed sample34: `8e 01 54 a3 05 1b 05`
        (`call(&sub.Foo 5)`) and `8e 01 1e <str> 1b 01` (`call("Foo" 1)`); n=1
        only. `p` = after the 2 header bytes.

        Args:
          tok: The extension token being decoded.
          pos: Offset of the opcode byte.
          p: Current offset (just after the fixed header bytes).

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unknown or the layout is not evidenced.
        """
        self.need(pos, 2)
        n = self.code[pos + 1]
        if tok == "X_O8E":
            p = self.instr(p, 1)
            for _ in range(n):
                p = self.instr(p, 1)
            return p
        raise Unresolved(f"bad GROUP O token {tok}")

    # ---- END GROUP O ADDITIONS ----

    def _cond(self, pos: int, p: int, tok: list) -> int:
        """Decodes a conditional (groupB) layout token.

        groupB tokens (JSON lists), offsets relative to the opcode byte at
        pos:
        ["IF",   off, mask, [then], [else]]  then-tokens if code[pos+off] & mask
        ["IFEQ", off, val,  [then], [else]]  then-tokens if code[pos+off] == val
        ["IFGT", off, val,  [then], [else]]  then-tokens if code[pos+off] > val
        ["SKIPN", off, unit, minn]  skip max(code[pos+off], minn)*unit bytes
        ["?"]  unresolved (raises Unresolved)
        Sub-token lists may contain ints, "S", "T2" and nested lists.

        Args:
          pos: Offset of the opcode byte.
          p: Current offset.
          tok: The conditional token list.

        Returns:
          The offset just past the instruction.

        Raises:
          Unresolved: If the token is unverified or malformed.
        """
        k = tok[0]
        if k == "?":
            raise Unresolved(f"unverified branch at {pos}")
        self.need(pos, tok[1] + 1)
        v = self.code[pos + tok[1]]
        if k == "SELCASE":
            # GROUP M: 0x88 case: count*4 bytes; count 0 (else) = 4 pad bytes
            # for int sel, 0 for string sel
            n = v * 4
            if v == 0:
                kind = 0
                if self.stream:
                    for e in reversed(self.stream):
                        if (
                            e < pos
                            and self.code[e] == 0xD9
                            and self.code[e + 3] == self.code[pos + 3]
                        ):
                            kind = self.code[e + 4]
                            break
                n = 0 if kind else 4
            self.need(p, n)
            return p + n
        if k == "SKIPN":
            n = max(v, tok[3]) * tok[2]
            self.need(p, n)
            return p + n
        if k == "IF":
            sel = tok[3] if v & tok[2] else (tok[4] if len(tok) > 4 else [])
        elif (
            k == "IFGT"
        ):  # then-tokens if code[pos+off] > val (0xc3 mkdir: b>1 -> parent S)
            sel = tok[3] if v > tok[2] else (tok[4] if len(tok) > 4 else [])
        elif k == "IFEQ":
            sel = tok[3] if v == tok[2] else (tok[4] if len(tok) > 4 else [])
        else:
            raise Unresolved(f"bad cond token {tok}")
        for t in sel:
            if isinstance(t, int):
                self.need(p, t)
                p += t
            elif t == "S":
                p = self.instr(p, 1)
            elif t == "T2":
                p = self.instr(p, 2)
            elif isinstance(t, list):
                p = self._cond(pos, p, t)
            else:
                raise Unresolved(f"bad token {t}")
        return p


def decode_function(code: bytes, stream: list[int]) -> dict:
    """Decode every top-level stream entry; compare starts with the stream.

    Args:
      code: The bytecode of one function.
      stream: Instruction start offsets taken from the function's stream.

    Returns:
      A dict with keys top, starts, errors, extra_starts, missing_entries,
      unresolved and opcount.
    """
    d = Decoder(code)
    ents = sorted(set(stream))
    errors = []
    pos = 0
    top = []
    for e in stream:
        # top-level entries are those not already covered by a previous decode
        pass
    covered_to = 0
    for e in ents:
        if e < covered_to:
            continue
        try:
            end = d.instr(e, 1)
            top.append((e, end))
            covered_to = end
        except Unresolved as exc:
            errors.append((e, str(exc)))
            covered_to = e + 1
    starts = sorted(set(d.starts))
    extra = [s for s in starts if s not in ents]  # decoded but not in stream
    missing = [e for e in ents if e not in starts]  # in stream but not decoded
    return {
        "top": top,
        "starts": starts,
        "errors": errors,
        "extra_starts": extra,
        "missing_entries": missing,
        "unresolved": d.unresolved,
        "opcount": d.opcount,
    }
