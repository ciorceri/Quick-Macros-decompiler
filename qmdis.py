#!/usr/bin/env python3
"""
qmdis.py - Level 2 bytecode disassembler for Quick Macros (QM) 2.4.2 exes.

Implements the interpreter model documented in docs/research-log.md:

  - The dispatch loop (FUN_00420730) walks an INSTRUCTION STREAM: an array of
    16-bit offsets into the code base. The opcode is the first byte at the
    current code offset. Handlers may modify the instruction counter
    (jumps/loops), so the stream order is execution order.
  - Handler table PTR_FUN_00461038 (VA 0x461038), 64 documented entries
    (opcodes 0x00-0x3F). A second, statement-level table (PTR_FUN_00461438)
    is used inside block opcodes (opcode 0x03).

HARD RULE (from the project charter): never invent semantics. Any opcode
whose handler semantics are NOT recorded in docs/research-log.md makes the
disassembler raise QmUndocumentedOpcodeError. Unknown opcodes are a signal
that RE work is still needed - they are collected and reported, never guessed.

Usage:
    python qmdis.py <extracted_dir>            # dir with
    res2.bin/res3.bin/res4.bin
    python qmdis.py <res4.bin>                 # raw res4 payload directly
    python qmdis.py <res4.bin> --code-base 0x4c --stream-offset 0x46e

Exit codes: 0 = fully decoded, 2 = completed with undocumented opcodes (RE
gaps).
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import struct
import sys

# Reuse the validated container/decryption helpers from qmtool.py.
from qmtool import KNOWN_QM_KEY
from qmtool import qm_decrypt

# ---------------------------------------------------------------------------
# res4 layout constants (validated on a 6828-byte res4 of a QM 2.4.2 exe
# (original-1))
#
# These offsets are NOT yet recorded in docs/research-log.md; they were derived
# during disassembler bring-up and are surfaced as CLI options so the analyst
# can correct them without touching this file. See docs/FORMAT.md.
# ---------------------------------------------------------------------------
RES4_HEADER_PTRS = 9  # dwords 0x00..0x24: relocated runtime pointers
CODE_BASE_OFFSET = 0x48  # block + 0x48 (corrected 2026-11-07; was 0x4C)
STREAM_SEARCH_START = 0x48  # fallback scan start


class QmUndocumentedOpcodeError(Exception):
    """Raised when the bytecode has an opcode with no documented semantics.

    Attributes:
      opcode: The undocumented opcode byte.
      code_offset: Offset of the opcode within the code region.
      stream_index: Index of the instruction in the stream.
    """

    def __init__(
        self, opcode: int, code_offset: int, stream_index: int
    ) -> None:
        """Stores the offending opcode and its location.

        Args:
          opcode: The undocumented opcode byte.
          code_offset: Offset of the opcode within the code region.
          stream_index: Index of the instruction in the stream.
        """
        self.opcode = opcode
        self.code_offset = code_offset
        self.stream_index = stream_index
        super().__init__(
            f"undocumented opcode 0x{opcode:02x} at code offset "
            f"0x{code_offset:04x} (stream entry {stream_index}) - "
            "handler semantics not recorded in docs/research-log.md"
        )


# ---------------------------------------------------------------------------
# Documented opcode semantics (docs/research-log.md, batches 1 and 2)
#
# Each entry: (mnemonic, operand_format). operand_format describes ONLY what
# research-log.md explicitly records, plus encodings validated against the
# original-1 sample's instruction stream (documented in docs/FORMAT.md):
#   "call7"   - 7-byte instruction, 16-bit function index at +5   (opcode 0x02;
#               re-verified 2026-11-05 against handler 0x429200:
#               movzx eax, word ptr [edi+5] - see docs/FORMAT.md)
#   "block"   - 16-bit block length at +1; body of <len> bytes follows the
#               3-byte header, then 4 trailing bytes (2 type bytes + 2 more);
#               sub-opcodes dispatch through the statement-level table
#               (opcode 0x03; validated: next stream entry == start+3+len+4
#               for all 4 blocks in the original-1 sample)
# "type2_u16" 2 type bytes then a 16-bit field/element offset    (opcode 0x12)
# "global3" 3 bytes total (IP += 3), 16-bit table index          (opcode 0x20)
# "for"     16-bit loop label at +2, flag byte at +3             (opcode 0x33)
#   Batch 3 (research-log.md, sections 3a/3b/3c):
#   "imm_i32"/"imm_u32"  4-byte immediate at +1, total 5 bytes     (0x19/0x1a)
#   "imm_i8"             1-byte immediate at +1, total 2 bytes     (0x1b)
#   "imm_f64"/"imm_i64"  8-byte immediate at +1, total 9 bytes     (0x1c/0x1d)
#   "frame_addr"         int32 frame offset at +1, total 5 bytes   (0x1e)
#   "local3"             3 bytes total, 16-bit local-var index +1  (0x1f/0x21)
#   "index_elem"         sub-instr A at +1, sub-instr B at +2, then a
#                        trailing uint16 element stride (position depends on
#                        the sub-instructions; annotated from the NEXT stream
#                        entry, which marks the end of this instruction)
#                        (opcode 0x16)
#   "iface_get"          sub-opcode at +1, index byte at +2, total 3 (0x37)
#   "com_create"         kind byte +1, arg-count +2, flags +3      (0x39)
#   "array_op"           op byte +1, arg-count byte +2             (0x3a)
#   "array_elem"         index-count byte +1, element-type byte +2 (0x3b)
#   "memcpy"             sub-opcode +1, uint16 byte count +2, total 4 (0x3c)
#   "obj_assign"         sub-opcode +1, uint16 table index +2, total 4 (0x3d)
#   "com_assign"         sub-instr A at +1, sub-instr B at +2      (0x3e)
#   "obj_op"             no inline operands; sub-instructions follow (0x35)
#   Final batch (research-log.md, "Final opcode batch (capstone inline RE,
#   2026-11-06)" section):
# "index_addr"          `18 <A> <B> <u16 stride>` (0x18, corrected 2026-11-07)
#   "query_iface"         `43 <u16 iid idx> <obj sub-expr>` (0x43)
#   (0x36 "typed_store" was WRONG - the handler at 0x424dcc is a thunk
#    `push 0; call 0x424ce0; ret`, i.e. 0x35 with arg 0; the earlier text
#    described the NEXT function at 0x424dd4. Corrected 2026-11-07.)
#   "slot_store"          3-byte fixed part: tag +1, sub-opcode +2
#                         dispatched (evaluates value) (0x38)
#   "method_invoke_3null" 3-byte fixed part: tag +1, sub-opcode +2
#                         dispatched (evaluates value) (0x3F)
#   None      semantics documented, operand layout NOT documented
# ---------------------------------------------------------------------------

DOCUMENTED_OPCODES: dict[int, tuple[str, str | None]] = {
    0x00: ("expr_statement", None),
    # evaluate expression, statement/exit check
    # Pending-opcode batch (research-log.md, "Pending-opcode batch" section)
    0x01: ("var_access_value", "var_access"),  # 4 B: tag +1, uint16 index +2
    0x02: ("call_function", "call7"),  # 7-byte instruction, 16-bit index at +5
    0x03: ("block", "block"),  # 16-bit block length at +2, table-2 sub-opcodes
    0x04: ("neg", None),  # unary minus (int64 or double)
    0x05: ("bit_not", None),  # bitwise NOT
    0x06: ("log_not", None),  # logical NOT, result 0/1
    0x07: ("conv_int64", None),  # convert to int64, result type 6
    0x08: ("conv_double", None),  # convert int->double, result type 5
    0x09: ("load_i32", None),  # deref, sign-extend to int64
    0x0A: ("load_u32", None),  # deref, zero-extend
    0x0B: ("load_u8", None),  # deref, zero-extend byte
    0x0C: (
        "deref_int16",
        "deref_sub",
    ),  # dispatch next opcode, read int16, sign-extend
    0x0D: ("deref_double", "deref_sub"),
    # dispatch next opcode, fld/fstp qword
    0x0E: ("deref_int64", "deref_sub"),  # dispatch next opcode, copy 8 bytes
    0x0F: ("deref_value", None),
    # *slot -> value slot, one indirection removed
    0x10: ("address_of", None),  # value slot = variable address
    0x11: ("pop_restore", None),  # increment +0x1d, copy slot back
    0x12: ("deref_add_u16", "type2_u16"),  # 2 type bytes + 16-bit field offset
    0x13: ("deref_read_types", None),
    # advance IP, dispatch, load 2 type bytes
    0x14: ("deref_add_u16_via15", None),  # calls 0x15 handler, adds uint16
    0x15: ("deref_nullcheck", None),  # deref with null check, 2 type bytes
    0x17: ("deref_redispatch", None),  # re-dispatch, slot = base + offset
    # Final opcode batch (research-log.md, "Final opcode batch (capstone
    # inline RE, 2026-11-06)" section) - closes the former PENDING set
    0x18: (
        "index_addr",
        "index_addr",
    ),  # array element address: base + index*stride
    0x36: (
        "two_operand_op_0",
        "obj_op",
    ),
    # 2.4.12 thunk 0x425052: push 0; call 0x424f66 (same helper as 0x35, arg 0).
    # 2026-11-07: old address 0x424ce0 belongs to another build. Layout [1,S,S]
    # (qmlayout)
    0x43: (
        "query_interface",
        "query_iface",
    ),  # QueryInterface(obj, IID[idx]) - REA 2026-11-07
    0x38: (
        "slot_store",
        "slot_store",
    ),  # store into slot (0x37/0x3a/0x3c/0x3d family)
    0x3F: (
        "method_invoke_3null",
        "method_invoke_3null",
    ),  # invoke with 3 null args
    # Batch 3a (research-log.md, "Batch 3a" section)
    0x16: (
        "index_element",
        "index_elem",
    ),  # array indexing: base + index*stride
    0x1F: ("load_local_addr", "local3"),  # address of local variable (3 bytes)
    0x21: ("load_local_value", "local3"),  # value of local variable (3 bytes)
    0x35: (
        "str_append",
        "obj_op",
    ),
    # 2026-11-07: NOT object_op. 2.4.12 thunk 0x42504a: push 1; call 0x424f66;
    # layout [1,S,S]; `s+"lit"` (sample11/18, 2 occurrences, meaning inferred).
    # Old cited 0x424ce0 is wrong
    # Batch 3b (research-log.md, "Batch 3b" section) - immediate pushes
    0x19: ("push_i32", "imm_i32"),  # push int32 immediate, sign-extended
    0x1A: ("push_u32", "imm_u32"),  # push uint32 immediate, flags 0x40
    0x1B: ("push_i8", "imm_i8"),  # push 8-bit immediate (0..255)
    0x1C: ("push_f64", "imm_f64"),  # push 64-bit double immediate
    0x1D: ("push_i64", "imm_i64"),  # push 64-bit int immediate
    0x1E: ("frame_addr", "frame_addr"),  # push frame_base + int32 offset
    # Batch 3c (research-log.md, "Batch 3c" section) - COM/array family
    0x37: ("interface_get", "iface_get"),  # property get via DAT_00461578
    0x39: ("com_create", "com_create"),  # CreateObject family
    0x3A: ("array_op", "array_op"),  # SAFEARRAY operations
    0x3B: ("array_element", "array_elem"),  # SAFEARRAY element access
    0x3C: ("memcpy", "memcpy"),  # block memory copy
    0x3D: ("object_assign", "obj_assign"),  # interface copy with refcount
    0x3E: ("com_assign", "com_assign"),  # COM ref assignment (Release/AddRef)
    0x20: ("load_global", "global3"),  # 16-bit index -> global/struct table
    0x22: ("load_global_deref", None),  # 0x20 handler then one indirection
    0x23: ("store_pointer", None),  # dispatch, save ptr, dispatch, store
    0x24: ("store_i32", None),  # store 4 bytes
    0x25: ("store_i32_round", None),  # store int32, double -> ROUND
    0x26: ("store_byte_round", None),  # store byte, double -> ROUND
    0x27: ("store_u16_round", None),  # store uint16, double -> ROUND
    0x28: ("store_i64", None),  # store 8 bytes
    0x29: ("store_double", None),  # store double
    0x2A: ("rmw_i32", None),  # read-modify-write int32
    0x2C: ("rmw_u8", None),  # read-modify-write byte
    0x2D: ("rmw_u16", None),  # read-modify-write uint16
    0x2E: ("rmw_i64", None),  # read-modify-write int64
    0x2F: ("rmw_8byte", None),  # read-modify-write 8-byte value
    0x30: ("double_to_int", None),  # double->int conversion, special cases
    0x31: ("get_window_handle", None),  # QM internal HWND
    0x32: ("get_foreground_window", None),  # GetForegroundWindow()
    0x33: ("for_loop", "for"),  # 16-bit label at +2, flag byte at +3
    0x34: ("deref_call", None),  # deref then method/interface dispatch
    # Pending-opcode batch (research-log.md, "Pending-opcode batch" section)
    0x4B: (
        "computed_var_access",
        "computed_var",
    ),  # uint16 var-idx +1, sub-opcode +3
    0x52: ("address_of_var", "addr_of_var"),  # 2 B: var-tag byte at +1
    # Log-exe opcode addendum (research-log.md, "Log-exe opcode addendum
    # (capstone inline RE, 2026-11-06)" section)
    0x4A: (
        "method_invoke",
        "method_invoke",
    ),  # 3 B fixed + dispatched sub-expression
    0x4F: ("var_access_deref", "var_access_deref"),  # 3 B: uint16 idx at +1
    # REA inline (research-log.md, "Opcode 0x49 = call_function_args" section):
    # real opcode in 2.4.12 (handler 0x429650 non-zero); never hit by 2.4.2
    # samples. 7-byte fixed part + argc dispatched argument sub-instructions.
    0x49: ("call_function_args", "call_args"),  # 49 sel tb1 tb2 argc u16 fnidx
}

# Phantom opcodes (research-log.md, "Pending-opcode batch" + "Final opcode
# batch (capstone inline RE, 2026-11-06)" + "QM 2.4.12 runtime addendum"):
# their handler VA in the dispatch table is 0x000000, i.e. they are NOT
# real opcodes - the disassembler walked into non-code data (ASCII text or
# uint16-table pairs). They are reported as DATA markers, not RE gaps.
# Static set because qmdis.py has no PE access (no pefile dep); union across
# both runtimes, validated against the dispatch tables, 2026-11-05/06. The
# 9999-site bytes `86 c9` are operand data (see research-log.md comparison-site
# reinterpretation), hence 0x86/0xc9 in the set.
# 2.4.2 builds (table PTR_FUN_00461038, 64 entries): 12 phantoms.
# 2.4.12 builds (table DAT_00472090, 87 entries 0x00-0x56): adds
# {0x58, 0x6f, 0x82, 0xad, 0xcc, 0xfe, 0xff} (handler VA = 0, verified via
# REA on sample05, 2026-11-06). 0x98 never occurs in any sample.
PHANTOM_OPCODES = {
    0x58,
    0x62,
    0x66,
    0x6F,
    0x70,
    0x77,
    0x7C,
    0x80,
    0x82,
    0x86,
    0xAD,
    0xB7,
    0xC9,
    0xCC,
    0xCE,
    0xE2,
    0xE7,
    0xFE,
    0xFF,
}

# Dispatch-table bound (REA read_bytes, 2026-11-07): both runtimes have valid
# handlers for indices 0x00..0x55 only (2.4.12 DAT_00472090: idx 0x55 =
# 0x4126f0, idx 0x56.. = 0; 2.4.2 PTR_FUN_00461038: idx 0x52..0x55 =
# 0x42a200/0x412450/0x412260/0x4122a0, idx 0x56 = 0). Any opcode byte >= 0x56
# has handler VA 0, i.e. it is DATA (checked directly for 0x71 in 2.4.12 and
# 0xac in 2.4.2), so the static set above is just the history of hits.
DISPATCH_TABLE_BOUND = 0x56  # static image only; see RUNTIME_TABLE1_VALID

# CORRECTION 2026-11-07 (docs/research-log.md "Level 2 full re-validation"):
# the PE image only holds the first 86 handlers. The startup function
# (FUN_0040abc4 in 2.4.2) fills ~99 more entries of table 1 at run time. The
# set below is the table AFTER initialization (runtime_tables.py; identical
# index set in 2.4.2 and 2.4.12). Only bytes outside this set are genuinely
# not opcodes (data). Opcodes 0x80..0xed in the set are REAL statement/control
# opcodes (if/out/ret/for/else...) whose semantics are NOT yet documented.
RUNTIME_TABLE1_VALID = frozenset(
    [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        29,
        30,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        60,
        61,
        62,
        63,
        64,
        65,
        66,
        67,
        68,
        69,
        70,
        71,
        72,
        73,
        74,
        75,
        76,
        77,
        78,
        79,
        80,
        81,
        82,
        83,
        84,
        85,
        128,
        130,
        131,
        132,
        133,
        134,
        135,
        136,
        137,
        138,
        139,
        140,
        141,
        142,
        145,
        147,
        148,
        149,
        150,
        151,
        152,
        153,
        154,
        155,
        156,
        157,
        159,
        160,
        161,
        162,
        163,
        164,
        165,
        166,
        167,
        168,
        169,
        170,
        171,
        172,
        173,
        174,
        175,
        176,
        177,
        178,
        179,
        180,
        182,
        183,
        184,
        185,
        186,
        187,
        188,
        189,
        190,
        191,
        192,
        193,
        194,
        195,
        196,
        197,
        198,
        199,
        200,
        201,
        203,
        204,
        205,
        206,
        207,
        208,
        209,
        210,
        211,
        212,
        213,
        214,
        215,
        217,
        218,
        219,
        221,
        222,
        223,
        225,
        226,
        227,
        229,
        230,
        231,
        232,
        233,
        234,
        235,
        236,
        237,
    ]
)


def is_phantom(opcode: int) -> bool:
    """True only for bytes that have NO handler even after runtime init.

    Args:
      opcode: The opcode byte to test.

    Returns:
      True if the opcode is not in RUNTIME_TABLE1_VALID.
    """
    return opcode not in RUNTIME_TABLE1_VALID


# ---------------------------------------------------------------------------
# Container parsing
# ---------------------------------------------------------------------------


def parse_res2_index(blob: bytes) -> list[dict]:
    """Parse res2: the bytecode index.

    Corrected layout (validated on the original-1 sample): 10 records x 20
    bytes,
        <H code_offset> <H flags> <H kind> <H flags2> <I size> <I offset>
    where code_offset is the record's first u16 (QM-internal id; role as a
    code offset is unverified), `size` is ACTUALLY the offset of the
    function's name inside decrypted res3 (verified 2026-11-07 on 12 exes and
    in runtime loader FUN_00401ff1), and `offset` is the function's data-block
    offset inside res4. The key name "size" is kept for compatibility.

    NOTE: qmtool.py's parse_bytecode_index() used to assume 16-byte records
    (fixed 2026-11-07); it now parses the same 20-byte layout as this function.

    Args:
      blob: The res2 payload.

    Returns:
      One dict per record (index, code_offset, flags, kind, flags2, size,
      data_offset); parsing stops at the first all-zero record.
    """
    records: list[dict] = []
    pos = 0
    while pos + 20 <= len(blob):
        code_off, flags, kind, flags2, size, offset = struct.unpack_from(
            "<HHHHII", blob, pos
        )
        if code_off == 0 and kind == 0 and size == 0 and offset == 0:
            break
        records.append(
            {
                "index": len(records),
                "code_offset": code_off,
                "flags": flags,
                "kind": kind,
                "flags2": flags2,
                "size": size,
                "data_offset": offset,
            }
        )
        pos += 20
    return records


def decrypt_res3(blob: bytes, key: bytes = KNOWN_QM_KEY) -> list[str]:
    """Decrypt res3 (identifier names); split into null-terminated strings.

    Args:
      blob: The encrypted res3 payload.
      key: Accepted for symmetry but not used; qm_decrypt() always uses its
        default key.

    Returns:
      The non-empty names, decoded as ASCII.
    """
    plain = qm_decrypt(blob)
    return [s.decode("ascii") for s in plain.split(b"\x00") if s]


HEADER_PTR_COUNT = 9  # relocated section pointers at the start of a block
HEADER_BASE_ADJUST = 0x48  # res4 offset that header pointer #0 refers to


def locate_stream_from_header(
    res4: bytes, block_off: int = 0
) -> tuple[int, int] | None:
    """Locate a function block's instruction stream from its header.

    Every res4 function block starts with 9 relocated u32 section pointers.
    Pointer #0 corresponds to block-relative offset 0x48, so
        stream_offset = block_off + (ptr1 - ptr0) + 0x48
        stream bytes  = ptr2 - ptr1   (u16 code offsets; a trailing 0 is
                                       4-byte alignment padding when the
                                       entry count is odd)
    Verified 2026-11-07 on block 0 of all 12 QM exes (it reproduces the
    scanner's answer wherever the scanner was right, and fixes 6 targets
    where the scanner picked another function's stream). Returns
    (stream_offset, n_entries) or None if the header is implausible.

    Args:
      res4: The res4 payload.
      block_off: Offset of the function block inside res4.

    Returns:
      (stream_offset, n_entries), or None if the header is implausible.
    """
    if block_off < 0 or block_off + 4 * HEADER_PTR_COUNT > len(res4):
        return None
    ptrs = struct.unpack_from("<%dI" % HEADER_PTR_COUNT, res4, block_off)
    d1, d2 = ptrs[1] - ptrs[0], ptrs[2] - ptrs[0]
    if not (0 < d1 < d2 < 0x10000) or (d2 - d1) % 2:
        return None
    start = block_off + d1 + HEADER_BASE_ADJUST
    count = (d2 - d1) // 2
    if start + 2 * count > len(res4):
        return None
    values = struct.unpack_from("<%dH" % count, res4, start)
    if values[0] != 0:
        return None
    if len(values) > 1 and values[-1] == 0:
        values = values[:-1]  # alignment padding
    return start, len(values)


def locate_code_and_stream(
    res4: bytes, code_base: int | None, stream_offset: int | None
) -> tuple[int, int, int]:
    """Locate the code base and the instruction stream inside res4.

    Validated layout (QM 2.4.2 exe original-1):
      0x00..0x24  9 relocated runtime pointers
      0x24..      counts / header fields
      0x4C..      code base (function code blocks, per res2 code_offset)
      0x46E..     instruction stream: uint16 offsets into the code base
      ...         per-function tables, then the string pool

    The stream is located from the block-0 header pointer table
    (locate_stream_from_header); only if the header is implausible does it
    fall back to scanning for the longest run of uint16 values
    that are all valid code offsets (< code region size) and non-decreasing.
    The run must be followed by a value that is NOT a valid code offset, which
    keeps the scan from running into the string-offset tables. The chosen
    offsets are reported in the output so they can be audited.

    Args:
      res4: The res4 payload.
      code_base: Code base offset, or None for the default 0x48.
      stream_offset: Instruction stream offset, or None to auto-locate.

    Returns:
      (code_base, stream_offset, code_end), where code_end is len(res4).

    Raises:
      ValueError: If the code base is outside res4 or no stream is found.
    """
    total = len(res4)
    if code_base is None:
        # block + 0x48 (FUN_00401add relocates header ptr0 to block+0x48 = code
        # base); the old 0x4C was wrong
        code_base = 0x48
    if code_base >= total:
        raise ValueError(
            f"code base 0x{code_base:x} outside res4 (size 0x{total:x})"
        )

    if stream_offset is not None:
        return code_base, stream_offset, total

    located = locate_stream_from_header(res4, 0)
    if located is not None:
        return code_base, located[0], total

    code_region_max = total - code_base
    best_start = None
    best_len = 0
    pos = code_base
    run_start = None
    run_len = 0
    prev_value = -1
    while pos + 2 <= total:
        (value,) = struct.unpack_from("<H", res4, pos)
        if value < code_region_max and value >= prev_value:
            if run_start is None:
                run_start = pos
                prev_value = -1
            run_len += 1
            prev_value = value
        else:
            if run_start is not None and run_len >= 8:
                if best_start is None or run_len > best_len:
                    best_start = run_start
                    best_len = run_len
            run_start = None
            run_len = 0
            prev_value = -1
        pos += 2
    if (
        run_start is not None
        and run_len >= 8
        and (best_start is None or run_len > best_len)
    ):
        best_start = run_start
    if best_start is None:
        raise ValueError(
            "could not locate the instruction stream in res4; "
            "pass --stream-offset explicitly"
        )
    stream_offset = best_start
    return code_base, stream_offset, total


# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------


def disassemble(
    res4: bytes,
    code_base: int,
    stream_offset: int,
    code_end: int,
    entry_count: int | None = None,
) -> dict:
    """Walk the instruction stream and decode each instruction.

    The stream gives every instruction start, so no linear sweep and no
    instruction-length table is needed. Operand bytes are shown as context
    hex; only formats explicitly documented in research-log.md are annotated.

    Args:
      res4: The res4 payload.
      code_base: Offset of the code region inside res4.
      stream_offset: Offset of the instruction stream inside res4.
      code_end: Offset where the code region ends.
      entry_count: Maximum number of stream entries to read, or None to read
        until the stream stops being non-decreasing.

    Returns:
      A dict with code_base_offset, code_size, stream_offset, stream_entries,
      documented_counts, undocumented, data_markers and listing.

    Raises:
      ValueError: If no stream entries are found.
    """
    code = res4[code_base:code_end]
    entries: list[int] = []
    pos = stream_offset
    prev_value = -1
    while pos + 2 <= len(res4):
        if entry_count is not None and len(entries) >= entry_count:
            break
        (value,) = struct.unpack_from("<H", res4, pos)
        # The stream is non-decreasing; a drop means we've left the stream
        # (e.g. run into the per-function tables or the string pool).
        if value >= len(code) or value < prev_value:
            break
        entries.append(value)
        prev_value = value
        pos += 2

    if not entries:
        raise ValueError(
            "no instruction stream entries found - "
            "check --code-base/--stream-offset"
        )

    listing: list[dict] = []
    undocumented: dict[int, list[dict]] = {}
    data_markers: dict[int, list[dict]] = {}
    documented_counter: Counter[int] = Counter()

    for index, offset in enumerate(entries):
        opcode = code[offset]
        next_offset = entries[index + 1] if index + 1 < len(entries) else None
        if is_phantom(opcode):
            # Handler VA = 0x000000 in the dispatch table (research-log.md):
            # data misdecoded as code, not a real opcode. Report as a DATA
            # marker so it does not surface as an RE gap.
            record = {
                "stream_index": index,
                "code_offset": offset,
                "opcode": opcode,
                "context": code[offset : offset + 8].hex(" "),
            }
            data_markers.setdefault(opcode, []).append(record)
            listing.append(
                {
                    **record,
                    "mnemonic": f"DATA_0x{opcode:02x}",
                    "status": "data",
                }
            )
            continue
        info = DOCUMENTED_OPCODES.get(opcode)
        if info is None:
            record = {
                "stream_index": index,
                "code_offset": offset,
                "opcode": opcode,
                "context": code[offset : offset + 8].hex(" "),
            }
            undocumented.setdefault(opcode, []).append(record)
            listing.append(
                {
                    **record,
                    "mnemonic": f"UNDocumented_0x{opcode:02x}",
                    "status": "RAISED",
                }
            )
            continue

        mnemonic, operand_format = info
        documented_counter[opcode] += 1
        entry: dict = {
            "stream_index": index,
            "code_offset": offset,
            "opcode": opcode,
            "mnemonic": mnemonic,
            "status": "ok",
        }
        # Annotate only the formats research-log.md explicitly documents.
        if operand_format == "call7" and offset + 7 <= len(code):
            (func_index,) = struct.unpack_from("<H", code, offset + 5)
            entry["operand"] = {
                "function_index": func_index,
                "length": 7,
                "note": (
                    "index at +5 verified against handler "
                    "0x429200 (movzx eax, word ptr [edi+5]); "
                    "looked up via FUN_0042911d linear search "
                    "over 12-byte records (DAT_00461bec), "
                    "NOT a direct res2 fn index"
                ),
            }
        elif operand_format == "block" and offset + 3 <= len(code):
            (block_len,) = struct.unpack_from("<H", code, offset + 1)
            entry["operand"] = {
                "block_length": block_len,
                "total_length": 3 + block_len + 4,
                "note": (
                    "length at +1; 4 trailing bytes after body "
                    "(validated against stream deltas)"
                ),
            }
        elif operand_format == "global3" and offset + 3 <= len(code):
            (table_index,) = struct.unpack_from("<H", code, offset + 1)
            entry["operand"] = {"table_index": table_index, "length": 3}
        elif operand_format == "for" and offset + 4 <= len(code):
            (loop_label,) = struct.unpack_from("<H", code, offset + 2)
            flag_byte = code[offset + 3]
            entry["operand"] = {
                "loop_label": loop_label,
                "flags": f"0x{flag_byte:02x}",
                "flag_bits": {
                    "step_given": bool(flag_byte & 1),
                    "bounds_64bit": bool(flag_byte & 2),
                    "counter_64bit": bool(flag_byte & 4),
                },
            }
        elif operand_format == "type2_u16" and offset + 4 <= len(code):
            (field_offset,) = struct.unpack_from("<H", code, offset + 2)
            entry["operand"] = {"field_offset": field_offset}
        # ---- Batch 3 operand formats ----
        elif operand_format == "imm_i32" and offset + 5 <= len(code):
            (value,) = struct.unpack_from("<i", code, offset + 1)
            entry["operand"] = {"immediate": value, "length": 5}
        elif operand_format == "imm_u32" and offset + 5 <= len(code):
            (value,) = struct.unpack_from("<I", code, offset + 1)
            entry["operand"] = {
                "immediate": value,
                "unsigned": True,
                "length": 5,
            }
        elif operand_format == "imm_i8" and offset + 2 <= len(code):
            entry["operand"] = {"immediate": code[offset + 1], "length": 2}
        elif operand_format == "imm_f64" and offset + 9 <= len(code):
            (value,) = struct.unpack_from("<d", code, offset + 1)
            entry["operand"] = {
                "immediate": value,
                "type": "double",
                "length": 9,
            }
        elif operand_format == "imm_i64" and offset + 9 <= len(code):
            (value,) = struct.unpack_from("<q", code, offset + 1)
            entry["operand"] = {
                "immediate": value,
                "type": "int64",
                "length": 9,
            }
        elif operand_format == "frame_addr" and offset + 5 <= len(code):
            (frame_offset,) = struct.unpack_from("<i", code, offset + 1)
            entry["operand"] = {"frame_offset": frame_offset, "length": 5}
        elif operand_format == "local3" and offset + 3 <= len(code):
            (local_index,) = struct.unpack_from("<H", code, offset + 1)
            entry["operand"] = {"local_index": local_index, "length": 3}
        elif operand_format == "var_access" and offset + 4 <= len(code):
            # 0x01: handler 0x42a1f0 does IP+=1, then helper FUN_00429f80(0)
            # does IP+=3 and reads the uint16 at +2 (value path, mode 0).
            (var_index,) = struct.unpack_from("<H", code, offset + 2)
            entry["operand"] = {
                "tag": f"0x{code[offset + 1]:02x}",
                "var_index": var_index,
                "length": 4,
            }
        elif operand_format == "deref_sub" and offset + 2 <= len(code):
            # 0x0c/0x0d/0x0e: IP+=1, then the next opcode is dispatched to
            # evaluate the pointer; slot must be >= 0x10000 (else runtime
            # error 0x23c); then int16 sign-extended / qword loaded.
            entry["operand"] = {
                "sub_opcode": f"0x{code[offset + 1]:02x}",
                "length": 2,
            }
        elif operand_format == "computed_var" and offset + 4 <= len(code):
            # 0x4b: IP+=3, sub-opcode at +3 dispatched (evaluates the index);
            # uint16 at +1 indexes 8-byte records in var table [ctx+0x24]+8.
            (var_index,) = struct.unpack_from("<H", code, offset + 1)
            entry["operand"] = {
                "var_index": var_index,
                "sub_opcode": f"0x{code[offset + 3]:02x}",
                "length": 4,
            }
        elif operand_format == "addr_of_var" and offset + 2 <= len(code):
            # 0x52: IP+=1, tag byte dispatched as opcode (evaluates the
            # variable), getter called with -1 -> result = variable address.
            entry["operand"] = {
                "var_tag": f"0x{code[offset + 1]:02x}",
                "length": 2,
            }
        elif operand_format == "method_invoke" and offset + 3 <= len(code):
            # 0x4a: handler 0x429d3f does IP+=1, resolves the object/fn ref
            # via FUN_004291b0(code+IP) (uint16 at +1), IP+=2, then dispatches
            # the next opcode (evaluates the argument) and finally does the
            # virtual call [vtbl+0x10](obj, value). The fixed part is 3 bytes
            # but the dispatched sub-expression has variable length.
            (obj_ref,) = struct.unpack_from("<H", code, offset + 1)
            entry["operand"] = {
                "object_ref_index": obj_ref,
                "fixed_length": 3,
                "total_length": (
                    next_offset - offset if next_offset is not None else None
                ),
                "note": (
                    "fixed part 3 B; sub-expression after it is variable "
                    "length - total_length taken from the next stream "
                    "entry, UNVALIDATED (same caveat as 0x16/0x35/0x3e; "
                    "see docs/FORMAT.md stream-structure open item)"
                ),
            }
        elif operand_format == "var_access_deref" and offset + 3 <= len(code):
            # 0x4f: helper 0x4121e0 does IP+=3, reads the uint16 at +2,
            # indexes 8-byte var records (type tag word at +4 clamped <=0xff,
            # extra byte at +6); handler derefs one pointer level.
            (var_index,) = struct.unpack_from("<H", code, offset + 1)
            entry["operand"] = {
                "var_index": var_index,
                "length": 3,
            }
        elif operand_format == "call_args" and offset + 7 <= len(code):
            # 0x49: handler 0x429650 (2.4.12). 7-byte fixed part: result
            # width selector at +1, type tag/flags at +2/+3, argc at +4,
            # uint16 function index at +5 (looked up via helper 0x429520 in
            # the 12-byte-record function table at 0x473bc8). Then argc
            # dispatched sub-instructions (the arguments) - variable total
            # length.
            argc = code[offset + 4]
            (fn_index,) = struct.unpack_from("<H", code, offset + 5)
            entry["operand"] = {
                "result_selector": code[offset + 1],
                "type_tag": f"0x{code[offset + 2]:02x}",
                "type_flags": f"0x{code[offset + 3]:02x}",
                "arg_count": argc,
                "function_index": fn_index,
                "fixed_length": 7,
                "total_length": (
                    next_offset - offset if next_offset is not None else None
                ),
                "note": (
                    "fixed part 7 B; argc argument sub-instructions after "
                    "it are variable length - total_length taken from the "
                    "next stream entry, UNVALIDATED (stream-structure open "
                    "item)"
                ),
            }
        # ---- Final opcode batch (research-log.md, "Final opcode batch
        # (capstone inline RE, 2026-11-06)" section) ----
        elif operand_format == "index_addr" and offset + 3 <= len(code):
            # 0x18: handler 0x411e50. CORRECTED 2026-11-07 (REA bytes +
            # capstone): layout is `18 <sub-expr A: base ptr> <sub-expr B:
            # index> <u16 stride>`. IP+=1; dispatch A; dispatch B; IP+=2;
            # result = A + B * uint16(stride at the END of the instruction).
            # The old note (stride right after the opcode, one sub-expression)
            # was wrong. Total length is variable: taken from the next stream
            # entry; the stride is the last 2 bytes of that span.
            total = next_offset - offset if next_offset is not None else None
            op = {
                "fixed_length": 1,
                "total_length": total,
                "note": (
                    "18 <A> <B> <u16 stride>; sub-expressions variable, "
                    "total_length from next stream entry (stream "
                    "entries may also mark sub-expressions: UNVALIDATED)"
                ),
            }
            if total and total >= 4:
                (op["stride_if_span_exact"],) = struct.unpack_from(
                    "<H", code, offset + total - 2
                )
            entry["operand"] = op
        elif operand_format == "query_iface" and offset + 3 <= len(code):
            # 0x43: handler 0x415316 (2.4.2), bytes read via REA 2026-11-07.
            # IP+=3; u16 at +1 = IID index (16-byte entries, table at
            # [ctx+0x24]+0x1c, same table opcode 0x39 uses); then ONE
            # sub-expression is dispatched (the COM object); then
            # obj->vtbl[0](obj, &IID, &result) = IUnknown::QueryInterface;
            # non-zero HRESULT -> error helper 0x412fd5. Seen only inside the
            # Acc.* library stubs (`43 00 00 0a 12 1f 00 00` in Acc.Find).
            (iid,) = struct.unpack_from("<H", code, offset + 1)
            entry["operand"] = {
                "iid_index": iid,
                "fixed_length": 3,
                "total_length": (
                    next_offset - offset if next_offset is not None else None
                ),
                "note": (
                    "3 B fixed + object sub-expression; high confidence "
                    "on mechanics (handler bytes), medium on the QM-level name"
                ),
            }
        elif operand_format == "typed_store" and offset + 2 <= len(code):
            # 0x36: IP+=1; read tag byte (IP+=1); dispatch next opcode
            # (evaluates the value); tag byte selects width/type (handler
            # 0x424dcc type-tag switch). Variable total length.
            entry["operand"] = {
                "type_tag": f"0x{code[offset + 1]:02x}",
                "sub_opcode": f"0x{code[offset + 2]:02x}",
                "fixed_length": 3,
                "total_length": (
                    next_offset - offset if next_offset is not None else None
                ),
                "note": (
                    "variable length (sub-expression); total_length "
                    "UNVALIDATED (stream-structure open item)"
                ),
            }
        elif operand_format == "slot_store" and offset + 3 <= len(code):
            # 0x38: 3-byte fixed part `38 <tag> <sub-opcode>`; IP+=1; read
            # 2 tag bytes; dispatch next opcode (evaluates the value); then
            # the >= 0x10000 slot check -> store into slot (same family as
            # 0x37/0x3a/0x3c/0x3d). Variable total length (sub-expression).
            entry["operand"] = {
                "tag": f"0x{code[offset + 1]:02x}",
                "sub_opcode": f"0x{code[offset + 2]:02x}",
                "fixed_length": 3,
                "total_length": (
                    next_offset - offset if next_offset is not None else None
                ),
                "note": (
                    "fixed part 3 B; value sub-expression after it is "
                    "variable length - total_length taken from the next "
                    "stream entry, UNVALIDATED (stream-structure open item)"
                ),
            }
        elif operand_format == "method_invoke_3null" and offset + 3 <= len(
            code
        ):
            # 0x3f: 3-byte instruction `3F <tag> <sub-opcode>`; IP+=1; read
            # tag byte; dispatch next opcode (evaluates the value); call
            # helper 0x413cd0(tag, value, 0, 0, 0) -> method invocation with
            # 3 null args (same family as 0x4a method_invoke). Variable
            # total length (sub-expression).
            entry["operand"] = {
                "tag": f"0x{code[offset + 1]:02x}",
                "sub_opcode": f"0x{code[offset + 2]:02x}",
                "fixed_length": 3,
                "total_length": (
                    next_offset - offset if next_offset is not None else None
                ),
                "note": (
                    "fixed part 3 B; value sub-expression after it is "
                    "variable length - total_length taken from the next "
                    "stream entry, UNVALIDATED (stream-structure open item)"
                ),
            }
        elif operand_format == "iface_get" and offset + 3 <= len(code):
            entry["operand"] = {
                "sub_opcode": f"0x{code[offset + 1]:02x}",
                "dispatch_index": code[offset + 2],  # index into DAT_00461578
                "length": 3,
            }
        elif operand_format == "com_create" and offset + 4 <= len(code):
            kind = code[offset + 1]
            entry["operand"] = {
                "kind": kind,
                "arg_count": code[offset + 2],
                "flags": f"0x{code[offset + 3]:02x}",
                "length": 4,
            }
        elif operand_format == "array_op" and offset + 3 <= len(code):
            entry["operand"] = {
                "op": code[offset + 1],
                "arg_count": code[offset + 2],
                "length": 4,
            }
        elif operand_format == "array_elem" and offset + 3 <= len(code):
            # Batch-3c finding: element-type 0/0x24 means the instruction
            # carries 3 extra bytes (total 6, not 4). 0 hits in original-1
            # sample, so this annotation is unvalidated (docs/batch3-c.md).
            extra = 3 if code[offset + 2] in (0x00, 0x24) else 0
            entry["operand"] = {
                "index_count": code[offset + 1],  # 0 = append
                "element_type": f"0x{code[offset + 2]:02x}",
                "length": 4 + extra,
            }
        elif operand_format == "memcpy" and offset + 4 <= len(code):
            (byte_count,) = struct.unpack_from("<H", code, offset + 2)
            entry["operand"] = {"byte_count": byte_count, "length": 4}
        elif operand_format == "obj_assign" and offset + 4 <= len(code):
            (table_index,) = struct.unpack_from("<H", code, offset + 2)
            entry["operand"] = {"table_index": table_index, "length": 4}
        elif operand_format in ("index_elem", "com_assign", "obj_op"):
            # Variable-length instructions whose tail is sub-instructions
            # (0x16, 0x35, 0x3e). CAVEAT: the next stream entry is only
            # ASSUMED to mark the end of this instruction; the first-pass
            # "delta = instruction length" assumption did not hold in
            # general (see docs/FORMAT.md, stream-structure open item).
            # None of these three opcodes occur in the original-1 sample, so
            # this
            # annotation is unvalidated.
            instr_len = (
                next_offset - offset if next_offset is not None else None
            )
            operand: dict = {"length": instr_len}
            if operand_format == "index_elem" and instr_len and instr_len >= 4:
                (stride,) = struct.unpack_from(
                    "<H", code, offset + instr_len - 2
                )
                operand["element_stride"] = stride
            if operand_format == "index_elem" and instr_len and instr_len >= 3:
                operand["sub_instruction_a"] = f"0x{code[offset + 1]:02x}"
                operand["sub_instruction_b"] = f"0x{code[offset + 2]:02x}"
            elif (
                operand_format == "com_assign" and instr_len and instr_len >= 3
            ):
                operand["sub_instruction_a"] = f"0x{code[offset + 1]:02x}"
                operand["sub_instruction_b"] = f"0x{code[offset + 2]:02x}"
            entry["operand"] = operand
        entry["context"] = code[offset : offset + 8].hex(" ")
        listing.append(entry)

    return {
        "code_base_offset": code_base,
        "code_size": len(code),
        "stream_offset": stream_offset,
        "stream_entries": len(entries),
        "documented_counts": {
            f"0x{op:02x}": n for op, n in sorted(documented_counter.items())
        },
        "undocumented": {
            f"0x{op:02x}": recs for op, recs in sorted(undocumented.items())
        },
        "data_markers": {
            f"0x{op:02x}": recs for op, recs in sorted(data_markers.items())
        },
        "listing": listing,
    }


def decode_all_functions(res2_blob: bytes, res4: bytes) -> list[dict]:
    """Disassemble EVERY function block of res4 (not just block 0).

    Each block starts with the 9-pointer header (see locate_stream_from_header)
    and its code base is block_off + 0x48 (FUN_00401add relocates header
    pointer 0 to block+0x48; CORRECTED from 0x4c on 2026-11-07). Returns one
    dict per res2 record: {"index", "kind", "block_off",
    "stream_offset", "entry_count", "result" or "error"}.

    Args:
      res2_blob: The res2 payload (function table).
      res4: The res4 payload.

    Returns:
      One dict per res2 record, as described above.
    """
    records = parse_res2_index(res2_blob)
    starts = sorted(r["data_offset"] for r in records) + [len(res4)]
    out = []
    for rec in records:
        b = rec["data_offset"]
        end = starts[starts.index(b) + 1]
        item = {"index": rec["index"], "kind": rec["kind"], "block_off": b}
        loc = locate_stream_from_header(res4, b)
        if loc is None:
            item["error"] = "block header not plausible"
        else:
            item["stream_offset"], item["entry_count"] = loc
            try:
                item["result"] = disassemble(
                    res4, b + 0x48, loc[0], end, loc[1]
                )
            except ValueError as exc:
                item["error"] = str(exc)
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Runs the command line tool.

    Returns:
      The process exit code: 2 if undocumented opcodes or errors were found,
      else 0.
    """
    parser = argparse.ArgumentParser(
        description="Level 2 bytecode disassembler for Quick Macros exes"
    )
    parser.add_argument(
        "input",
        type=Path,
        help="res4.bin payload, or a directory containing "
        "res2.bin/res3.bin/res4.bin",
    )
    parser.add_argument(
        "--code-base",
        type=lambda x: int(x, 0),
        default=None,
        help="code base offset inside res4 (default: 0x48)",
    )
    parser.add_argument(
        "--stream-offset",
        type=lambda x: int(x, 0),
        default=None,
        help="instruction stream offset inside res4 " "(default: auto-locate)",
    )
    parser.add_argument(
        "--code-end",
        type=lambda x: int(x, 0),
        default=None,
        help="code region end offset (default: stream start)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write the listing to this file",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="disassemble every function block listed in "
        "res2 (directory input only), not just block 0",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=20,
        help="stop after this many distinct undocumented opcodes",
    )
    args = parser.parse_args()

    path = args.input
    if path.is_dir():
        res2_blob = (path / "res2.bin").read_bytes()
        res3_blob = (path / "res3.bin").read_bytes()
        res4 = (path / "res4.bin").read_bytes()
    else:
        res2_blob = b""
        res3_blob = b""
        res4 = path.read_bytes()
        if res4[:2] == b"MZ":
            parser.error(
                f"{path} is a PE executable, not a res4 payload. "
                "Extract it first (python qmtool.py <exe> -o <dir>) "
                "and pass the directory (or <dir>/res4.bin)."
            )

    print(f"res4: {len(res4)} bytes")
    if res2_blob:
        records = parse_res2_index(res2_blob)
        print(f"res2 index: {len(records)} records x 20 bytes")
        for rec in records:
            print(
                f"  fn{rec['index']}: code_off=0x{rec['code_offset']:04x} "
                f"kind={rec['kind']} size={rec['size']} "
                f"data@0x{rec['data_offset']:04x}"
            )
    if res3_blob:
        identifiers = decrypt_res3(res3_blob)
        print(
            f"res3 identifiers ({len(identifiers)}): "
            + ", ".join(identifiers[:6])
            + (" ..." if len(identifiers) > 6 else "")
        )

    if args.all:
        if not res2_blob:
            parser.error(
                "--all needs a directory with res2.bin/res3.bin/res4.bin"
            )
        names = decrypt_res3(res3_blob) if res3_blob else []
        rc = 0
        for item in decode_all_functions(res2_blob, res4):
            nm = names[item["index"]] if item["index"] < len(names) else "?"
            if "error" in item:
                print(
                    f"fn{item['index']} {nm} (kind {item['kind']}): "
                    f"ERROR {item['error']}"
                )
                rc = 2
                continue
            res = item["result"]
            und = sorted(res["undocumented"])
            print(
                f"fn{item['index']} {nm} (kind {item['kind']}) "
                f"block 0x{item['block_off']:x} "
                f"stream 0x{item['stream_offset']:x} "
                f"entries {res['stream_entries']}: "
                f"undocumented={und or 'none'} "
                f"data={sorted(res['data_markers']) or 'none'}"
            )
            if und:
                rc = 2
        return rc

    code_base, stream_offset, code_end = locate_code_and_stream(
        res4, args.code_base, args.stream_offset
    )
    print(f"code base: 0x{code_base:x}, stream @ 0x{stream_offset:x}")

    result = disassemble(res4, code_base, stream_offset, code_end)

    print(f"stream entries: {result['stream_entries']}")
    print("documented opcodes decoded:")
    for op, count in result["documented_counts"].items():
        mnemonic = DOCUMENTED_OPCODES[int(op, 16)][0]
        print(f"  {op} {mnemonic}: {count}")
    if result["data_markers"]:
        print("phantom opcodes reported as DATA (handler VA = 0, not RE gaps):")
        for op, recs in result["data_markers"].items():
            first = recs[0]
            print(
                f"  {op}: {len(recs)} hit(s), first at code offset "
                f"0x{first['code_offset']:04x}, bytes {first['context']}"
            )
    if result["undocumented"]:
        print("UNDOCUMENTED opcodes raised (RE gaps):")
        for op, recs in result["undocumented"].items():
            first = recs[0]
            print(
                f"  {op}: {len(recs)} hit(s), first at code offset "
                f"0x{first['code_offset']:04x}, bytes {first['context']}"
            )
    else:
        print("no undocumented opcodes encountered")

    if args.output:
        import json

        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"listing written to {args.output}")

    return 2 if result["undocumented"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
