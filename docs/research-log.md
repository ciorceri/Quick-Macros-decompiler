# Research log

Technical findings, in the order they were established, with the evidence they rest on. This is the redacted
form of the project's internal working notes: statements about the three private QM 2.4.2 executables used early
on are written generically (`original-1/2/3`), their script-specific content has been removed, and
administrative chatter is dropped. Handler addresses are virtual addresses in the stock QM runtimes
(image base 0x400000); `FUN_xxxxxxxx` names are Ghidra labels.

How to read it:

* Sections are append-mostly. A section that says **SUPERSEDED** or **CORRECTED** was wrong; the newer
  section wins. For the current model read `FORMAT.md`, `OPCODES.md` and the last sections here
  ("Level 2 full re-validation", "Level 2 byte-layout model", "Level 3 groundwork", and the addenda).
* "Level 1" = container extraction, "Level 2" = bytecode layout, "Level 3" = decompiler.
* Earlier opcode batches (3a, 3b, 3c, "pending", "final") contain opinions that were later corrected by the
  run-time dispatch-table discovery; they are kept because they carry handler evidence.
* Counts quoted inside old sections (exes, tiling totals) refer to the corpus at that time, not to the public
  samples. Run the audit on your own corpus for current numbers.
* Lines that referred to private files or sessions were removed, so some tables or lists are shorter than
  the original.

## Lessons (kept from the project history)

* A wrong base offset (`+0x4c` instead of `+0x48`) made every earlier annotation plausible but wrong; exact tiling found it.
* "Phantom opcodes" were a mistake: the PE only holds part of the dispatch table, the runtime fills the rest.
* Tiling of a length-prefixed block does not validate its nested arguments.
* Table-2 comparison operators were first labelled with the opposite sense; handler code (`cmp LHS,RHS; j<cc> skip`) shows `0x0e` is `>`.
* A note that `d1` was a store instruction was false; it is the `rep` loop.
* Using `/* */` for decompiler notes produced invalid QM; QM comments are `;;note` or lines starting with `;`.


Durable findings from the analysis. Every entry cites evidence. Append-only
by convention; superseded entries get a "SUPERSEDED" note, not deletion.

## Resource 252 container layout (validated on all 3 exes)

> **RE-AUDITED 2026-11-07 (see "Level 1 re-audit" at the end of this file).**
> Resource numbers below are the PE resource **NAME** ids, which are what the
> runtime loader uses. QM uses names 1,2,3,4,6,8,9 (there is no 5 or 7 in
> these exes; names 5, 7, 10 are optional and simply absent). `qmtool.py`
> now writes `res<name>.bin` accordingly; before 2026-11-07 it numbered
> files by position (res5/res6/res7 = names 6/8/9). Where this section says
> "res3 = code base" or "bytecode in res3" it is SUPERSEDED: res3 holds the
> encrypted function/identifier NAMES; the code lives in per-function blocks
> inside res4.

**CORRECTED 2026-11-05 (Level 2 breakthrough — supersedes the old model):**
the bytecode is in **res3 (encrypted)**, NOT res4. Evidence: initializer
`FUN_00401ff1` (0x401ff1) loads res3 as the code base (decrypted) and res4
as the data/string base (not decrypted).

| Entry | Size (original-1) | Content (corrected) |
|---|---|---|
| 2 | 200 | Function table: 10 records × 20 bytes: `<H id><H flags><H kind><H flags2><I name_off into decrypted res3><I block_off into res4><I blob_off (res5, 0 here)>`. NOTE: the 5th field is a **name offset, not a size** (verified 2026-11-07, all 12 QM exes + loader FUN_00401ff1) |
| 4 | 6828 | **String/constant pool + per-function data blocks** (NOT encrypted) |
| 6 | 73 | Global-variable definitions (loaded as PE name 6 by FUN_004022f3; **NOT encrypted**, corrected 2026-11-05): structured binary, entropy ~2.1, 48/73 zero bytes; shares long common subsequences with the other exes' res5 (just reordered) — impossible for encrypted data. Layout partially mapped: `<H count>` + `<HH>`-pair records + dword block; exact field semantics still unknown. (Formerly listed twice as "5" and "6"; positional file name `res5.bin`.) |
| 8 | 35 | DLL names (null-separated): user32, kernel32, wtsapi32, oleacc |
| 9 | 232 | Dynamically loaded API names |

## Encryption (recovered from FUN_00438c3b, verified)

4-byte-key XOR chain, key table at VA **0x455854** = `5d 91 38 6f`.
Decrypts backward from last byte to first:

```python
k = KEY[n & 3]
for i in range(n - 1, -1, -1):
    b = data[i]
    out[i] = b ^ k
    k = (KEY[i & 3] + b) & 0xFF
```

Verified: res3 (132 B) decrypts to readable QM identifier names.

### Key validation across builds (2026-11-05)

The key is **identical in all 3 QM exes, at the same address**:

| File | Key @ VA 0x455854 | res3 decrypts? |
|---|---|---|
| `original-3` | `5d 91 38 6f` | ✅ |

- Same key, same place: RVA `0x55854` (VA `0x455854`, image base `0x400000`).
- It is a **runtime constant, not per-script** — the key lives in the QM
  influence it.
- Cross-validated functionally: each exe's res3 decrypts to clean,
  script-specific identifier names.
- **Guard in qmtool.py**: `check_runtime_key()` reads the key at RVA 0x55854
  and compares against `KNOWN_QM_KEY` (`5d91386f`). If a future build stores
  a different key (or none), the report says `DIFFERENT KEY` / `absent` and
  res3 decryption is skipped instead of silently producing garbage.

## Interpreter dispatch loop (FOUND 2026-11-05 — plan item 2.1 complete)

**`FUN_00420730` is the QM bytecode interpreter dispatch loop.** Verified via
decompilation:

```c
// VM state: param_1 (thread context), instruction stream = 16-bit offsets
uVar2 = *(ushort *)(param_1[9] + 0x28);          // instruction count
iVar3 = *(int *)(param_1[9] + 4);                 // instruction stream base
while (iVar4 < instruction_count) {
    param_1[5] = *(ushort *)(iVar3 + iVar4 * 2);  // fetch 16-bit code offset
    // dispatch: handler = table[opcode_byte], opcode = first byte at code offset
    (*(code *)(&PTR_FUN_00461038)[*(byte *)(param_1[4] + param_1[5])])();
    iVar4++;   // handlers can modify the counter (jumps/loops)
}
```

**Key facts:**
- Instruction stream = array of 16-bit offsets into the code base (res3, decrypted)
- Opcode = first byte at the current code offset
- Handler table: `PTR_FUN_00461038` (VA 0x461038), **64 entries** (opcodes 0x00–0x3F)
- Handlers can modify the instruction counter (jump/loop opcodes)
- `param_1[4]` = code base (res3 decrypted), `param_1[5]` = current code offset

### Full call chain (verified, main entry → interpreter)

```
FUN_0040168d  main entry: creates "QM_ExeManager" window, SetTimer, runs setup
  └─ FUN_0040278f  startup orchestrator:
       FUN_0040abc4
       FUN_00401ff1  script initializer (loads PE names 2,3,4,5; decrypts res3)
       FUN_004026d3  identifier + string-pool loader
       FUN_004022f3  global-variable initializer (loads PE name 6; switches on its type tags
                     0xd/0xf/0x13/0x21/0x27/0x28 — confirms res6 = global
                     variable definitions)
       FUN_00401b87  name-pool loader (count + 2*count null-terminated strings)
       FUN_0040248d  per-function setup (loads count + 8-byte records)
  └─ FUN_00404210  thread launcher (FUN_00401147 → FUN_00403d02)
       └─ FUN_0040303a  thread body: resolves function by index
            └─ FUN_00403999  executor wrapper
                 └─ FUN_00402ed5  thread setup (frame, EnumThreadWindows)
                      └─ FUN_00420730  ★ INTERPRETER DISPATCH LOOP
```

### Opcode handler table (PTR_FUN_00461038, 64 entries, extracted 2026-11-05)

Raw bytes (little-endian DWORDs, handler VAs):

```
0x00: 0x004206c0   0x01: 0x0042a1f0   0x02: 0x00429200   0x03: 0x00411ec0
0x04: 0x004122d0  0x05: 0x00412320  0x06: 0x00412380  0x07: 0x004123d0
0x08: 0x00412400  0x09: 0x00411f30  0x0a: 0x00411f70  0x0b: 0x00411fb0
0x0c: 0x00411ff0  0x0d: 0x00412030  0x0e: 0x00412070  0x0c: 0x00411bb0
0x0d: 0x00411bf0  0x0e: 0x00411c30  0x0f: 0x00411c60  0x0c: 0x00411cc0
0x0d: 0x00412720  0x0e: 0x00411d00  0x0f: 0x00411d60  0x0f: 0x00411df0
0x10: 0x00411e50  0x11: 0x0040e725  0x12: 0x0040e748  0x13: 0x0040e769
0x14: 0x0040e78b  0x15: 0x0040e7a8  0x16: 0x0040e7ce  0x17: 0x004120b0
0x18: 0x00412770  0x19: 0x004120f0  0x19: 0x004127c0  0x1a: 0x00411a70
0x1a: 0x0004f0d0  0x1b: 0x0004f140  0x1c: 0x0004f140  0x1d: 0x0004f260
0x1e: 0x0000f340  0x1e: 0x0007f340  0x1f: 0x000e0f34  0x20: 0x0005f440
0x21: 0x0000f440  0x22: 0x0009f540  0x23: 0x0003f640  0x24: 0x000b0f64
0x25: 0x0042665c  0x26: 0x00427503  0x27: 0x0042848e  0x28: 0x00420d30
0x29: 0x00424ca4  0x2a: 0x00424dc4  0x2b: 0x00424dcc  0x2c: 0x0042342b
0x2d: 0x00414a60  0x2e: 0x004155c1  0x2f: 0x004161ef  0x30: 0x00416855
0x31: 0x00416855  0x32: 0x00411ab0  0x33: 0x00411b20  0x31: 0x004252a1
0x32: 0x0042526c
```

(Note: some indices above repeat due to hex-dump alignment; the authoritative
0x0040e959/0x0040e7xx range and 0x0042xxxx range are the two handler families.)

### Opcode handler tables (correctly aligned, extracted 2026-11-05)

**Table 1 — top-level dispatch (PTR_FUN_00461038, VA 0x461038):**

```
0x00: 0x4206c0  0x01: 0x42a1f0  0x02: 0x429200  0x03: 0x411ec0
0x04: 0x4122d0  0x05: 0x412320  0x06: 0x412380  0x07: 0x4123d0
0x08: 0x412400  0x09: 0x411f30  0x0a: 0x411f70  0x0b: 0x411fb0
0x0c: 0x411ff0  0x0d: 0x412030  0x0e: 0x412070  0x0f: 0x411bb0
0x10: 0x411bf0  0x11: 0x411c30  0x12: 0x411c60  0x13: 0x411cc0
0x14: 0x412720  0x15: 0x411d00  0x16: 0x411d60  0x17: 0x411df0
0x18: 0x411e50  0x19: 0x40e725  0x1a: 0x40e748  0x1b: 0x40e769
0x1c: 0x40e78b  0x1d: 0x40e7a8  0x1e: 0x40e7ce  0x1f: 0x4120b0
0x20: 0x412770  0x21: 0x4120f0  0x22: 0x4127c0  0x23: 0x411a70
0x24: 0x40f0d0  0x25: 0x40f140  0x26: 0x40f1d0  0x27: 0x40f260
0x28: 0x40f300  0x29: 0x40f370  0x2a: 0x40f3e0  0x2b: 0x40f450
0x2c: 0x40f4f0  0x2d: 0x40f590  0x2e: 0x40f630  0x2f: 0x40f6b0
0x30: 0x42665c  0x31: 0x427503  0x32: 0x42848e  0x33: 0x420d30
0x34: 0x424ca4  0x35: 0x424dc4  0x36: 0x424dcc  0x37: 0x42342b
0x38: 0x414a60  0x39: 0x4155c1  0x3a: 0x4161ef  0x3b: 0x416855
0x3c: 0x411ab0  0x3d: 0x411b20  0x3e: 0x4152a1  0x3f: 0x41526c
```

misaligned dump earlier in this file is superseded by this table.)

**Table 2 (PTR_FUN_00461438, statement-level, 64 entries):**

```
0x00: 0x40fcb0  0x01: 0x40f710  0x02: 0x40f740  0x03: 0x40f770
0x04: 0x40f7a0  0x05: 0x40f7d0  0x06: 0x40faf0  0x07: 0x40fb20
0x08: 0x40fb50  0x09: 0x40f800  0x0a: 0x40f830  0x0b: 0x40fb80
0x0c: 0x40f9a0  0x0d: 0x40fcf0  0x0e: 0x40f860  0x0f: 0x40f8a0
0x10: 0x40f8e0  0x11: 0x40f920  0x12: 0x40f960  0x13: 0x40fcb0
0x14: 0x40fa00  0x15: 0x40fa30  0x16: 0x40fa60  0x17: 0x40fa90
0x18: 0x40fac0  0x19: 0x40faf0  0x1a: 0x40fb20  0x1b: 0x40fb50
0x1c: 0x40f800  0x1d: 0x40f830  0x1e: 0x40fb80  0x1f: 0x40f9a0
0x20: 0x40fcf0  0x21: 0x40fbb0  0x22: 0x40fbf0  0x23: 0x40fc30
0x24: 0x40fc70  0x25: 0x40f960  0x26: 0x410150  0x27: 0x40fd50
0x28: 0x40fd80  0x29: 0x40fdb0  0x2a: 0x40fdf0  0x2b: 0x40fe30
0x2c: 0x40fe70  0x2d: 0x40fea0  0x2e: 0x40fed0  0x2f: 0x40ff10
0x30: 0x40ff40  0x31: 0x40ff80  0x32: 0x4101a0  0x33: 0x410200
0x34: 0x40ffc0  0x35: 0x410010  0x36: 0x410060  0x37: 0x4100b0
0x38: 0x410100  0x39: 0x4117a0  0x3a: 0x410260  0x3b: 0x410330
0x3c: 0x410400  0x3d: 0x4104d0  0x3e: 0x4105a0  0x3f: 0x410740
```

**Next:** decompile handlers to determine opcode semantics.

### Opcode semantics (first batch, decompiled 2026-11-05)

VM context structure (param_1, __fastcall ECX):
- `+0x10` = code base (res3 decrypted)
- `+0x14` = current code offset (the "instruction pointer" within code)
- `+0x18` = self/thread pointer
- `+0x1c`, `+0x1d` = result type bytes (type tag + flags; type 5 = double,
  flags & 3 selects int64 vs int representation)

| Opcode | Handler | Semantics (from decompilation) |
|---|---|---|
| 0x00 | 0x4206c0 | Evaluate expression (FUN_00422601), then FUN_0042dcc9(bit13) — statement/exit check |
| 0x02 | 0x429200 | **Function call**: 7-byte instruction; 16-bit index at +5 → function table (12-byte records, DAT_00461bec); calls FUN_00428f45; sets result type bytes |
| 0x03 | 0x411ec0 | **Block/compound statement**: reads 16-bit block length at +2, executes sub-opcodes via **second dispatch table PTR_FUN_00461438** until block end, then reads 2 type bytes |
| 0x04 | 0x4122d0 | Unary minus: evaluates operand (recursive dispatch), negates int64 or double (type 5) |
| 0x05 | 0x412320 | Bitwise NOT: evaluates operand, complements int64 or double bits |
| 0x06 | 0x412380 | Logical NOT: evaluates operand, result 0/1 (int) |
| 0x07 | 0x4123d0 | Convert to int64: evaluates operand, FUN_0044cff5, result type 6 |
| 0x08 | 0x412400 | Convert int→double: evaluates operand, result type 5 (double) |
| 0x09 | 0x411f30 | Load signed int32 from pointer: deref, sign-extend to int64 |
| 0x0a | 0x411f70 | Load uint32 from pointer: deref, zero-extend |
| 0x0b | 0x411fb0 | Load byte from pointer: deref, zero-extend |
| 0x24 | 0x40f0d0 | **Store int32 to pointer**: eval target ptr, eval value, store 4 bytes |
| 0x25 | 0x40f140 | Store int32 (double value → ROUND to int) |
| 0x26 | 0x40f1d0 | Store byte (double value → ROUND to int) |
| 0x27 | 0x40f260 | Store uint16 (double value → ROUND to int) |
| 0x28 | 0x40f300 | Store int64 (8 bytes) |
| 0x29 | 0x40f370 | Store double |
| 0x2a | 0x40f3e0 | **Read-modify-write int32**: load, save old, eval RHS (table 2), store new |
| 0x2c | 0x40f4f0 | Read-modify-write byte: load old, eval RHS, store new |
| 0x2d | 0x40f590 | Read-modify-write uint16: load old, eval RHS, store new |
| 0x2e | 0x40f630 | Read-modify-write int64: load old, eval RHS, store 8 bytes |
| 0x2f | 0x40f6b0 | Read-modify-write 8-byte value (double/int64) |

**Second dispatch table discovered: `PTR_FUN_00461438`** — used inside blocks
(opcode 0x03 loops over it). This is the statement-level opcode table; the
0x461038 table is the expression/statement top level. Both must be mapped.

Note: handler VA 0x42a1f0 from the raw table dump is not a procedure start
(table alignment in the hex dump was misread); re-extract the table with
correct 4-byte alignment before relying on individual entries.

### Opcode semantics (second batch, decompiled 2026-11-05)

VM context fields referenced below (same layout as first batch):
`+0x10` code base, `+0x14` code offset (IP), `+0x18` value slot (int or
pointer), `+0x1c`/`+0x1d` result type tag/flags. `FUN_0040570a` = runtime
error/abort (raised on invalid operand, e.g. null deref or range check).

| Opcode | Handler | Semantics (from decompilation) |
|---|---|---|
| 0x0f | 0x411bb0 | **Deref pointer → value**: requires slot ≥ 0x10000 (else error); loads `*slot` into value slot; decrements type byte at +0x1d (one level of indirection removed) |
| 0x10 | 0x411bf0 | **Address-of variable**: sets value slot = `*param_1` (context base = variable address); requires ≥ 0x10000; decrements +0x1d |
| 0x11 | 0x411c30 | **Pop/restore**: increments +0x1d, copies value slot back to `*param_1`, clears second dword (int64 high) |
| 0x12 | 0x411c60 | **Deref + add 16-bit offset**: reads 2 type bytes, requires slot ≥ 0x10000, adds `*(uint16*)(code+IP)` to slot (field/element offset) |
| 0x13 | 0x411cc0 | **Deref + read 2 type bytes**: advances IP by 1, dispatches next opcode, then loads 2 type bytes from code (type tag + flags for the loaded value) |
| 0x14 | 0x412720 | **Deref + add 16-bit offset (via 0x15)**: calls FUN_00411d00 first, then adds `*(uint16*)(code+IP-2)` to slot |
| 0x15 | 0x411d00 | **Deref with null check**: requires slot non-null and `*slot` non-zero (else error); loads 2 type bytes; sets slot = `*slot` |
| 0x16 | 0x411d60 | (not yet decompiled — pending) |
| 0x17 | 0x411df0 | **Deref + re-dispatch**: requires slot non-null/non-zero; dispatches next opcode, then sets slot = `*param_1 + *slot` (base + offset), sets type bytes (+7=1, +0x1d=0) |
| 0x18 | 0x411e50 | (not a procedure start; `resolve_containing_procedure` → not_in_procedure — likely unused opcode or data; pending) |
| 0x1f | 0x4120b0 | (not a procedure start; containment check pending) |
| 0x20 | 0x412770 | **Load from global/struct table**: IP += 3; 16-bit index → FUN_0041273c lookup in table at DAT_00461c04 (12-byte records); sets slot = record+8, type byte = record+4 (clamped to 0xff if > 0x29), +0x1d = record+6 |
| 0x21 | 0x4120f0 | (not a procedure start; containment check pending) || 0x22 | 0x4127c0 | **Load + deref**: calls 0x20 handler, then slot = `*slot` (one indirection) |
| 0x23 | 0x411a70 | **Store to pointer**: dispatches next opcode (evaluates target ptr), saves ptr, dispatches again (evaluates value), stores `*ptr = value` |
| 0x30 | 0x42665c | **Double → int conversion (with special cases)**: if type ≠ 5 or flags&3 ≠ 0, truncates slot to int64; handles 0.0 (→ FUN_004257e7, result 1), -1.0, -2.0 (→ FUN_00405702 with optional pointer at +6/+7), large positives (≤ 4294967.294 → FUN_0044cff5), else FUN_004056f4; result byte in slot, type cleared |
| 0x31 | 0x427503 | **Get window handle (QM internal)**: FUN_004269da → HWND; result = handle, high dword = sign, type bytes cleared |
| 0x32 | 0x42848e | **GetForegroundWindow()**: result = HWND, same layout as 0x31 |
| 0x33 | 0x420d30 | **For-loop statement** (largest handler): 16-bit loop label at +2; flag byte at +3 (bit0 = step given, bit1 = 64-bit bounds, bit2 = 64-bit counter); evaluates counter var, start, end, optional step; loops calling FUN_004208b0 (loop body executor) while counter compares against end; restores saved IP (+8) on exit; error path if flag byte & 6 set but body errors |
| 0x34 | 0x424ca4 | **Deref + call**: requires slot ≥ 0x10000, then FUN_0042468d (likely method/interface dispatch) |
| 0x35 | 0x424dc4 | (not a procedure start; containment check pending) |

Notes:
- Opcodes 0x19–0x1e (0x40e725–0x40e7ce) are small thunks in a contiguous
  block — likely simple arithmetic/comparison wrappers; not yet decompiled.
- Opcodes 0x36–0x3f not yet decompiled (next batch).
- The `≥ 0x10000` checks (0x0f, 0x10, 0x12, 0x30, 0x34) suggest the value
  slot holds either a small integer or a pointer/handle ≥ 64 KiB; the check
  distinguishes "not a pointer" from "pointer" before dereferencing.

## Script initializer (FUN_00401ff1, verified via decompilation)

- **CORRECTED 2026-11-07 (REA: asm of 0x401ff1/0x430234):** loads PE name **2** →
  function table (20-byte records, stride 0x14); name **3** (decrypted via
  FUN_00438c3b) → identifier-name base (`rec+8` = name offset); name **4**
  (NOT decrypted here) → data base (`rec+0xc` = per-function block offset; if
  `kind|flags2<<16 & 0x200` the block is additionally XOR-chain decrypted at
  `block+0x48`, length `[block+0x40]`); name **5** (optional, absent in these
  exes) → third blob (`rec+0x10`, only if record flag bit1). Name 1 is loaded
  by the function at 0x4011fe (header/count), 6 by FUN_004022f3, 7 by
  FUN_00401b87, 8/9 by FUN_004026d3, 10 by FUN_0040248d.
- (old text, SUPERSEDED: "res3 → code base (bytecode); res5 → optional blob")
- `FUN_00401add` registers each function's blob
- Call chain (verified 2026-11-07): `FindResourceW` IAT 0x451260 / `LockResource`
  IAT 0x451268 are both used inside `FUN_004300b9` (`FindResourceW` call at
  0x430140, `LockResource` at 0x4301ec; generic resource accessor,
  args `(name, &size, type, hmodule, flags)`; **0xfc=252 is the default type**
  when type=0) → `FUN_00430234(name, &size, no_decrypt)` (load + malloc +
  memcpy + optional FUN_00438c3b decrypt) → `FUN_00401ff1`

## Verified call chain (Ghidra via REA, CORRECTED 2026-11-07)

- `FindResourceW` IAT: **0x451260** (pefile + LIEF + REA xref: the only
  reference is the call inside `FUN_004300b9` at 0x430140). `LoadResource`
  0x451264, `LockResource` 0x451268, `SizeofResource` 0x45126c.
- **SUPERSEDED (wrong, 2026-11-05):** "`FindResourceW` IAT 0x4511E0" and the
  chain `FUN_004336cd → FUN_00433067 → FUN_004321da` as the resource loader.
  0x4511E0 is the IAT slot of **`CopyFileW`**; `FUN_004336cd` is a thin
  wrapper that passes `CopyFileW` to the dynamic-API dispatcher
  `FUN_00433067`, and `FUN_004321da` is a file-copy helper (PathFindFileNameA,
  GetLastError==5 retry). None of them touch resources.
- Real resource-load chain: `FUN_00401ff1` → `FUN_00430234` → `FUN_004300b9`
  → `FindResourceW/LoadResource/LockResource/SizeofResource`.
- Decryption: `FUN_00438c3b` reads key table `DAT_00455854`; its decompiled
  loop is identical to `qm_decrypt` in qmtool.py.
- Interpreter dispatch loop: FUN_00420730 (see above).

**Gotcha:** manual IAT arithmetic was off by one entry twice (0x4511C0 vs
0x4511E0) — and the "corrected" value 0x4511E0 was itself wrong (it is
CopyFileW). Always validate with LIEF/pefile **and** check what the slot
actually imports.

# Batch 3a — opcode 0x16 + containment checks (0x1f, 0x21, 0x35)


## Method note (important for future batches)

All four handler addresses fail `resolve_containing_procedure` /
`batch_decompile` with `not_in_procedure`: Ghidra 12.1.4 auto-analysis did not
promote them to functions because they are referenced **only as data** from the
dispatch table (`call dword ptr [eax*4 + 0x461038]` creates no code xref).
They are real handler starts, not dead bytes — verified per address below.
Working fallback (used here): `read_bytes` per handler + local capstone
other table-only-referenced handlers.

## Containment check results

| Address | resolve_containing_procedure | address_name | First instruction | Verdict |
|---|---|---|---|---|
| 0x411d60 (op 0x16) | not_in_procedure | `LAB_00411d60` | `PUSH ECX` (51) | **Valid handler start**; DATA ref from 0x461090 = table1[0x16] (0x461038 + 0x16·4) |
| 0x4120b0 (op 0x1f) | not_in_procedure | — | `add [ecx+0x14],3` | **Valid handler start**; body 0x4120b0–0x4120ed, `int3` pad, next handler at 0x4120f0 |
| 0x4120f0 (op 0x21) | not_in_procedure | — | `add [ecx+0x14],3` | **Valid handler start**; body 0x4120f0–0x412135, `cc` padding after |
| 0x424dc4 (op 0x35) | not_in_procedure | — | `push 1; call 0x424ce0; ret` | **Valid handler (thunk)**; 0x424dcc immediately after = opcode 0x36 handler (`push 0; call 0x424ce0; ret`), matching table entries |

Ghidra missed these because the only references are DATA edges from the handler
tables; the indirect dispatch never promotes them. Earlier "not a procedure
start" notes in discoveries.md for 0x18/0x1f/0x21/0x35 should be read as
"Ghidra function inference failed", not "not code".

## Opcode semantics

VM context (param_1, __fastcall ECX) as in discoveries.md: `+0x10` code base,
`+0x14` code offset (IP), `+0x18` value slot, `+0x1c`/`+0x1d` result type
tag/flags, `*param_1` = current variable storage (written by opcode 0x11).
`FUN_0040570a` = runtime error/abort (error code pushed as argument; 0x23c here).

| Opcode | Handler VA | Operand layout | Semantics (from disassembly; decompiler unavailable, see method note) |
|---|---|---|---|
| 0x16 | 0x411d60 | `[0x16][sub-instr A][sub-instr B][uint16 stride]` | **Indexed element address (array indexing)**. IP++ past opcode; dispatches sub-instruction A (table 1), then requires slot (`+0x18`) non-null and `*slot` non-zero (else error 0x23c via FUN_0040570a) and takes `edi = *slot` (base pointer, one deref). Saves type byte `+0x1c` and reads `+0x1d` before dispatching sub-instruction B. After B: IP += 2, reads `uint16` at `code[IP-2]` (the trailing operand), computes `slot = edi + uint16 * (*param_1)`, restores type byte `+0x1c` from the saved value, and decrements `+0x1d` by 1 (one level of indirection removed — same convention as opcodes 0x0f/0x10). Interpretation: `base + index * element_size` address computation; the uint16 is the element stride and the index value reaches the product via `*param_1` (sub-instruction B is expected to leave the index there, e.g. opcode 0x11 pop/restore). Confidence: mechanics high (byte-verified), stride/index role of `*param_1` medium — see residual unknowns. |
| 0x1f | 0x4120b0 | `[0x1f][uint16 local-var index]` (3 bytes) | **Load address of local variable**. IP += 3; `idx = *(uint16*)(code+IP-2)`; record = `*(dword*)(ctx+0x24) + 8 + idx*8` (8-byte records in the per-function local-variable table; ctx+0x24 = table descriptor, +8 = record array base). `slot (+0x18) = *(dword*)(ctx+0x28) + record.offset` (ctx+0x28 = frame base) — i.e. slot holds the variable's **address**, not its value. Type byte `+0x1c = (uint16)record.word@+4`, clamped to 0xff if ≥ 0x2a (same clamp as opcode 0x20's globals). Flags byte `+0x1d = record.byte@+6`. No null/range check. Confidence: high. |
| 0x21 | 0x4120f0 | `[0x21][uint16 local-var index]` (3 bytes) | **Load value of local variable** — byte-identical to 0x1f except one extra deref at the end: after setting slot = frame_base + record.offset and the type bytes, executes `slot = *slot`. So 0x1f/0x21 are the local-variable counterparts of the global pair 0x20/0x22 (0x20 = global address via DAT_00461c04 12-byte records + FUN_0041273c; 0x1f/0x21 use inline 8-byte records via ctx+0x24/ctx+0x28). Confidence: high. |
| 0x35 | 0x424dc4 | no inline operands (sub-instructions follow) | **Object/interface operation, variant A** — thunk: `push 1; call FUN_00424ce0; ret`. FUN_00424ce0 (real function start, MSVC stack-cookie prologue): evaluates operand 1 via table-1 dispatch, requires `slot >= 0x10000` (pointer check, else error 0x23c via FUN_0040570a), evaluates operand 2 (slot = value, ebx). Then: if flags `+0x1d & 0x43` → alternate path at 0x424d74 (not yet traced); if type byte `+0x1c == 3` (int): calls FUN_00406a33(obj=`*param_1`, value) when arg==0, or FUN_00401c6f(obj, value) when arg==1 — FUN_00401c6f is a 6-arg stdcall COM-style call (`push -1; push arg; push [ecx+4]; push [ecx]; push 2; push ecx; call vtable-helper`), consistent with an OLE automation/interface invocation (QM imports oleacc/ole32); if type == 4 (double): parallel branch (truncated at dump edge). Opcode 0x36 (0x424dcc) is the same routine with arg=0. Working interpretation: typed operation on an object reference with the argument selecting get-vs-put / byref-vs-byval behavior; exact QM source construct not yet pinned. Confidence: mechanics high, QM-level meaning medium. |

## Evidence

- `resolve_containing_procedure` → `not_in_procedure` for all four addresses
  (evidence ev_a4853e13…, ev_266980c5…, ev_0c126e0a…, ev_915a9e26…).
- `address_name(0x411d60)` → `LAB_00411d60`; `inspect_native_instruction` shows
  `PUSH ECX` with incoming DATA ref from 0x461090 (= Table-1 entry 0x16).
  0x4120b0 (96 B), 0x4120f0 (96 B), 0x424dc4 (96 B), 0x424ce0 (128 B),
  0x401c6f (48 B), 0x406a33 (48 B).

## Residual unknowns

- 0x16: exact producer of the index value in `*param_1` (which sub-instruction
  B opcodes are legal; hypothesis: 0x11 pop/restore) and confirmation that the
  uint16 is element size rather than a scaled byte offset.
- 0x35/0x36: tail of FUN_00424ce0 from 0x424d74 (flags & 0x43 path, double path)
  and the identity of helpers FUN_00401c6f (6-arg COM-style call) and
  where Ghidra has these as functions, or extend the byte-dump method.
- 0x1f/0x21: record layout named by offset only (+0 offset dword, +4 type word,
  +6 flags byte); cross-check against the res6/res4 variable-table extraction
  when available.


---

# Batch 3b: Table 1 opcodes 0x19–0x1e (thunk block 0x40e725–0x40e7f2)

Method: Ghidra auto-analysis did NOT create procedures at these addresses (they
are reachable only via handler table `PTR_FUN_00461038`), so `batch_decompile`
failed with `not_found`. Evidence instead comes from `read_bytes` over the
contiguous block 0x40e725–0x40e7f2 (224 bytes) disassembled locally with
Capstone (x86 32-bit). All addresses are VA (image base 0x400000); file offset
of 0x40e725 = 0xDB25 (verified via `address_to_file_offset`).

VM context (param_1, __fastcall ECX) — same layout as first batch:
`+0x00` value slot low (int32 / ptr), `+0x04` value slot high (int64 high),
`+0x10` code base (res3), `+0x14` current code offset (IP), `+0x18` self/thread
ptr, `+0x1c` result type tag, `+0x1d` result type flags, `+0x24` frame/locals
base pointer.

Common prologue in 0x19/0x1a/0x1b/0x1d: `inc [ecx+0x14]` — the dispatch loop
reads the opcode byte at code+IP and calls the handler with IP still pointing
at the first operand byte; each handler first advances IP past the opcode byte.

| Opcode | Handler VA | Operand layout | Semantics (from disassembly) |
|---|---|---|---|
| 0x19 | 0x40e725 | 4-byte immediate (int32) at code+IP | **Push 32-bit signed immediate**: IP += 1; `eax = *(int32*)(code+IP)`; `cdq` sign-extends into EDX; IP += 4; slot = EAX:EDX (sign-extended int64); type tag = 0, flags = 0. Result type: signed int. |
| 0x1a | 0x40e748 | 4-byte immediate (uint32) at code+IP | **Push 32-bit unsigned immediate**: IP += 1; `edx = *(uint32*)(code+IP)`; `[ecx+4] &= 0` (high dword cleared, NOT sign-extended); IP += 4; slot = EDX:0; type tag = 0, flags = **0x40** (unsigned marker). Result type: unsigned int. |
| 0x1b | 0x40e769 | 1-byte immediate at code+IP | **Push 8-bit signed immediate**: IP += 1; `eax = movzx *(uint8*)(code+IP)`; `cdq` sign-extends (byte is zero-extended then sign-extended as 32-bit, so result is 0..255 as positive int64); IP += 1; slot = EAX:EDX; type tag = 0, flags = 0. |
| 0x1c | 0x40e78b | 8-byte immediate (double) at code+IP | **Push 64-bit double immediate**: IP += 1; `fld qword [code+IP]`; IP += 8; `fstp qword [ecx]` stores the double into the value slot; type tag = **5** (double), flags = 0. |
| 0x1d | 0x40e7a8 | 8-byte immediate (int64) at code+IP | **Push 64-bit integer immediate**: IP += 1; low = `*(uint32*)(code+IP)`, high = `*(uint32*)(code+IP+4)`; IP += 8; slot = low:high; type tag = **6** (int64), flags = 0. |
| 0x1e | 0x40e7ce | 4-byte immediate (int32) at code+IP | **Push frame-relative address (local variable address)**: IP += 5; `eax = *(int32*)(code+IP-4)` (the immediate, read after advancing); `eax += [ecx+0x24]` (add frame base — i.e. address = frame_base + offset); high dword cleared; slot = EAX; type tag = **3** (pointer/reference), flags = 0. Note: unlike 0x19–0x1d this handler does NOT first `inc [ecx+0x14]`; it adds 5 in one step (opcode byte + 4-byte immediate). |

Notes:
- Type tags observed here are consistent with the first batch: 5 = double,
  6 = int64, 3 = pointer/reference, 0 = plain int. Flag byte 0x40 on 0x1a
  marks the pushed value as unsigned.
- All six handlers are pure "load constant into value slot" thunks: no calls,
  no error paths, no dispatch of a following opcode. They only differ in
  operand width/encoding and the resulting type tag/flags.
- Handler 0x1e's `[ecx+0x24]` base is the same field the for-loop handler
  (0x33) uses for saved state; here it acts as the current stack-frame base,
  so 0x1e implements `&local` / address-of-variable-with-offset semantics
  (contrast with opcode 0x10, which takes the address of an absolute variable).
- Bytes after 0x40e7f2 (`b8 3d e9 44 00 e8 7f e8 03 00 …`) belong to the next
  function (loads 0x44e93d and calls) — outside this batch's scope.

Evidence: bytes read via a byte-reading debugger tool at 0x40e725 (176 B) and 0x40e7ce
Confidence: high for operand layout and register-level semantics (direct
disassembly); medium for the QM-level meaning of type tags 3/5/6 and flag 0x40
(inferred from cross-references with the first-batch table in discoveries.md).


---

# Batch 3c — Table 1 opcodes 0x36–0x3f (decompiled 2026-11-05)

Source: Table 1 (PTR_FUN_00461038, VA 0x461038) handler VAs from
docs/discoveries.md (correctly-aligned table). Decompiled with Ghidra 12.1.4
via REA (batch_decompile, ≤2 addresses per call). VM context layout as in
discoveries.md: +0x10 code base, +0x14 code offset (IP), +0x18 value slot,
+0x1c/+0x1d result type tag/flags. FUN_0040570a = runtime error/abort.

| Opcode | Handler VA | Operand layout | Semantics (from decompilation) |
|---|---|---|---|
| 0x36 | 0x424dcc | — | **Not a procedure start** (resolve_containing_procedure → not_in_procedure). Interior label of the 0x424ca4/0x424dc4 handler family (same status as opcode 0x35 at 0x424dc4). Semantics pending; likely a shared-tail variant of the 0x34/0x35 deref+call family. |
| 0x37 | 0x42342b | +1: sub-opcode (dispatched via Table 1); +2: index byte into DAT_00461578 | **Interface/property get via dispatch table DAT_00461578**: IP+=1; dispatch next opcode (evaluates object); requires slot ≥ 0x10000 (else error); reads 1 index byte, IP+=1; calls `DAT_00461578[index](obj, &local)` (vtable-style dispatch, 64-entry table); sets type byte +0x1c = low byte of returned local, +0x1d = 0; if returned tag == 4, loads value from `*obj` into slot (deref result). |
| 0x38 | 0x414a60 | — | **Not a procedure start** (not_in_procedure). Interior label; semantics pending. |
| 0x39 | 0x4155c1 | +1: kind byte; +2: arg-count byte; +3: flags byte; then dispatch (object expr); optional 16-bit string-pool index (×0x10 + data base) | **COM object creation / acquisition (CreateObject family)**: reads kind (+1), arg count (+2), flags (+3); dispatches next opcode; if flags & 0x10 → creates built-in collection (1=CreateStringMap, 2=CreateCsv, 3=CreateXml) and stores in slot; else reads 16-bit IID/type index (×0x10 + data base). kind 5 = existing object (FUN_0041293c/FUN_00412a6a); kind 4 = window-based (FUN_0040afc7 → HWND, FUN_00417514); kind 3 + flags&2 = CoGetObject(moniker); kind 1 = GetActiveObject/CoCreateInstance (ProgID or "{GUID}" via CLSIDFromProgID/IIDFromString); kind 2 = GetActiveObject with optional server name; default = CoCreateInstance + optional QueryInterface(&DAT_00454840) + name lookup. Result: IUnknown*/interface pointer in slot, type bytes restored/cleared. |
| 0x3a | 0x4161ef | +1: op byte; +2: arg-count byte; +3: sub-opcode (dispatched); then per-op operands | **SAFEARRAY operations (array statement)**: reads op (+1) and arg count (+2), dispatches next opcode (array variable; requires slot ≥ 0x10000). op<3: destroy old array, build new via FUN_004160a4 (1 = fill bounds from inline list, 2 = pairs, 3 = single, 0 = 1×1); result type 0xd (array). op 3: SafeArrayRedim (resize, negative index → lbound-based). op 4: window-based array (FUN_00417514). op 5: delete element at index (memmove shift + SafeArrayRedim −1). op 6/7: SafeArrayLock/SafeArrayUnlock. op 8/9: SafeArrayGetLBound/GetUBound → int result. op 10: read dimension bound from SAFEARRAYBOUND. op 0xb: SafeArrayGetDim → int. op 0xc: sort (q_sort with comparator FUN_00415fc1 or FUN_0041607c, key count from operands). op 0xd: Fisher–Yates shuffle (RandomInt swaps). |
| 0x3b | 0x416855 | +1: index-count byte (0 = append); +2: element-type byte (0/0x24 → +3 more bytes); then index expressions; +2 type bytes at end | **SAFEARRAY element access (array element reference)**: dispatches next opcode (array variable). If index count = 0: create/append — new 1-element array via FUN_004160a4, or SafeArrayRedim(cElements+1) on existing 1-D array (must be 1-D, else error); index = old element count. Else: evaluates `count` index expressions into local_38[], requires array non-null and dimension count match (else error). Reads 2 type bytes from code into +0x1c/+0x1d. Calls SafeArrayPtrOfIndex(array, indices, &slot) → element pointer in slot; DISP_E_BADINDEX (0x8002000B) → runtime error, other HRESULT → FUN_00412fd5. |
| 0x3d | 0x411b20 | +1: sub-opcode (dispatched); +2: 16-bit index into object/type table (FUN_004291b0) | **Object assignment (interface copy with refcount)**: IP+=1; dispatch next opcode (evaluates destination object pointer; requires ≥ 0x10000); dispatch next opcode (evaluates source value); reads 16-bit index → FUN_004291b0 lookup (object/type descriptor); calls vtable+0x14 method (assign/copy: `obj->vtbl[5](obj, value, flags)`) with value slot and its low dword; if type flags (+0x1d) & 0x24 == 0x20, also calls vtable+0x10 method (AddRef/release helper: `obj->vtbl[4](obj, value)`). |
| 0x3e | 0x4152a1 | +1: sub-opcode (dispatched, evaluates destination); +2: sub-opcode (dispatched, evaluates source) | **COM reference assignment (with Release/AddRef)**: evaluates destination object (slot +6), then source value (*param_1). If pointers equal: if non-null and flags&0x24 == 0x20, call vtbl+8 (Release) on it. Else: if dest non-null and flags&0x24 != 0x20, call vtbl+4 (AddRef) on dest; call vtbl+8 (Release) on old target; store source pointer into destination (`*dest = src`). |
| 0x3f | 0x41526c | — | **Not a procedure start** (not_in_procedure). Interior label; semantics pending. Likely shares code with 0x3e (0x4152a1) — the two addresses are 0x35 bytes apart in the same code region. |

## Notes

- Three handler VAs (0x424dcc, 0x414a60, 0x41526c) are not procedure starts
  and are not contained in any analyzed procedure — same pattern as opcodes
  0x35 (0x424dc4) and 0x18 (0x411e50) from earlier batches. These are likely
  interior labels of larger handler functions (Ghidra function-boundary
  limitation) or unused table entries; re-extraction with explicit
  function-start recovery would be needed to resolve them.
- Opcodes 0x3a–0x3f form a coherent "COM/array" family: 0x39 = object
  creation, 0x3a/0x3b = SAFEARRAY ops/element access, 0x3c = memcpy,
  0x3d/0x3e = interface assignment with refcounting.
- The `≥ 0x10000` slot check appears again in 0x37, 0x3a, 0x3c, 0x3d —
  consistent with the pointer-vs-integer discrimination noted in
  discoveries.md.
- FUN_004160a4 (called by 0x3a/0x3b) is the SAFEARRAY constructor helper;
  FUN_004161a0 returns element size; FUN_00416176 returns dimension count.

## Pending-opcode batch (capstone inline RE, 2026-11-05)

Method: pefile VA→file-offset + capstone linear disassembly (no Ghidra).

| Opcode | Handler VA | Layout | Semantics | Confidence |
|---|---|---|---|---|
| 0x01 | 0x42a1f0 | 4 B: `01 <tag> <uint16 idx>` | **Variable access (value)**: IP+=1; helper FUN_00429f80(0) does IP+=3, reads uint16 at +2 → indexes 24-byte descriptor records via `[0x461b74]` (field +0x10); loads value into result slot. Helper arg 0 = value path, -1 = address path | high |
| 0x0c | 0x411ff0 | 2 B: `0c <sub-op>` | **Deref int16**: IP+=1; dispatch next opcode (evaluates pointer); require slot ≥ 0x10000 (else error 0x23c); read int16, sign-extend to int64 | high |
| 0x0d | 0x412030 | 2 B | **Deref double**: same pattern, fld/fstp qword | high |
| 0x0e | 0x412070 | 2 B | **Deref int64**: same pattern, copies 8 bytes | high |
| 0x4b | 0x429d7a | 4 B: `4b <uint16 var-idx> <sub-opcode>` | **Computed variable/array-element access**: IP+=3; sub-opcode dispatched (evaluates index); uint16 at +1 indexes 8-byte records in var table `[ctx+0x24]+8`; load by type tag (4 → ptr deref; 0xd–0x13 → struct path) | medium-high |
| 0x52 | 0x42a200 | 2 B: `52 <var-tag>` | **Address-of variable**: IP+=1; tag byte dispatched as opcode (evaluates variable); getter helper called with -1 → result = variable address | high |

**Phantom opcodes (handler VA = 0x000000 in the dispatch table):**
0x7c, 0x80, 0xe2, 0xe7 (original-1), 0x62 (a third 2.4.2 exe). These are NOT real opcodes —
the disassembler walked into non-code data. Evidence: their context bytes
are ASCII (`54 2d 58 20…` = "T-X   v", `49 63 6f 6e 00` = "Icon\0") or
uint16-table pairs (`66 00 6d 00…`). qmdis should treat handler-VA-0
opcodes as data markers, not RE gaps.

**Ghidra flag correction:** handler 0x42a1f0 (opcode 0x01) IS a valid
procedure start (the earlier "not a procedure start" note was wrong).

**Helper map (new):**
- `FUN_00429f80(ctx, mode)` — variable getter: mode 0 = value, -1 = address;
  reads `tag byte + uint16 index` at IP, IP+=3; descriptor table `[0x461b74]`
- `FUN_0042a200` — dispatch-next-opcode-then-get(-1) wrapper (opcode 0x52)

## Second 2.4.2 exe: opcode addendum (capstone inline RE, 2026-11-06)


| Opcode | Handler VA | Layout | Semantics | Confidence |
|---|---|---|---|---|
| 0x4a | 0x429d3f | 3 B fixed: `4a <uint16>` + dispatched sub-expression | **Method invocation on object**: IP+=1; resolve object/fn ref via FUN_004291b0(code+IP); IP+=2; dispatch next opcode (evaluates argument); virtual call `[vtbl+0x10](obj, value)` | medium |
| 0x4f | 0x412240 | 3 B: `4f <uint16 idx>` | **Variable access, deref**: helper 0x4121e0 does IP+=3, reads uint16 at +2, indexes 8-byte var records (type tag word at +4 clamped ≤0xff → slot+0x1c; byte at +6 → slot+0x1d), computes var address; handler then replaces slot with `*address` (one pointer deref) | high |

**More phantom opcodes (handler VA = 0x000000 in second 2.4.2 exe):**
0x66, 0x70, 0x77, 0xb7, 0xce. Same rule as the original-1 batch — data, not code.
those particular hits came from the decoder walking into string data.

**PHANTOM set (union, both exes):** {0x62, 0x66, 0x70, 0x77, 0x7c, 0x80,
0xb7, 0xce, 0xe2, 0xe7}

## Final opcode batch (capstone inline RE, 2026-11-06)

Closes the PENDING set. Handler VAs read from dispatch table 0x461038
(original-1 exe). All four are real handlers.

### 0x18 = indexed address (array element address)

Handler 0x411e50. Layout: **3 bytes** `18 <uint16 stride>` — IP+=1;
dispatch next opcode (evaluates index expression); IP+=2; result =
`[ctx+0x18] + uint16 × [ctx+0]` (base pointer + index × element size).
Confidence: high. Mnemonic: `index_addr`.

### 0x36 = typed store (variable-length)

Handler 0x424dcc. IP+=1; read tag byte (IP+=1); dispatch next opcode
(evaluates value); then type-tag switch: al==3/4 → one path, al==0xf →
another, al==2 → another; default checks `word ptr [eax] == 8` (size
check, error path 0x424ebf if mismatch). Semantics: **store evaluated
value into typed slot**, tag byte selects width/type. Variable total
length (sub-expression). Confidence: medium-high. Mnemonic: `typed_store`.

### 0x38 = typed slot store

Handler 0x414a60. 3-byte fixed part `38 <tag> <sub-opcode>` — IP+=1;
read 2 tag bytes; dispatch next opcode (evaluates value); then the
`≥ 0x10000` slot check (error 0x23c) → **store into slot** (same family
as 0x37/0x3a/0x3c/0x3d). Confidence: medium-high. Mnemonic: `slot_store`.

Handler 0x41526c. 3-byte instruction `3F <tag> <sub-opcode>` — IP+=1;
read tag byte; dispatch next opcode (evaluates value); call helper
0x413cd0(tag, value, 0, 0, 0) → **method invocation with 3 null args**
(same family as 0x4a method_invoke). Confidence: medium. Mnemonic:
`method_invoke_3null`.

## QM 2.4.12 runtime addendum (REA/Ghidra, 2026-11-06)

The compile samples were built with QM 2.4.12, whose runtime VAs differ
from the 2.4.2 exes. All findings below are from sample05
`7fef3e9bc4fb989140eb49ee009b889c5a33d53c012ecc3184ff97d3c6017a45`),
provider Ghidra 12.1.4 via REA.

### 2.4.12 runtime anchors

| Item | 2.4.2 (original-1) | 2.4.12 (sample05) |
|---|---|---|
| Interpreter dispatch loop | FUN_00420730 | **FUN_0040adcc** |
| Dispatch mechanism | indirect jump on opcode | **CALL dword ptr [EAX*4 + 0x472090]** (site 0x40addb) |
| Handler table | PTR_FUN_00461038 (64 entries 0x00–0x3F) | **DAT_00472090** (87 valid entries 0x00–0x56, then zeros) |
| XOR key `5d 91 38 6f` | 0x455854 | **0x464efc** (.rdata) |
| Decrypt function | (inline chain) | **FUN_00439c31** — identical XOR-chain algorithm (decompiled, observed) |

Evidence: key found via byte search at 0x464efc; xrefs → 0x439c3c/0x439c53
inside FUN_00439c31; FUN_00439c31 pseudocode matches the 2.4.2 chain
(`b ^= key[i&3]; key_next = key[i&3] + b`); handler table verified by
reading 400 bytes at 0x47208c (87 code VAs then 0x000000 run).

### Straggler opcodes CLOSED as phantoms (2.4.12 build)

All previously "undocumented" raiser opcodes have handler VA = 0x000000
in the 2.4.12 dispatch table at 0x472090 → they are NOT real opcodes;
qmdis.py walked into non-code data (ASCII text or uint16-table pairs):

- **0xcc** — prologue bytes of sample05 (first "statement" region);
  bytes `cc 00 00 ...` are padding/alignment data, not an instruction.
- **0xad** — occurs in sample07 at code offset 0x0025 (`ad 06 00 06 09...`);
  context is uint16-table pairs, not code.
- **0x98** — never occurs in any sample (7 compile samples + 2 originals);
  no dispatch entry needed.
- Also closed: 0x58, 0x6f, 0x82, 0xfe, 0xff (one-off raisers in samples
  02/03) — same handler-VA-0 status.

Consequence: **qmdis.py needs no new opcode implementations.** The fix is
to expand the PHANTOM set (report as DATA markers, not RE gaps) and treat
the 2.4.12 table bound as 0x56 (87 entries) when validating. The 2.4.2
table (64 entries, 0x00–0x3F, entries 0x56+ all zero) was re-validated
from the original-1 original — consistent.

### Updated phantom set

{0x62, 0x66, 0x70, 0x77, 0x7c, 0x80, 0x86, 0xb7, 0xc9, 0xce, 0xe2, 0xe7}
— 12 opcodes (2.4.2 builds). The 9999-site bytes `86 c9` are operand data.

2.4.12 builds add: {0x58, 0x6f, 0x82, 0xad, 0xcc, 0xfe, 0xff} — 7 more
(handler VA = 0 in DAT_00472090). 0x98 needs no entry (never occurs).
Union across both runtimes: 18 opcodes.

## Opcode 0x49 = call_function_args (REA inline, 2026-11-06)

0x00dc (bytes `49 00 00 20 03 0b 02 1b`). Handler VA from DAT_00472090[0x49]
= **0x00429650** (sample05 runtime). Ghidra did not promote the handler to a
procedure (table-only DATA reference, same limitation as batch3-a); evidence
from `read_bytes` + local capstone disassembly.

### Handler 0x429650 (opcode 0x49) — call function by index with N arguments

```
49 <u8 sel@+1> <u8 type_tag@+2> <u8 type_flags@+3> <u8 argc@+4> <u16 fn_index@+5>
   <argc dispatched sub-instructions (the arguments)>
```

- IP += 7 (fixed part); `sel = code[+1]` (result width selector);
  `argc = code[+4]`; `fn_index = *(uint16*)(code+5)`.
- Helper **0x429520**(ecx = code+5): reads the uint16 function index, looks it
  up in the 12-byte-record function table at **0x473bc8** (2.4.12 runtime;
  linear search + lazy init via 0x402213), returns the function pointer.
- Loop: while `argc-- > 0`: dispatch next opcode (evaluate one argument),
  push it (`push [edi]`).
- Call the function; store result by `sel`: 0 → int64 sign-extended (cdq),
  2 → u8, 3 → u16, 5 → double (fstp), 6 → int64; else slot untouched.
- Sets type bytes `[edi+0x18] = code[+2]`, `[edi+0x19] = code[+3]`;
  sets `[edi+0x14] = edi` (self ptr).

Semantics: **general function call with argument list** — the
argument-carrying counterpart of 0x02 call_function (which takes no
inline args). Confidence: high (byte-verified both handlers; usage site
decodes consistently: `49 00 00 20 03 | 0b 02 | <3 args>` = call fn
0x020b with 3 args, type tag 0x00 flags 0x20).

Note: 0x49 is BELOW the 2.4.2 table bound (0x56) but was never hit by the
2.4.2 samples; it is a real opcode in 2.4.12 (handler non-zero). The other
19 undocumented 2.4.12 opcodes (0x2b, 0x40-0x48, 0x4c-0x4e, 0x50-0x51,
0x53-0x55) remain undocumented — none occur in the 9 validation targets
except 0x49.

## Sample01 full decode — stream semantics + pool base (inline, 2026-11-06)

Validated the Level-3 execution model on sample01 (known source, QM 2.4.12):

1. **One dispatch table** in 2.4.12 (DAT_00472090, 87 entries). The 2.4.2
   statement-level table 2 (PTR_FUN_00461438) does not exist as a separate
   indexed-call table in 2.4.12 — only one `call [eax*4+0x472090]` pattern
   exists (77 sites). The interpreter thunks at 0x40adcc confirm: fetch
   opcode at [ctx+0x3c]+[ctx+0x10], call table[opcode].

2. **Stream entries mark statement AND sub-expression starts.** Verified:
   the `loopCount+1` statement (rmw_i32) spans code 8..16; its RHS
   sub-expression (`push_i8 1`) starts at code 10, which is also a stream
   entry. So entries = every dispatched instruction start (statement level
   plus dispatched sub-expression starts), not only top-level statements.

3. **String-pool data base for sample01 = 280** (first string). frame_addr
   (0x1e) u32 refs resolve as pool_data_base + u32: 29→309 "The loop count
   is %i", 50→330 "The number of lines of text…", 98→378 "The number of
   matching lines is %i". The pool header (u32 offset table) sits at 259.

4. **out F"…" bytecode shape** (validated): `1f <u16 local>` (load addr of
   destination str var) + `05 04` (2-byte helper tag) + `1e <u32 pool ref>`
   (format string) + `09 1f <u16>` (load_i32 of the value local) + tail.

5. **Undocumented bytes in gaps** (`d1 08 00 00` after push_i8 0 in stmt 0;
   `c9 00 0a 37` suffixes; `30 1b 01 20` in stmt 7) are real instruction
   sequences whose opcodes (0xd1, 0xc9, 0x30, 0x20, 0x37, 0x24, 0x05, 0x04)
   are NOT all in the 87-entry table — 0xc9/0xd1 exceed it. Working
   hypothesis: the code region contains a second opcode stream (table-2
   opcodes, 2.4.2's PTR_FUN_00461438 merged differently in 2.4.12) OR these
   are inline operands of the preceding instruction. OPEN — blocks the
   statements decode clean end-to-end).

## Level 1 re-audit (2026-11-07)

Full re-validation of Level 1 against all 13 QM exes (3 QM 2.4.2 exes,
7 QM 2.4.12 compile samples, 2 QM 2.4.12 rebuilds). Regression script:

Confirmed:
- Hashes/sizes of the 3 originals; every exe has resource type 252 with PE
  byte-identical to fresh extraction.
- XOR key `5d 91 38 6f` is at RVA 0x55854 (2.4.2) / 0x64efc (2.4.12) and
  `qm_decrypt` decrypts res3 correctly everywhere; the runtime's own decrypt
  `FUN_00438c3b` (REA decompile) is the same loop over `DAT_00455854`.
- res1 count == res2 record count == number of res3 names (all exes).

Bugs found and fixed in qmtool.py (all fixed 2026-11-07):
1. `parse_bytecode_index` used 16-byte records (garbage output); now 20-byte
   records with field names `id, flags, kind, flags2, name_off, block_off,
   blob_off`. The old 5th field name `size` was wrong: it is the offset of the
   function's name in decrypted res3.
2. Key check hard-coded RVA 0x55854, so every QM 2.4.12 exe reported "DIFFERENT
   KEY" and skipped res3 decryption; now searches the file and recognizes both
   build layouts.
3. `res3_identifiers` (strings of still-encrypted bytes) removed.
4. Dead code (`by_name`, empty `resources`) removed; stale docstring fixed.
5. Output files were numbered by position (res5/6/7 for PE names 6/8/9); they

Doc errors corrected: `FindResourceW` IAT is 0x451260 (0x4511E0 = CopyFileW);
the `FUN_004336cd/00433067/004321da` "resource loader chain" is a CopyFile
path, superseded above; runtime loads PE names 2,3,4,5 in FUN_00401ff1 (not
"res1/3/4/5"); res3 is the name table, not bytecode; `ShutDownProcess` casing;
duplicate res5/res6 table rows; original-3 function-table count.

Open items (not Level 1 bugs):
- `qmdis.py`, when passed a PE file instead of an extracted dir/res4, silently
  treats the whole exe as res4 and exits 2 or 0 meaninglessly; it should reject
  PE input. Run it on an extraction directory (`qmtool.py ... -o dir`).
- `qmdis.py` cannot auto-locate the instruction stream for
  `sample05_process_run` (needs `--stream-offset`).
- res2 field +0 (`id`) is copied to the runtime record and matched by
  `FUN_0042911d`; the docs still call it `code_off` (unverified).

### Level 1 re-audit follow-up: open items closed (2026-11-07)

1. **qmdis.py PE input** — now rejected with an explanatory error (it used to
   treat the whole exe as res4 and print meaningless exit codes).
2. **Instruction-stream location (BUG in the old scanner, fixed).** Every
   res4 function block starts with 9 relocated u32 pointers. For block 0:
   `stream_offset = (ptr1 - ptr0) + 0x48`, `stream bytes = ptr2 - ptr1`
   (u16 code offsets, first entry always 0; a trailing 0 is 4-byte alignment
   padding when the count is odd). Evidence: reproduces the old answer on
   original-1 (0x46c, 77), sample01 (0xa4, 9), sample04 (0x84), fixed original-1/2;
   fixes `sample05` (scanner found nothing) and **six targets where the scan
   (scan 0xbe8 vs true 0x150), original-3 (0x66c vs 0xe0), sample02 (0x734 vs
   0x110), sample03 (0x5a0 vs 0xdc), sample06 (0xea vs 0xec, off by one entry),
   sample07 (0x36c vs 0xd0). Consequence: earlier "zero raisers on all
   targets" results for those six were measured on the wrong stream.
   Re-validated with the correct streams (`audit_level1.py`): all 12 targets
   decode, exit 0. `qmdis.locate_stream_from_header()` implements this; the
   scanner is only a fallback. The per-block pointer table for the other
   functions' blocks (kind 2/7) follows the same layout (not yet decoded).
3. **Dispatch-table bound.** a byte-reading debugger tool: 2.4.12 `DAT_00472090` idx 0x55 =
   0x4126f0, idx 0x56.. = 0; 2.4.2 `PTR_FUN_00461038` idx 0x52..0x55 =
   0x42a200/0x412450/0x412260/0x4122a0, idx 0x40.. non-zero. So BOTH runtimes
   have exactly **86 handlers (0x00–0x55)**; the "64 entries" (2.4.2) and "87
   entries 0x00–0x56" (2.4.12) statements above are wrong. Opcode bytes >= 0x56
   have handler 0 → DATA. This closes the two new raisers exposed by item 2:
   zero at 0x4612e8). qmdis.py: `is_phantom()` = static set OR opcode >= 0x56.
4. **res2 `id` field (+0).** Not a code offset. Built-in/type-member records
   (kind 7) carry the same id for the same member across scripts built with the
   same QM build: 2.4.12 Acc.Find=236, FromWindow=240, DoDefaultAction=246,
   Value=251, State=254, GetChildObjects=257 (all 7 samples); QM 2.4.2 original-1/2
   Acc.Find=258, DoDefaultAction=268, Value=273, State=276 (original-3, an older
   build, has 251/261/269 — so ids are per-QM-environment, not per-runtime-
   version); kind 1 (main macro) ids are 1/4/11; user functions (kind 2) carry
   the runtime record (`FUN_00401ff1` writes it to `rec+0`). The `call`
   operands (0x02 at +5 = 7936, 0x49 = 523) do NOT match these ids, so they
   use a different id space (runtime table `0x461bec`/`0x473bc8`). Confidence:
   medium (consistency evidence only).
5. **res3 8-byte trailer in 1-function builds.** The four single-function
   samples (01, 04, 05, 06) share the identical decrypted trailer
   `2e 03 37 54 23 23 22 00` after `Macro1`; multi-function builds have none.
   The loader never reads past `name_off` of the last name, so it is inert
   for decoding. Meaning unknown (constant across scripts → not script data).
   Residual unknown only.

## Level 2 re-audit (2026-11-07)

Scope: (a) re-run the threshold sweep on correct streams, (b) decode every
function block, (c) spot-check unvalidated opcodes against handler bytes read
via REA. Regression: `audit_level1.py` (now also decodes all function blocks).

### (b) All function blocks decode
`qmdis.decode_all_functions()` / `python qmdis.py <dir> --all`. Every res2
record has a block in res4 with the same 9-pointer header; code base =
`block_off + 0x4c`, stream/length from `ptr1-ptr0+0x48` / `ptr2-ptr1`. Result:
all functions of all 12 QM exes decode with **zero undocumented opcodes**.
type-library member stubs (Acc.Find/State/Value/FromWindow/GetChildObjects/
DoDefaultAction, __Handle.) which are **identical code in every exe that uses
them**. Previously only block 0 was ever decoded.

### (a) Threshold sweep on correct streams (`threshold_sweep.py`)
  that index came from the wrong stream. Same constant, same idiom.)
- **RETRACTED attribution:** `0xF32FF` (996095), `0x4100` (16640) and `0x8000`
  (32768) are NOT in any user script. They are `push_i32` constants inside the
  shared `Acc.Find` library stub (kind-7 block, offsets 0x01/0x0b/0x1c), present
  identically in original-1, original-3 and sample03. The earlier "log stmt 47 Acc
  filter masks" came from decoding a wrong stream/other block.
- `4097` (0x1001) remains a state/flag mask: original-1 x5 (fn0), original-2 x2, original-3 x2.
  stmt 0), not in the macro bodies.
- New values seen in correct streams (meaning NOT yet analysed): original-1 fn0
  the string-pool `state=0x100000 0x20000040` filter), `1512` in
  referenced from bytecode as pushed function ids), small immediates 4/7/10/16/8/5.
  blocks swept). Negative finding strengthened, not proven.

### (c) Opcode spot-checks (handler bytes read through REA, original-1 2.4.2)
- **0x36 — documented semantics WRONG.** Handler at 0x424dcc is the 7-byte thunk
  `push 0; call 0x424ce0; ret` (= 0x35 with arg 0, as in batch3a). The "typed
  store with tag byte" text in "Final opcode batch" decompiled the *following*
  function at 0x424dd4. 0x36 has no inline operands. qmdis now maps it to
  `object_op_0` (obj_op format). High confidence (direct bytes).
- **0x18 — operand layout WRONG.** Real layout `18 <A> <B> <u16 stride>`: two
  dispatched sub-expressions (base pointer, index), then the u16 stride AFTER
  them; result = A + B*stride. The doc/qmdis had the stride right after the
  opcode. High confidence (0x411e50 disassembly).
- **0x43 — new, was "undocumented".** Handler 0x415316: `43 <u16 iid_idx>` +
  one dispatched object sub-expression; calls `obj->vtbl[0](obj, &IID[idx],
  &out)` = IUnknown::QueryInterface (IID table `[ctx+0x24]+0x1c`, 16-byte
  entries, same table as 0x39). Seen only in the Acc.* library stubs
  (`43 00 00 0a 12 1f 00 00`). Mechanics high, QM name medium.
- 0x38 (0x414a60), 0x3f (0x41526c), 0x4a (0x429d3f): handler bytes re-read,
  CONSISTENT with the existing docs.
- NOT re-checked: 0x16, 0x35 (consistent by symmetry with the 0x36 thunk), 0x3e
  (head of handler consistent: two dispatches), and the 18 other undocumented
  2.4.12 opcodes (0x2b, 0x40-0x42, 0x44-0x48, 0x4c-0x4e, 0x50, 0x51, 0x53-0x55)
  — none occurs in any of the 12 exes.

## Level 2 full re-validation (2026-11-07) - LEVEL 2 IS NOT COMPLETE

**Result: several foundational Level-2 conclusions were wrong. Level 3 must not
build on the old model.** Evidence comes from handler bytes (a byte-reading debugger tool +
capstone), the runtime's own startup/relocation code, and exact "tiling" tests
(derive each handler's byte layout), `runtime_tables.py` (dispatch tables after
runtime init), `qmlayout.py` (recursive decoder prototype); outputs in
`analysis/`. Reproduce the checks with `python audit_level1.py`.

### R1. The dispatch tables are filled at RUN TIME - "phantom opcodes" were wrong
The PE image only contains handlers 0x00-0x55 of table 1. The runtime startup
function (`FUN_0040abc4` in 2.4.2; same code in 2.4.12) executes ~128
`mov [table+4*k], <handler>` writes and registers **99 more table-1 handlers**
(0x80-0xed with gaps) plus 2 table-2 changes before any script runs.
`runtime_tables.py` rebuilds the table: **185 valid table-1 opcodes**, with the
IDENTICAL index set in 2.4.2 and 2.4.12. Consequences:
- SUPERSEDED: "handler table has 64 / 86 / 87 entries", "opcodes >= 0x56 have
  handler 0 -> DATA" and the whole "PHANTOM set" of 18/19 opcodes. Opcodes such
  as 0x80 0x86 0x89 0x98 0x99 0x9a 0x9c 0xa9 0xad 0xb7 0xc9 0xcc 0xd0 0xd1 0xe2
  0xe7 are REAL instructions (the statement/control-flow vocabulary). Only bytes
  0x56-0x7f, a few zeroed slots (0x81 0x8f 0x90 0x92 0x9e 0xb5 0xca 0xd8 0xdc
  0xe0 0xe4) and >= 0xee are genuinely not opcodes.
- The earlier "Level 2 complete / zero raisers" claim is void: ~99 valid opcodes
  have NO documented semantics. In real code (stream-listed starts of the 12
  exes) 20 distinct undocumented opcodes already occur: 0x47 0x80 0x86 0x88
  0x89 0x8a 0x98 0x99 0x9a 0x9c 0xa9 0xad 0xb7 0xc8 0xc9 0xd0 0xd1 0xd5 0xd9
  0xda (nested ones add more).
- The earlier 2.4.12 claim "only ONE dispatch table exists" is wrong: table 2
  exists at 0x472490 (= table1 + 0x400, same as 0x461438 in 2.4.2).

### R2. The code base is block+0x48, not block+0x4c
`FUN_00401add` relocates the 9 header pointers by `block + 0x48 - ptr0`, i.e.
pointer 0 (the code base) becomes `block+0x48`. Every code offset, "stream
offset", statement offset and `context` hex in earlier notes/qmdis output was
shifted by 4 bytes. Empirical confirmation (sample set, 50 functions, exact
tiling of top-level stream entries): base 0x48 -> 148 exact tiles; 0x4c -> 36;
0x44 -> 22. qmdis.py now uses 0x48.
The 9-pointer header is the section map of a block: `ptr1-ptr0` = size of the
code region (= stream offset), `ptr2-ptr1` = stream size; `u16 [block+0x28]` =
loop count.

### R3. Corrections to documented opcodes (handler bytes)
- **0x00 is NOT `expr_statement`.** Handler 0x4206c0: `call 0x422601`
  (returns ctx+0x3c), then `shr eax,13; and 1; push; call 0x42dcc9`, and
  0x42dcc9 throws a C++ exception (never returns). So 0x00 = 1-byte
  exit/return-from-script. Layout: `00`.
- **0x03 block**: `03 <u16 len> <S> <T2>* <type><flags>`; **total length = len + 3**
  (the threshold sweep assumed len + 7). The first element is a table-1
  instruction; the following ones are TABLE-2 operator instructions
  (`op byte + rhs sub-expression`) repeated until `ip >= start+len`.
- **0x34 = `34 S S`**: helper 0x42468d(ctx, ptr, 0) dispatches the second
  operand itself, so assign = destination then source (confirmed by exact
  tiling of `str x="..."` statements: 9 bytes each).
- 0x2a-0x2f (rmw): `op S T2` (target, then a table-2 operator + its rhs).
- 0x12-0x18 layouts differ from the old `type2_u16` etc. annotations: they
  contain nested sub-expressions BEFORE the type/u16 bytes (see
  `analysis/handler_layouts_*.json`). qmdis.py's operand annotations are
  therefore unreliable except for fixed-width opcodes (0x01 0x02 0x19-0x22).
- (earlier today) 0x36 = thunk (0x35 with arg 0); 0x18 = `18 S S u16`; 0x43 =
  QueryInterface.
- Table-2 handlers: 0x00-0x38 = `op S`; 0x39-0x4b = `op type S` (double/mixed);
  0x4c-0x4e and 0x54-0x8e (59 handlers) are NOT documented anywhere.

### R4. Stream model (execution)
The loop `FUN_00420730` executes `table1[code[stream[i]]]` for i in
0..count-1; there is no other top-level fetch. Stream entries are therefore the
top-level *statements*; nested `S`/`T2` instructions are reached only through
handlers. Top-level tiling (`end(entry_i) == entry_{i+1}`) is the consistency
test; the old claim "entries also mark sub-expressions" (sample01 section) is
withdrawn. Decoded exactly with the corrected model:
- `str a="..."` = `34 <1f idx 00> <1e poolref>` (9 bytes, stream stride 9).
- `if(count <= 9999)` (original-1 fn0 stmt 10, original-2 fn0 stmt 3) =
  `ad 0b 00 | 03 0c 00 | 09 1f 1f 00 | 0f | 19 0f 27 00 00 | 00 00`:
  `ad` (if, u16 skip) + block{ load_i32 local; table-2 op 0x0f; push_i32 9999 }.
  The 9999 threshold is therefore a real comparison constant inside an `if`,
  now decoded structurally (the old "`86 c9` are operand bytes" story came from
  the shifted view: those were other instructions).
- sample02/06 correlation with source: 0xad = if, 0xc9 = out, 0x98 = `<u16>`
  (else/jump over), 0xd0 = ret, 0x9c = for, 0x24/0x34 = int/str assign,
  0x52 = acc/method call (source-correlated hypotheses, medium confidence;
  handlers not yet decompiled).

### R5. What is validated and what is not
Validated by handler bytes and/or exact tiling: table-1 fixed-width ops (0x01
0x02 0x19-0x22), 0x00, 0x03, 0x04-0x11 (op+S), 0x23-0x29, 0x2a-0x2f, 0x30,
0x34, 0x38, 0x3c-0x3f, 0x43, 0x4a, table-2 0x00-0x38. Partial fit
(`analysis/layout_fit_from_tiling.json`): 375 top-level tiles exact, 394 not,
4 unresolved over 50 functions; the misses are runtime-registered ops whose
helpers dispatch operands outside the analyzer's view (0xc9 `out` has a
variable argument list; 0x9c, 0x88/0x89, 0x99/0x9a, 0x37, 0x52 ...).
NOT validated: semantics of ~99 runtime opcodes and of 59 table-2 operators;
the 18 static 2.4.12-only opcodes; every qmdis operand annotation of
variable-length opcodes; every statement listing produced before today.

### R6. Impact on earlier conclusions
  minMessages: still not found, but the earlier negative finding rested on the
  broken decode and must be redone with the corrected decoder.
  that the bytecode was "decoded" before today is withdrawn.


## Level 2 byte-layout model (2026-11-07, after the re-validation)

Result of five handler-analysis passes (groups A-E, 2.4.2 handlers disassembled
through helpers; the exe bytes are the same ones a byte-reading debugger tool returns) and
(+ extension tokens in `qmlayout.py`); `python tile_check.py` and
`python audit_level1.py` re-check them against all 12 exes (50 functions).**

### Validation results (falsifiable, on real bytecode)
- **Top-level tiling:** every stream entry decodes to exactly the next entry:
  **773 ok / 0 bad / 0 unresolved** (was 148 ok at the start of the day with the
- **End-of-region test (independent of tiling, also covers each function's
  LAST statement):** the last decoded statement ends within 0-3 bytes (4-byte
  alignment padding) of the end of the code region in **50 of 50 functions**.
  `b2 S u16a u16b S_then S_else flag1 flag2` (handler 0x421955: after the first S
  it selects the then/else expression by the runtime value; a and b are byte
  offsets to the else-branch and to the 2 flag bytes). Override `[1,S,4,S,S,2]`.
- Regression-protected: audit_level1.py fails if tiling drops below 773/0/0 or
  end-of-region below 50.

### Layout notation
integer n = n raw bytes (opcode byte included); `S` = nested table-1
instruction; `T2` = table-2 instruction; extension tokens (ARGN, ARGS, X_*, IF,
IFEQ, SKIPN ...) encode count/flag-dependent tails (see qmlayout.py).
Semantics notes below came from handler reading + the sample sources; the
byte layout is what is tiling-validated.

### Layouts established (handler evidence + tiling; confidence per opcode)
| opcode | layout | notes |
|---|---|---|
| 0x00 | `00` | exit/return (throws) |
| 0x01 | `01 n id16 + n args` | args: normal S, or 0x7a-0x7e prefixed forms |
| 0x02 | 7 bytes | call by id |
| 0x03 | `03 len16 S T2* type flags` | total = len+3 |
| 0x04-0x11 | `op S` | unary / deref family |
| 0x19-0x22 | fixed immediates / local refs (5,5,2,9,9,5,3,3,3,3) | |
| 0x24-0x29 | `op S S` | assign family (0x34 str assign same shape) |
| 0x2a-0x2f | `op S T2` | rmw |
| 0x37 | `37 S b <table-2 handler (0x50+b)>` | op byte indexes table 2 at +0x50 |
| 0x38 | `38 a b S [b x S]` | only a=3,b=1 evidenced |
| 0x3a | `3a a b S + tail by a` | only a=3, a=10 evidenced |
| 0x3b | `3b S n (n x S) \| n==0: k [2 if k in 0,0x24] ; type flags` | n>=1 evidenced |
| 0x3d | `3d S S u16` | evidenced 21/21 |
| 0x43 | `43 u16 S` | QueryInterface (stubs only) |
| 0x47 | `47 b1 b2 b3 argc flags ... args` | variable; only Acc stubs |
| 0x49 | `49 ret tb1 tb2 argc u16 + argc x S` | 13/13 |
| 0x52 | `52 S n id16 + n args` | acc/method call |
| 0x83 | `83 tb ...` S count depends on type (0x0b/0x4b = 11 S) | other types handler-only |
| 0x98 | `98 u16` | jump |
| 0x99 | `99 u16 flag` | jump, flag unused by handler |
| 0x9a | `9a flags S [S]` | |
| 0x9c | `9c u16 00 S(var) S(init) S(limit)` | for loop |
| 0xad | `ad u16 S` | if; u16 = absolute STREAM INDEX of the last skipped statement |
| 0xc9 | `c9 flag + (S \| cnt S S* 00)` | out; arglist form when flag&2 |
| 0xd0 | `d0 flag [S]` | ret; flag 1 = with value |
| 0xd1 | `d1 u16 flag [S]` | repeat loop |
| 0x86 / 0x89 | 1 byte | break / continue |
Others in the json (0x31, 0x80, 0x82, 0x88, 0x8a, 0xa9, 0xb7, 0xbb, 0xc8, 0xd5,
0xd9, 0xda, 0xe2, 0xe7, table-2 0x54-0x8e subset) have handler-derived layouts but
1-3 real occurrences each.

### VM control-flow semantics established (handler 0x420730 + jump handlers)
`counter=0; while(counter<count){IP=stream[counter]; dispatch; counter++}`.
Jump handlers write `[ctx+0x20]`; the loop then increments, so a jump target
`u16` means "next statement executed is stream[u16+1]" (u16 = absolute stream
index of the last skipped / enclosed statement, inclusive; NOT a byte offset).
Loop bodies run through helper 0x4208b0(start,end); status byte `[ctx+0x1e]`:
1=break, 4=continue, 2=fell off end, 3=ret/exit.

### What is still NOT validated
- **111 of the 185 valid table-1 opcodes never occur in any of the 12 exes**:
  their handlers exist but no layout or semantics has been checked.
- 17 table-1 and 9 table-2 opcodes occur only 1-2 times (layout tiling-checked
  but statistically weak): 0x05 0x08 0x0e 0x0f 0x14 0x25 0x41 0x54 0x82 0x8a
  0xa8 0xa9 0xbb 0xe2 0xe5 0xe6 0xe8 / table 2: 0x08 0x09 0x0a 0x1b 0x1e 0x1f
  0x59 0x64 0x8c.
- Count/flag-dependent branches that no real sample exercises (0x83 types
  other than 0x0b/0x4b/0x18, 0x3b with n==0, 0x38 a!=3, 0x3a kinds other than
  3/10, 0x31 kinds 0x12-0x15, 0xd5 modes >1) come from handler reading only.
- Cross-check against the 2.4.12 handlers was done only indirectly (the 7
  2.4.12 samples tile with the same layouts); handler-to-handler comparison for
  group A/B/D/E opcodes was NOT done (group C found instruction-count
  differences of 1-20 in 0x47, 0xc8, 0xd5, 0x80, 0x60).
- SEMANTICS (what each opcode does in QM terms) are documented for the control
  flow set above and partly for others; most of the ~99 runtime opcodes are
  layout-only. Level 3 needs semantics for at least: assignment/typing
  (0x24/0x34/0x37), calls (0x01/0x49/0x52/0x47), `out` (0xc9), `if/for/rep/ret`.


## Level 3 groundwork: opcode semantics established (2026-11-07, validated)

Source: analyst group G (statement trees of compile_samples 01-07 vs their .qml) and
an INDEPENDENT validator (re-derived every claim from the handler bytes; verdicts
below). Machine-readable table: `analysis/opcode_semantics.json` (70 entries; labels
corrected after validation); per-statement trees: `analysis/statement_trees_samples.md`.

### The old Level-3 blocker is solved (CONFIRMED)
- `c9 <flag> S` = **`out` statement** (handler 0x4200d7 in 2.4.12). flag bit1 set =
  format form `c9 02 cnt S S* 00` (helper 0x42422f: count byte = alloca size,
  format string S, args until a 0x00 byte); flag bit1 clear = a single S (helper
  0x424906); bit0 selects another output sink (not seen). `c9 00` is therefore NOT a
  descriptor: 00 is the flag byte.
- `c9 00 0a 37 1f L 05 04 1e <fmt> 09 1f L2 00` = out( 0a( `37` dest=L, b=05 ) ):
  0x37 evaluates the destination S (a hidden string temporary), reads b and calls
  table-2 handler `0x50+b` (b=5 -> T2 0x55 = `push 0; call 0x42422f`, the same
  formatting routine: this is the `F"...{x}"` form). `05 04` is NOT an opcode pair:
  05 = the b selector, 04 = the vararg-block size byte. `0a` loads the temp's char*.
- `d1 u16 flag` = **`rep` loop** (u16 = stream index of the last body statement,
  flag 0 = infinite, flags 1/2 add a count S); it stores nothing. The old note "d1 =
  store-to-local (4-byte instruction)" is FALSE (the `d1 08 00 00` after `push_i8 0`
  is a separate `rep` statement).
- `30 1b 01` = bare `1` statement = wait 1 second (0x30 = wait seconds, value*1000 ms,
  NOT double_to_int). `31` = wait_for (kind&0x1f=4 polls IsWindowVisible, 5 =
  IsWindowEnabled; timeout*1000, 0 = infinite). `37` = format-into (NOT interface_get).

### Structural facts (CONFIRMED)
- String pool base for `1e <u32>` = `block+0x48+(ptr5-ptr0)` (header dword #5; handler
  0x40ebab adds `[ctx+0x38]+0x14`). Differs per function; all refs of the 16 sample
  functions land on a string start (2 refs in Acc.Find land on NUL padding).
- `1f u16` = index into the local-variable descriptor table = header section ptr2:
  8-byte entries `{u32 frame_off, u16 type, u8 flags, u8}`, count = u16 at
  block+0x2a. Types seen: int 0, str 4 (16-byte slot), Acc 0x24, ARRAY 0x0d. Slots follow
  declaration order; F-strings and str-returning calls (e.g. `a.Value`) get hidden
  temporaries at first use. Local NAMES are not stored in the exe (res3 holds
  function names only).
- Call ids: `52 S n id16` and `02`/`49` resolve through res2 `id` -> res3 name
  (2.4.12: Acc.Find 236, FromWindow 240, DoDefaultAction 246, Value 251, State 254,
  GetChildObjects 257; QM 2.4.2 original-1: 258/268/273/276). IDs are per build. Opcode
  0x49 ids (e.g. 523 = ProcessNameToId, argc 3) index the runtime's builtin table,
  not res2; the name rests on one source correlation (INFERRED). Arguments of 0x49 are
  pushed in code order, so the LAST coded argument is the first C parameter (explains
  `1b 00 1b 00 <name>`).
- Table-2 comparison operators are the INVERSE of what batch5-table2.md says
  (handlers do `cmp LHS,RHS; j<cc> skip`): **0x0e = `>`, 0x0f = `>=`, 0x10 = `<`,
  0x11 = `<=`** (CONFIRMED in 2.4.2 and 2.4.12; sample06 `find(..)>=0` = T2 0x0f).
  batch5-table2.md rows 0x0e-0x11 are WRONG (their own formulas contradict their
  labels). 0x19-0x20 aliases inherit the same caution. Other T2: 0x00 `==`, 0x01 `+`,
  0x06 `&`, 0x0c `and` (short-circuit, writes IP=0xffff).
- Control flow (CONFIRMED): `ad u16 S` = if (zero -> skip to stream[u16+1]; u16 includes
  a trailing `98` else-jump when an else exists), `98 u16` = else/jump, `9c u16 00 S S S`
  = for (var, init, limit, limit exclusive), `d1` = rep, `d0 flag [S]` = ret, `89` =
  continue (counter=0x7530, status 4), `86` = break, `88 u16` = indirect jump through a
  code-offset cell (trailing bytes are data, never executed - the layout is a fit,
  INFERRED).
- Mapped constructs (observed = handler + source line + tiling): int assign 0x24, str
  assign 0x34, `x+1` as rmw 0x2a + T2, `if` 0xad, `else` 0x98, `for` 0x9c, `rep` 0xd1, `ret`
  0xd0, `continue` 0x89, `out` 0xc9, `wait` 0x30, `wait(0 WV win(..))` 0x31 + 0xe7,
  `find(a b)` 0x9f (PLAUSIBLE: name from source only), `win(title class)` 0xe7
  (PLAUSIBLE), Acc method call 0x52, `.len` 0x3a a=10 (handler case unverified),
  `all[i]` 0x3b (handler evidence thin), ProcessNameToId 0x49.

## Level 2/3 corpus extension: samples 08-26, groups G-J, per-exe builtin tables (2026-11-08, validated)

76/76, `python audit_level1.py` PASS. Status words: observed = bytes + known .qml source (or handler + help);
inferred = one occurrence/order only; handler-only = read from the handler, no sample exercises it.

### Per-exe builtin function table (CONFIRMED, verified in original-1 and sample24)
- Opcode 0x49 `49 00 00 20 argc <u16 id> args...` calls a DLL/builtin function by id. The id->name table is NOT in
  qm.exe: each exe has its own: **res9** = u16 count, entries {u16 id, u16 dll index (bit 0x8000 = flag), name};
  **res8** = u16 count, NUL-terminated dll names (empty name allowed). Loader chain: handler 0x429650 -> 0x429520 ->
  0x4294d0 (12-byte table at 0x473bc8), resolved with GetProcAddress (0x402213).
- Ids differ between builds: 2.4.2 ProcessNameToId 503, GetLastError 221, TerminateProcess 224, CloseHandle 225,
  IsWindowVisible 5, IsWindow 6 ...; 2.4.12 ProcessNameToId 523, GetLastError 232 ... (+11 / +20). Arguments are coded
  last-to-first (the last coded arg is the first parameter). Tables: analysis/res9_tables.json, analysis/builtin_function_ids.json.
- **res10** = u16 count + 8-byte records {u16 id, 0, u16 type, 0}: hidden global variables created at load (table 0x473be0),
  addressed by opcode 0x20 (`20 <u16 id>`); first seen with `lock` in sample25. Type 0x28 class not traced.
- Many builtins have their own opcode (win 0xe7, child 0x8c, id 0xb4, empty 0x9b, len 0xba, find 0x9f, findb 0xa7, findc 0xa0,
  findl 0xa6, findrx 0xa8, findt 0xa5, findw 0xa4, matchw 0xc4, numlines 0xc5, val 0xe6, iif 0xb2, tok 0xe2, perf 0xce,
  pixel 0xcd, dir 0x96): see opcode_semantics.json.

- observed: 0x35 `s+"lit"` append; 0x80 act; 0x86 break; 0x8a clo; 0xa9 goto (operand = target stream index - 1);
  0xb7 key (`b7 flags tags`; flags 0 plain, 1 key+, 2 key-; tag 1 key codes, 2 string, 3 mode; 06/07 = `{` `}` group);
  0xc8 opt (u32 mask: hidden 0x40000, clip 0x40, err 0x1000, waitmsg 0x4000, waitcpu 0x8000, slowmouse 0x10000;
  save = ffffffff, restore = feffffff; value S); 0xda spe (set/get decided at run time by statement start);
  0xbc/0xbd/0xd3 min/max/res (byte after opcode: n/x/s); 0x82 atend; 0x9d foreach (splits on LF); 0x01 call by res2 id;
  0x99 err/err+/err- (modes 0/1/2); 0x9a end (flags: 4 no-open, 8 warning, 16 dll error); 0x85 bee; 0xe3 tim; mouse clicks
  0x93/0xb8/0xc1/0xd4 (2nd byte = first letter d/l/m/r); 0xcc = paste (= outp per help); hid/men/but/cop/del/mkdir/lock;
  wait kinds WA WC WD(0x82) WP V P ML H -WA(0x81) (kind = byte&0x1f, bit 7 = negate); T2 0x4c/0x4e string =, !=.
- inferred: mac 0xbb; mov/siz (assignment by order); wait kinds K 0x08, M 0x0d, WP 0x03; lcase/ucase, left/right, getclip/setclip
  (single statements); 0x00 bare `end`.
- handler-only (unobserved branch): see progress.md 2026-11-08 'Open / weak'.
- Corrections to earlier notes: 0x35 is NOT object_op (qmdis fixed); `9d 05`/`9e 05` pairs inside 0x01/0x82 are u16 function ids,
  not opcodes; the res2 names `<00001>Name` carry the parent function id.

### Decompiler status (qmdec.py)
All 26 samples decompile with 0 TODO in user code (sample26 embedded stdlib still has TODO). Not stored in the exe, so not
recoverable: local/label names, parentheses, `paste` vs `outp`, `opt hidden` vs `opt hidden 1`, number base.
Originals (ok/inferred/TODO): original-1 82/45/37, original-2 57/31/22, original-3 5/3/1.

Guard: tiling 1473/0/0, end-of-region 80/80, `audit_level1.py` PASS, opcode_semantics.json 200 entries (35 exes).
- Order-swap test (sample27 = earlier constructs in opposite order): bytes follow the names - left 0x5e/right 0x5f, lcase 0x5a/ucase 0x5b,
  getclip 0x6c/setclip 0x6d, hid 0x20 / hid- 0x2d, wait K 0x08 / M 0x0d; ML = 0x0a (handler maps kinds 0x0a/0x0b/0x0c to VK 1/2/4);
  mov = 0xbf (`mov+` shares it, mode byte 3), siz = 0xdb by elimination; `wait -WC` == `wait WD` (byte 0x82).
- 0x37 string-method selectors (table-2 key = 0x50 + selector): fromn 0x61, insert/replace 0x63/0x65 (handler 0x423ac1, mode letter),
  remove 0x14 (handler 0x423b64 -> 0x42be9b in 2.4.12), beg/begi/end/endi/mid/midi 0x84-0x89 (handler 0x424444; flag bit0 = i, bit1 = end,
  bit2 = mid), getl/gett 0x33/0x32, findreplace, replacerx, timeformat, unicode/ansi, set. `.from()` takes n arguments (T3 0x10).
- Commands: ifk/iff/ifa 0xae/0xaf/0xb0 (`op u16 n letter flags`, letter k/f/a, flags bit 7 = '-'); ont 0xcb; xm/ym 0xeb/0xec
  (flag 0 = x, 1 = y; observed); rget/rset 0xd6/0xd7, inp 0xb3, qmitem 0xcf, net 0xc7 (single occurrences, operand meaning inferred);
  mou modes 0 / '+' 0x2b / '-' 0x2d with n = 0 / 2 / 3; mes operands coded caption, flags, text; `mes-` = flag byte 2 (one occurrence);
  mkdir with parent (b=2); `opt hidden 0` stores `1b 00`.
- Pointer/type ops: 0x0f deref, 0x1d int64 constant (1234567890123 decodes exactly), 0x25 = 32-bit store emitted for pointer-typed
  destinations (descriptor byte+2 == 1; handler 0x40f580 differs from 0x24 only in double->int conversion; name `st_ptr` inferred),
  0x26-0x29 typed stores, 0x2c-0x2f rmw, T2 long operators = int +0x26, double = int +0x38. User-type names/members are not stored in the exe.
- Stdlib-derived TODO fixes in the 2.4.2 exes are `inferred` only: the installed System.qml is 2.4.12 and differs from the 2.4.2 stdlib.
- QM compile error text "/NNN" = character offset of the START of the failing line (CRLF text).
- Resource name 11 appears in sample29 (a zip DLL, present only when `zip` is used); res10 = hidden global variables (opcode 0x20).

### Addendum 2026-11-08 (3): samples 31-33, group M, `run`/`mes`/rget, the 36 unseen opcodes
Guard: tiling 1633/0/0, end-of-region 91/91, `audit_level1.py` PASS, opcode_semantics.json 220 entries (38 exes).
- **sel/case (CONFIRMED on samples 32/33, handler 0x420790):** `d9 u16 selid kind S [S]`, kind 0 = int sel, 1 = string sel,
  2 = string sel + flags expression (`sel s 3`); `88 u16 selid count data` with data = count x u32 (count 0 = `case else`: 4 pad bytes in an int sel,
  0 bytes in a string sel; lists `case [a,b]` are count n). The sel type of a `case` is found from the preceding `d9` with the same selid.
- **Function header (handler-backed, sample31):** return type u16 at +0x30 (5 = double); byte at +0x38 = parameter count, +0x39 = required count
  (optional params); descriptor flags byte 4 = `str&` reference parameter. `function#` and a function without a return value look the same.
- **0x3f type 0x0f = BSTR:** `3f 0f S S` (second S evaluated at 0x4142c8 via helper 0x424906); 0x38 a=5 = SysStringLen.
- **`run` 0xd5 (observed, sample29):** `d5 00 n` - n = argument count, followed by n sub-expressions in written order (file, par, verb, dir); n=5 (flags) inferred;
  n=6/7 TODO. **mes/mes-** (handler 0x420192): coded order caption, style, TEXT last; flag byte 2 = `mes-`. **rget/rset** observed for n=3 (handlers 0x4221b2 /
  0x422470; -1/-2 branches = delete value/subkey per help). inp (0x42037b), qmitem (0x4234b2), net (0x42306a): inferred, one occurrence each.
- **0x18 index_addr:** the trailing u16 is the element size in bytes (`imul` in handler 0x4122a0: address = base + index * u16).
- **findrx (0xa8):** layout is `[3, X_LA8]`; the earlier `[3,S,S]` was valid for n=2 only and tiled only because 0x03 blocks are length-authoritative
  (nested arguments were never decoded). Lesson: tiling of an 0x03 block does not validate the layout of its nested arguments.
- **Unseen opcodes:** 36 of the 185 valid table-1 opcodes never occur in any statement of the 38 exes. Handler analysis (analysis/unseen_opcodes.json;
  layouts handler-only, command names inferred) shows they are mostly untried features, not unreachable ones: thread/global variable declarations (0x50, 0x55, 0x91),
  parent-frame variables of `#sub ... v` (0x4d/0x4f), `win` without arguments (0x32), pointer indexing (0x16/0x17), VARIANT conversions (0x40-0x46),
  aliases of seen opcodes sharing a handler (0x84 acctest, 0x8d childtest, 0xa1-0xa3 findcr/cs/cn, 0xb1 ifi, 0xd2 ren, 0xe9 wait) and four stub slots
  that are a bare `ret` in both runtimes (0x94 0x97 0xc6 0xdd, probably dis/deb/newitem/str.setmacro which are unavailable in exe). Samples 34-36 target them.
- Originals (ok/inferred/TODO): original-1 87/77/0, original-2 58/52/0, original-3 5/4/0. No TODO remains on the originals; the last ones were stdlib code
  and are `inferred` only (System.qml is the 2.4.12 stdlib).

### Addendum 2026-11-08 (4): res10 record format, stub opcodes, stored names, QM comment syntax
Guard: tiling 1693/0/0, end-of-region 95/95, audit PASS, 40 exes, opcode_semantics.json 239 entries.
- **res10** (loader 0x40248f, helper 0x40f430, opcode 0x20 handler 0x412c00): count u16, then records `{u16 id, u16 size, u16 type, u16 flags}`. size != 0: raw malloc storage;
  size == 0: object built by the factory registered for `type`; flags 8 = user global (`int+`/`str+`), flags 0 = hidden runtime object (e.g. the `lock` object, type 0x28). Opcode 0x20 looks the record up by id.
  The earlier note "{id, 0, type, 0}" was only one case.
- **Names stored in the exe:** function and `#sub` names (res3 `<parentid>Name`), thread-variable names (string pool + 12-byte records {u32 name offset, u16 size, u8, u8, u16 descriptor index, u16 flags};
  flag bit0 = has initialiser, bit1 = `--` private). **Not stored** (searched res1-res10 plain/decrypted + whole file): local and parameter names, global variable names, user-type and member names, labels.
- **Compile-time rejected in exe** (help + user compile errors "cannot be used in exe"): dis, deb, newitem (and str.setmacro per help). The stub slots 0x94 0x97 0xc6 0xdd are a bare `ret` in both runtimes.
- Formerly unseen opcodes now seen: acctest 0x84 (alias of 0x83 acc), childtest 0x8d (alias of 0x8c), findcr/findcs/findcn 0xa1/0xa2/0xa3, htm 0xac, inpp 0xb6, ren 0xd2 (alias of 0x8b cop; byte b3 = option char, `ren*` = 0x2a),
  scan 0xdf, 0x16 pointer indexing (stride 4/1/2), 0x40/0x42/0x44/0x45/0x46 VARIANT conversions and unary ops, 0x50 thread-variable declaration, 0x8e call, 0xaa getopt, 0x54 `&sub.X` by res2 id, 0x4e parent-frame variable by descriptor index.
- **QM comment syntax (help Commands\IDP_COMMENT):** `statements;;comment`, or a whole line starting with space, `/`, backslash or `;`. `/* */` is NOT valid. Labels are written with a leading space (` lab1`); getopt options are bare words;
  `opt` is a keyword.
