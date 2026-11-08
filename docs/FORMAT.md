# FORMAT - how a QM-built executable stores its script

This document describes what the tools in this repository have established about executables produced by
Quick Macros 2 ("QM", 2.4.2 and 2.4.12 were studied) with **Make Exe**. Everything here was derived by
static analysis (PE parsing, disassembly of the runtime's own handlers, and comparison with exes built from
known `.qml` sources in `samples/`). Where something is only read from handler code, it is marked as such.
See `METHODOLOGY.md` for the evidence rules and `OPCODES.md` for per-opcode detail.

## 1. Overall shape

A QM exe is a PE32 (x86) image: the common QM runtime (native code, several thousand functions, image base
0x400000) plus the user's script, **pre-compiled to bytecode** and stored in the resource table as a custom
resource of **type 252**. The runtime contains a bytecode interpreter; the exe does not contain the source text.

Resource entries are addressed by their **name id** (not by position). QM uses the names
`1, 2, 3, 4, 6, 8, 9` always or optionally `10`, `11` (there is no 5 or 7 in the exes studied).
`qmtool.py` writes them as `res<name>.bin`.

## 2. Resource layout (type 252)

| name | content |
|---|---|
| res1 | function-table header: `u16` function count, a few bytes, ONE `{GUID}` and the main macro's name, then a builder banner (text saying the exe was created with Quick Macros and the version). Only one name is stored here; all other function names are in res3. The GUID is the item GUID of the macro that was compiled. |
| res2 | function table: `count` records of **20 bytes** (see below) |
| res3 | **encrypted** NUL-separated identifier names: one per res2 record, in order (user function names, `#sub` names written `<00007>Name` = parent function id + name, and the embedded standard-library function names) |
| res4 | the script image: for each function a **block** (header + code + statement stream + descriptor tables) and the string pool. Not encrypted. |
| res6 | global-variable definition data (small, structured, not encrypted; not fully decoded) |
| res8 | DLL names used by builtin `0x49` calls: `u16` count then NUL-terminated names (an empty name is valid) |
| res9 | per-exe builtin-function table: `u16` count, entries `{u16 id, u16 dll (low 15 bits = index into res8, 0x8000 = flag), name + NUL}` |
| res10 | optional: `u16` count, records `{u16 id, u16 size, u16 type, u16 flags}` = hidden global variables created at load (see below) |
| res11 | optional: an embedded DLL (observed when the `zip` command is used) |

### res2 record (20 bytes, little-endian)

```
+0  u16 id          function id (the id used by call instructions)
+2  u16 flags       bit0 = has a res4 block, bit1 = has a res5 blob
+4  u16 kind        1 = main macro, 2 = user function / #sub, 7 = library stub, ...
+6  u16 flags2      (kind,flags2) read as a dword by the loader; dword & 0x200 => block encrypted
+8  u32 name_off    offset of this function's name in DECRYPTED res3 (start of the NUL-terminated name)
+12 u32 block_off   offset of this function's block in res4
+16 u32 blob_off    offset into res5 (only if flags bit1; else 0)
```

Checks used by `audit_level1.py`: `len(res2) % 20 == 0`, the res1 count equals the number of records and the
number of names in res3, `name_off` equals the cumulative start of each name, every `block_off` lies inside res4.

## 3. Encryption of res3

A 4-byte XOR chain with a constant key `5d 91 38 6f` that lives in the **runtime**, not in the script (it is
identical in every QM exe studied; its RVA is `0x55854` in 2.4.2 builds and `0x64efc` in 2.4.12 builds,
see `qmtool.KNOWN_KEY_RVAS`). Decryption runs from the last byte to the first:

```python
k = KEY[n & 3]
for i in range(n - 1, -1, -1):
    b = data[i]
    out[i] = b ^ k
    k = (KEY[i & 3] + b) & 0xFF
```

(`qmtool.qm_decrypt`). res3 then decodes to readable identifiers. `qmtool.check_runtime_key` verifies the key
bytes at the expected RVA; the audit fails if a new build keeps the key elsewhere.

## 4. Per-function block (in res4)

Every function starts at `res2.block_off`. The block begins with **9 u32 pointers** that the runtime loader
(`FUN_00401add` in 2.4.2) relocates by `block + 0x48 - ptr0`:

| pointer | meaning |
|---|---|
| ptr0 | start of the code region (after relocation: `block + 0x48` - the **code base**) |
| ptr1 | end of code / start of the **statement stream**; `ptr1 - ptr0` = code size = stream offset |
| ptr2 | end of the stream / start of the local-variable **descriptor table**; `ptr2 - ptr1` = stream size |
| ptr5 | string pool base: a `1e <u32>` constant reference resolves to `block + 0x48 + (ptr5 - ptr0) + u32` |
| others | further tables (function descriptors, thread-variable records, ...) |

Other header fields: `u16 [block+0x28]` = number of statements (stream length), `u16 [block+0x2a]` = number of
local descriptors, `u16 [block+0x30]` = return type (5 = double), `u8 [block+0x38]` = parameter count,
`u8 [block+0x39]` = required parameter count (optional parameters).

* **Code region** (`block + 0x48 ...`): the bytecode. Statements are variable length and are padded to a 4-byte
  boundary at the end of the region.
* **Statement stream**: an array of `u16` offsets into the code region, one per **top-level statement**. The
  interpreter executes `table1[code[stream[i]]]` for `i = 0 .. count-1`; nothing else fetches instructions.
* **Local-variable descriptor table**: 8-byte entries `{u32 frame_offset, u16 type, u8 flags, u8}`. Types seen:
  `int` 0, `str` 4 (16-byte slot), `Acc` 0x24, `ARRAY` 0x0d, ... Bytecode refers to locals by index
  (`1f u16`). Hidden temporaries (F-strings, string-returning calls) get descriptor slots at first use.
* **String pool**: NUL-terminated strings, referenced by `1e <u32 offset>`.
* **Thread variables** (`int- t`): the only variable names stored in the exe - string pool name plus a 12-byte
  record `{u32 name offset, u16 size, u8, u8, u16 descriptor index, u16 flags}` (flag bit0 = has initialiser,
  bit1 = `--` private).

## 5. The virtual machine

* The interpreter loop (`FUN_00420730` in 2.4.2): `counter = 0; while (counter < count) { IP = stream[counter];
  table1[code[IP]](ctx); counter++ }`. Jump handlers write the loop counter, so a jump operand `u16` means "the next
  statement executed is `stream[u16 + 1]`": it is the absolute **stream index of the last skipped statement**,
  not a byte offset. Loop bodies run through a helper that runs statements `start..end`; a status byte
  reports `1 = break, 4 = continue, 2 = fell off the end, 3 = ret/exit`.
* An instruction evaluates its operands by **dispatching nested instructions** (written `S` in layouts) which leave
  their result in the context (value, address, a type byte and a flags byte). Several opcodes call helpers that
  themselves dispatch further operands, which is why the byte length of many opcodes depends on the operands.
* **Dispatch tables are filled at run time.** The PE image only holds handlers `0x00-0x55` of table 1; the
  runtime start-up code registers ~99 more (`0x80-0xed`, with gaps) before any script runs. Together there are
  **185 valid table-1 opcodes** (identical index set in 2.4.2 and 2.4.12). `runtime_tables.py` rebuilds the
  post-init table from an exe by emulating those writes. Bytes `0x56-0x7f`, a few zeroed slots and `>= 0xee`
  are not opcodes.
* **Table 2** (operators: `==`, `+`, `and`, comparisons ...) is a second dispatch table (`table1 + 0x400`;
  VA 0x461438 in 2.4.2, 0x472490 in 2.4.12). It is used for the operator byte inside `0x03` expression blocks
  and for read-modify-write statements. Comparison operators are the inverse of the intuitive reading of the
  handlers: `0x0e = >`, `0x0f = >=`, `0x10 = <`, `0x11 = <=`.
* Builtin DLL/runtime functions are called with opcode `0x49` using **ids that are per-exe** (res8/res9 map id to
  name; ids differ between QM builds). User functions are called by their res2 id.
* Hidden globals (`int+`, `str+`, and the compiler's `lock` object) come from res10 and are addressed by `20 <u16 id>`.
  For a record with `size != 0` the storage is raw memory; with `size == 0` an object is built by the factory
  registered for `type` (type 0x28 = lock object). `flags 8` = user global, `flags 0` = hidden runtime object.

## 6. Layout notation

`analysis/layout_final.json` maps an opcode (decimal string) to a token list describing its byte layout:

| token | meaning |
|---|---|
| integer `n` | `n` raw bytes (the opcode byte is part of the first count) |
| `S` | a nested table-1 instruction |
| `T2` | a table-2 (operator) instruction |
| `BLOCK`, `FOR` | the length-prefixed expression block (`03`) and the `for` header |
| `ARGN`, `ARGS`, `X_*`, `IF`, `IFEQ`, `SKIPN`, ... | extension tokens for count/flag-dependent tails, implemented in `qmlayout.py` |
| key `t2:0x..` | a table-2 layout |

Layouts are tested, not trusted: see "tiling" and "end-of-region" in `METHODOLOGY.md`.
Examples: `03 <u16 len> S T2* type flags` (total length `len + 3`), `ad <u16> S` (if), `34 S S` (string
assignment), `c9 flag [cnt] (S | S S* 00)` (`out`).

## 7. What the decompiler does with this

`qmdec.py` walks every function's stream with `qmlayout.Decoder`, maps opcodes through
`analysis/opcode_semantics.json` to QM syntax, resolves builtin ids through the exe's own res8/res9, and prints
QM source with `;;` trailing notes where something is inferred. Names that are not stored in the exe are neutral
(`loc<i>`, `glob<id>`, `type_<id>`); see `LIMITATIONS.md`.
