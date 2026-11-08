# analysis/

Machine-readable facts about the QM bytecode and runtime. None of it contains script content from any third-party exe.

| file | content | rebuild |
|---|---|---|
| `opcode_semantics.json` | per-opcode name, operand layout, QM construct, evidence, confidence (keys `T1:0xNN`, `T2:0xNN`, `T2via37:0xNN`, `ARG:0xNN`) | curated by hand; `python tools/gen_opcodes.py` renders `docs/OPCODES.md` from it |
| `layout_final.json` | **the byte-layout table used by the tools** (`tile_check.py`, `qmdec.py`): decimal opcode -> token list; keys `t2:0x..` = table-2 layouts. Overlaid on `qmlayout.T1` | curated; each entry's provenance is in the group files |
| `layout_overrides*.json`, `layout_overrides_group*.json` | the individual override sets (A..O) that were applied, kept as provenance; later groups supersede earlier ones. `layout_final.json` already contains them | n/a |
| `builtin_function_ids.json` | builtin functions that have a dedicated opcode, and the per-build id differences of `0x49` calls | curated |
| `unseen_opcodes.json` | the 36 valid table-1 opcodes never seen in the reference corpus: handler addresses, behaviour read from the handler, the QML construct to try | curated |
| `handler_layouts_2.4.2_table1.json`, `handler_layouts_2.4.12_table1.json`, `handler_layouts_table2.json` | automatic handler-based layout guesses (see `handler_layout.py`); a starting point, NOT validated (known blind spot: helpers that dispatch operands) | `python handler_layout.py <exe> <table VA> --json out.json` (needs an exe of the matching build) |
| `runtime_tables_2.4.2.json`, `runtime_tables_2.4.12_sample06.json` | dispatch tables after the runtime's own initialisation (table 1 and table 2 handler VAs) | `python runtime_tables.py <exe> <t1 VA> <t2 VA> --json out.json` |
| `res9_tables.json` | per-exe res8/res9/res10 tables of the sample corpus (ids are NOT comparable across exes) | `python qmtool.py --dump-all analysis/res9_tables.json corpus` |

Addresses are virtual addresses in the stock QM runtimes (image base 0x400000). Labels "original-1/2/3" in evidence strings refer to
three QM 2.4.2 executables that were used during the research and are not distributed.
