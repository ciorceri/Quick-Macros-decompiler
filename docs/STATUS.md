# STATUS

Numbers below were produced on a corpus of the 35 public samples (`samples/set1` + `samples/set2`, built with QM 2.4.12) with the tools in this
repository. Your own corpus may give different totals; run `python audit_level1.py` and compare with your `baseline.json`.

## Levels

| level | goal | state |
|---|---|---|
| 1 - container | extract and decode PE resources (res1-res11), decrypt res3, validate framing | complete; `audit_level1.py` PASS |
| 2 - bytecode layout | byte layout of every opcode used by real code, validated by tiling | complete for all opcodes seen in the corpus; 36 valid table-1 opcodes are handler-only |
| 3 - decompiler | readable, valid QM source | working (`qmdec.py`): every statement of every sample decodes; evidence labels per line |
| 4 - round trip | recompile decompiler output and compare bytecode | 33 of 35 samples are round-trippable (the rest need constructs whose names or declarations are not stored in the exe, e.g. user types). Two-level verdict (LEVEL A semantic, LEVEL B binary layout): **33 of 33** round-trippable samples are SEMANTICALLY IDENTICAL after decompile -> recompile; LEVEL B differs only by string-pool order, section pointers/sizes and compile-time ids. In the first attempt 20 of 29 were identical; the rest were generator defects that were fixed (declaration order, unused locals, flat operator lists, label comments, `dll` declarations, thread-variable order, integer `ifk` operand). sample30 and sample33 are not round-trippable (user `type` declarations are not stored in the exe) |

## Validated numbers (35 samples, no private exes)

| measure | result |
|---|---|
| top-level stream entries tiled exactly (`tile_check.py`) | ok 1103, bad 0, unresolved 0 |
| end-of-region (last statement ends in padding) | 61 of 61 functions |
| undocumented opcodes seen in real code | 0 |
| unresolved `0x49` ids (not in the exe's own res9) | 0 |
| decompiler statements (all functions, incl. embedded stdlib) | 625 ok, 385 inferred, 0 partial, 1 TODO |
| decompiler statements (user code only) | 582 ok, 341 inferred, 0 partial, 0 TODO |
| output syntax check (`test_qmdec_syntax.py`) | 35 files, 0 failures |
| `compare_roundtrip.py --selftest` (self, other sample, 1-byte mutation, padding mutation) | 35/35 PASS |
| `make_roundtrip.py` | 33 of 35 round-trippable, 2 `NOT ROUNDTRIPPABLE` (sample30, sample33: user `type`) |
| `compare_roundtrip.py --all` (33 recompiled exes vs originals) | 33 of 33 SEMANTICALLY IDENTICAL (LEVEL A); LEVEL B differs only by string-pool order, section pointers/sizes, compile-time ids |

Opcode knowledge (`analysis/`): 239 semantic entries in `opcode_semantics.json` (199 observed - 5 of them with an inferred meaning - and 40 inferred; see `OPCODES.md`),
185 valid table-1 opcodes in total (identical in QM 2.4.2 and 2.4.12), of which 36 had not been seen in any statement of the author's reference corpus (the 35 samples plus three private QM 2.4.2 exes that are not distributed); a few of the remaining entries were first seen in those private exes, but every semantic entry also has sample evidence.

## Open items

* Handler-only opcodes (`analysis/unseen_opcodes.json`): thread/global variable declarations, parent-frame variables of `#sub`s, `win` without arguments, pointer indexing,
  VARIANT conversions, and aliases that share a handler with seen opcodes. Samples that exercise them are welcome.
* Weakly evidenced opcodes with 1-2 occurrences (marked `inferred` in `OPCODES.md`): `mac`, `inp`, `qmitem`, `net`, `mes-`, `run` with 5-7 arguments, `tok` with 4 arguments, `findrx` with other than 2 arguments.
* Table-2 operators `0x4c-0x4e` and `0x54-0x8e` are only partly mapped; handler-to-handler comparison between 2.4.2 and 2.4.12 was done indirectly through the shared layouts.
* The `type` declaration of user-defined types cannot be rebuilt (names are not stored); a round trip for those needs a manual declaration (sample30, sample33). `dll` declarations in round-trip output are inferred from call arguments (or a small Win32 table) and may differ from the original source.
* QM builds other than 2.4.2 and 2.4.12 are untested.
* `handler_layouts_*.json` are unvalidated automatic guesses kept as a starting point for new opcodes.

## Where things came from

The history of the research (corrections included) is in `research-log.md`; the evidence rules are in `METHODOLOGY.md`.
