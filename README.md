<<<<<<< HEAD
# Quick-Macros-decompiler
A decompiler for Quick Macros 2
=======
# Quick Macros 2 decompiler

**Quick Macros 2 decompiler** is a set of Python tools that recover a readable script from an executable built with
**Quick Macros 2** ("QM"; versions 2.4.2 and 2.4.12 studied). A QM exe is the QM runtime plus the script **pre-compiled to bytecode**
in a PE resource; the tools extract that resource, decode the bytecode with a layout model that is tested against real exes,
and print QM source.

The project documents the file format, the bytecode, and the evidence behind every claim, so others can verify and extend it.

## Legal and ethical notice

* Use these tools **only on executables you own or have the right to analyse** - typically to recover the source of your own
  macro whose `.qml` was lost, or for interoperability and research.
* Quick Macros is the property of its author. This project is **not affiliated with or endorsed by** QM's author. It contains
  **no QM binaries, no QM help text, and no copy of `System.qml`**. Compiled exes embed the proprietary QM runtime and
  must never be added to this repository (`.gitignore` blocks them; `python tools/check_publish.py` enforces it).
* The tools only **read** files. They never execute an exe.
* The purpose is recovery and interoperability: the decompiler output is a best-effort reconstruction, not the original source
  (see [LIMITATIONS](docs/LIMITATIONS.md)).

## Requirements

Python 3.10 or newer and:

```
pip install -r requirements.txt     # pefile, capstone
```

`capstone` is needed only by `handler_layout.py` and `runtime_tables.py` (research tools that read the QM runtime's own code);
the extractor, validators and decompiler need `pefile` only.

## Quick start

Your exes go in `./corpus` (searched recursively for `*.exe`), or set `QM_CORPUS=/path` or pass `--corpus DIR`.

```
# 1. extract the resources of one exe (res1.bin, res2.bin, ... named by PE resource name id)
python qmtool.py corpus/my_macro.exe -o extracted

# 2. check the layout model against your whole corpus
python tile_check.py                       # tiling ok/bad/unresolved: [N, 0, 0]
python audit_level1.py                     # container + layout audit, PASS/FAIL

# 3. decompile one exe, or all of them
python qmdec.py corpus/my_macro.exe                  # to stdout
python qmdec.py corpus/my_macro.exe -o my_macro.qmdec.qml
python qmdec.py corpus -o out                        # every exe of a folder -> out/<name>.qmdec.qml
python test_qmdec_syntax.py out                      # sanity check of the output syntax
```

When no exe is found the tools say so and exit non-zero.

### Build the corpus from the samples

The repository ships QM **source** samples in `samples/` (no exes). With your own legal QM installation compile each `.qml`
(Make Exe) and put the exes into `./corpus`. Details in [samples/README.md](samples/README.md). Then:

```
python audit_level1.py --write-baseline    # record the numbers for YOUR corpus in baseline.json
python audit_level1.py                     # from now on regressions fail (strict)
```

With the 35 public samples the author obtained: tiling ok 1103 / bad 0 / unresolved 0, end-of-region 61 of 61 functions
(see [STATUS](docs/STATUS.md)). Your numbers depend on your corpus; that is why the baseline is generated, not shipped.

### Optional environment variables

| variable | effect |
|---|---|
| `QM_CORPUS` | corpus directory (default `./corpus`) |
| `QM_EXCLUDE` | comma list; exes whose file name contains any entry are skipped |
| `QM_SYSTEM_QML` | path of your own QM installation's `System.qml`, used only to name parameters of embedded standard-library functions (inferred names, clearly marked) |

## Output format

Decompiler output is valid QM syntax:

* `;;` trailing notes carry the evidence level of a statement, e.g. `;;inferred: ...`; whole-line notes start with `;`. A line
  `; TODO(evidence ...)` means the statement could not be decoded and nothing was guessed; the raw bytes are in the note.
* **Thread-variable names are real** (they are stored in the exe). **All other names are placeholders**: locals and parameters
  `loc<i>`, globals `glob<id>`, user types `type_<id>`; labels, comments and formatting are lost. Function and `#sub` names are real.
* Builtin DLL/runtime calls are named from the exe's own resource tables.

### One item, one file

`qmdec.py` writes the main macro plus any `#sub` sections of its own. A QM exe also embeds copies of the standard-library
functions the macro calls (items of `System.qml`, e.g. `ShutDownProcess`). They are not part of your script: the macro
resolves them from `System.qml` when it is compiled, so importing them as items is unnecessary. With `QM_SYSTEM_QML` set,
these functions are left out by default and a `; Omitted ...` line lists them; `--with-library` writes them as well.
Without `QM_SYSTEM_QML` they cannot be told apart from your own functions, so everything is written.

Note on compiling: QM compiles one item per text, and `function` must be the first code line of an item (only comments
may precede it). A file holding several functions therefore compiles only if each extra function is a `#sub name` section
or is created as its own QM item.

## Round trip

1. `python make_roundtrip.py` decompiles every sample exe of the corpus in `--roundtrip` mode (every local declared at the
   function head in descriptor order, label lines, `dll` declarations inferred from the calls) into `roundtrip/*.qml`.
   Samples whose source needs information that is not stored in the exe (user `type` declarations) are reported as
   `NOT ROUNDTRIPPABLE`.
2. Compile each `.qml` with your own QM (Make Exe) into a folder, e.g. `roundtrip/`.
3. `python compare_roundtrip.py --all roundtrip/` compares each new exe with the original and prints two verdicts:
   **LEVEL A** (semantic): `SEMANTICALLY IDENTICAL` = same decoded statements, local table, thread variables and
   resources; **LEVEL B** (binary layout): may differ only by string-pool order, section pointers and function ids.
   Final result: 33 of 33 round-trippable samples are SEMANTICALLY IDENTICAL (LEVEL A); sample30 and sample33 are not
   round-trippable (user `type` declarations are not stored in the exe).
   `python compare_roundtrip.py --selftest` validates the comparer (mutations must be detected, padding changes must not).

See [METHODOLOGY](docs/METHODOLOGY.md) for how to read the verdicts.

## Project layout

```
qmtool.py           extractor: PE resource 252 -> res*.bin, key check, res8/9/10 parsers
qmdis.py            block/stream locator and legacy disassembler
qmlayout.py         layout decoder (the tested byte-layout model)
handler_layout.py   derives layouts from runtime handler code (research; needs capstone)
runtime_tables.py   rebuilds the run-time dispatch tables (research; needs capstone)
qmdec.py            decompiler
tile_check.py       falsifiable layout test (tiling)
audit_level1.py     container + layout audit, baseline handling
test_qmdec_syntax.py, threshold_sweep.py, res4diff.py
make_roundtrip.py, compare_roundtrip.py
qmcorpus.py         corpus discovery shared by all tools
analysis/           opcode semantics, layout tables, builtin ids, runtime tables (facts about the QM runtime)
samples/            QM source samples to compile yourself (no exes)
docs/               FORMAT, OPCODES, METHODOLOGY, LIMITATIONS, STATUS, CONTRIBUTING, research log
agents/             optional AI-assistant role definitions used during the research
tools/              check_publish.py (publish guard), gen_opcodes.py (renders docs/OPCODES.md)
.github/            issue template for unknown-opcode / decode-failure reports
```

## Status and limitations

Container extraction, the layout model and the decompiler work for every construct in the sample corpus; some opcodes are only
read from the runtime's code and not yet seen in an exe, and many names (locals, parameters, globals, types, labels) are not stored
in a QM exe at all. See [STATUS](docs/STATUS.md) and [LIMITATIONS](docs/LIMITATIONS.md).

## Contributing

The most useful contribution is a new sample `.qml` with a known source. Read [CONTRIBUTING](docs/CONTRIBUTING.md). Report an
unknown opcode or a decode failure with the issue template (attach the `.qml`, **never the exe**). Run
`python tools/check_publish.py` before you push.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Quick Macros 2 decompiler contributors.
>>>>>>> master
