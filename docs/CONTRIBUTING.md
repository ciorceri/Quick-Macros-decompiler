# CONTRIBUTING

The project is evidence-first: the most valuable contribution is **a new sample whose source is known**.

## Ground rules

* Only analyse executables you own or have the right to analyse. **Never attach or upload an exe, a `.bin` resource
  dump, QM's `System.qml`, QM help files or any text copied from them.** Issues and pull requests containing those
  will be closed.
* Keep samples and examples generic: no personal names, e-mail addresses, machine or domain names, absolute paths,
  window titles or log files taken from real scripts.
* Run `python tools/check_publish.py` before every commit/PR; it must exit 0.
* A layout or semantic claim needs handler evidence and/or sample + tiling evidence (see `METHODOLOGY.md`). Label it
  `observed`, `inferred` or `handler-only`.

## Add a sample

1. Write a `.qml` that exercises one construct per line, so a compile error or an undecodable statement points at one
   construct. Name it `sampleNN_topic.qml` in `samples/set2/` (or a new `samples/setN/`) with a short comment header
   (purpose, risk, what it tests). Do not use real window titles or paths.
2. Compile it with your own QM (Make Exe). The tools never run the exe.
3. Put the exe in `./corpus` and run:

```
python tile_check.py            # tiling ok/bad/unresolved must be N/0/0
python audit_level1.py          # PASS; add --write-baseline if you intentionally enlarged the corpus
python qmdec.py corpus -o out   # decompile every exe
python test_qmdec_syntax.py out
```

4. If `out/<name>.qmdec.qml` does not match your source, or contains `TODO(evidence ...)`, you found a gap (see below).
5. Open a PR with the new `.qml` (never the exe), the JSON changes and the numbers you obtained.

## Report an unknown opcode / decode failure

Use the "Unknown opcode / decode failure" issue template. Provide:

* the `.qml` source (this is what lets us reproduce it) and the QM version
* the exact error text. The tools report problems in these forms:
  * `undocumented opcode 0xNN at code offset 0xOOOO (stream entry I)`: `NN` = opcode byte, `OOOO` = offset inside the
    function's code region (block base + 0x48), `I` = index in the statement stream
  * `tile_check.py`: `0xNN ok=.. bad=.. unres=..` and, with `--samples 3`, lines like `decoded <len> span <len> | <hex bytes>`
    (`bad`: the layout tiled to the wrong length) or `ERR <text>` (`unresolved`: the decoder could not finish)
  * `TODO(evidence): #<stmt> @<start>-<end> op 0xNN: <reason>; raw <hex>` lines in a `.qmdec.qml`
* the output of `python tile_check.py --op 0xNN --samples 3` and of `python audit_level1.py`

All offsets are hexadecimal and relative to the function block's code base.

## Extend the model

* Layout fixes: record the evidence in a new `analysis/layout_overrides_group<X>.json` and apply the same entry to
  `analysis/layout_final.json`, which is the table the tools read (see `analysis/README.md`). Always include before/after tiling numbers.
* Semantics go into `analysis/opcode_semantics.json` (name, operands, qm_construct, evidence, confidence). Then run
  `python tools/gen_opcodes.py` to refresh `docs/OPCODES.md`.
* Decompiler changes must keep the output valid QM (`;;` notes, `;` comment lines); `test_qmdec_syntax.py` must pass.

## Style

Python 3.10+, standard library plus `pefile` and `capstone`. Tools run from the repository root with no required
arguments beyond an optional `--corpus`.
