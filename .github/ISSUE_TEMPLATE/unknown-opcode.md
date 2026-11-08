---
name: Unknown opcode / decode failure
about: qmdec / tile_check / audit_level1 reported an unknown opcode, a TODO(evidence) line, a tiling failure or a wrong decompilation
title: "[decode] "
labels: decode-failure
---

**Do NOT attach any executable, resource dump (`*.bin`), QM `System.qml`, or QM help files.** Attach the `.qml` source only.

## QM version
(e.g. 2.4.12; Help > About in Quick Macros)

## Source
Paste or attach the `.qml` that produces the problem (reduce it to the smallest program that still fails; no personal data, paths or window titles).

```
```

## Error text
Exact output of the tool, e.g. `undocumented opcode 0x.. at code offset 0x.... (stream entry ..)`, a `tile_check.py` line `0x.. ok=.. bad=.. unres=..`, or the `TODO(evidence): ...` line from the `.qmdec.qml`.

```
```

## Commands run
- [ ] `python tile_check.py --op 0x.. --samples 3`
- [ ] `python audit_level1.py`
- [ ] `python qmdec.py <exe>` (paste only the relevant lines)

## What you expected
The statement from the source that is decoded wrongly or not at all.

## Tool versions
Python version, `pefile` and `capstone` versions, OS.
