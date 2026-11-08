# Documentation index

| file | what it is |
|---|---|
| [FORMAT.md](FORMAT.md) | how a QM-built exe stores its script: resources res1-res11, the encryption key, the per-function block, the VM, dispatch tables, layout notation |
| [OPCODES.md](OPCODES.md) | every known opcode: layout, status (observed / inferred / handler-only), evidence. Generated from `analysis/opcode_semantics.json` |
| [METHODOLOGY.md](METHODOLOGY.md) | evidence rules and the checks (tiling, end-of-region, audit, round trip) |
| [LIMITATIONS.md](LIMITATIONS.md) | what is not stored in an exe, what is inferred, what QM refuses to compile |
| [BUILDING.md](BUILDING.md) | how to paste a decompiled script into QM and build an exe (QM cannot open the text `.qml` directly) |
| [STATUS.md](STATUS.md) | validated numbers and open items |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to add a sample, run the checks, and report an unknown opcode |
| [research-log.md](research-log.md) | technical history with evidence (redacted working notes) |

Start with the top-level `README.md`, then `FORMAT.md`.
