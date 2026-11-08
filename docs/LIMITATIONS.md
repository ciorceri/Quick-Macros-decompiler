# LIMITATIONS

## Information that is not in the executable (cannot be recovered)

QM compiles a script to bytecode and discards most names. Searching res1-res10 (plain and decrypted) and the
whole file found none of:

* names of **local variables and parameters** (the decompiler prints `loc0`, `loc1`, ... by descriptor index)
* names of **global variables** (`int+ a`, `str+ s`): printed as `glob<id>` with the res10 record in a comment
* names of **user-defined types and their members** (`type_<id>`; the `type` declaration itself cannot be rebuilt)
* **labels** (`goto` targets)
* comments, blank lines, indentation, parentheses that do not change evaluation, number bases, and spelling
  variants that compile to the same bytes (`paste` vs `outp`; `opt hidden` vs `opt hidden 1`)

What *is* stored: function and `#sub` names (res3), **thread-variable names** (`int- t`, `int-- t`; they keep
their real names), string literals, the main macro name and item GUID (res1), DLL and builtin function names
(res8/res9).

Optional: if you own QM, set `QM_SYSTEM_QML` to your installation's `System.qml`; `qmdec.py` then borrows
parameter/local names for the embedded standard-library functions by strict alignment (equal count and types).
Those names are marked `/*name from System.qml (...)*/` and are inferred. Nothing from that file is shipped here.
It matches QM 2.4.12; for a 2.4.2 exe it is only a weak hint.
The same file is used to recognise the embedded library functions: by default they are omitted from the output (the macro
resolves them from `System.qml` when compiled), `--with-library` keeps them. Without it the built-in name list `library_names.py` (530 function names of QM 2.4.12's `System.qml`, names only) is used;
a user function with one of these names is omitted by mistake. `qmdec.py` lists every omitted function and the reason on
stderr; `--with-library` keeps them.

**Corner case: a user function with a library name.** An exe stores no marker that tells a copy of a `System.qml` function
from a function of your own file; the only evidence is the name. A user function named like a `System.qml` function (for
example `init`, `Replace`, `Outp`) is therefore omitted as if it were the library one, and the decompiled macro calls a
function that is missing from the output. The omitted names are printed on stderr, with the reason (found in
`QM_SYSTEM_QML` or in the built-in list `library_names.py`). If your own function is among them, decompile again with
`--with-library` and create that function in QM from the section the tool writes. The two cannot be distinguished
automatically, even with `QM_SYSTEM_QML`, unless the function body is compared with the `System.qml` text (not done).

## Commands that are rejected when compiling an exe

QM refuses to compile some commands into an exe ("cannot be used in exe"): `dis`, `deb`, `newitem` (and
`str.setmacro` per the help). They can never occur in a QM-built exe. The corresponding stub slots
(`0x94 0x97 0xc6 0xdd`) are a bare `ret` in both runtimes. `samples/set2/sample36_noexe_deb.qml` and
`sample37_noexe_newitem.qml` document this.

## Decompiler status labels

* no note: observed - bytes and known source agree.
* `;;inferred: ...`: plausible, backed by one occurrence, handler reading, or a standard-library correlation.
* `;` line with `TODO(evidence ...)`: not decoded; raw bytes are kept in the note and nothing is guessed.

The output is meant to be **read** and, where the round-trip check passes, recompiled; it is not guaranteed to
equal the original author's source text.

In `--roundtrip` mode, `dll` declarations are reconstructed: the exe stores only the function name and library, so
parameter kinds are inferred from the call arguments (or a small table of well-known Win32 signatures) and are marked
inferred, so they may not match the original source text. Round-trip output also declares every local at the function head, which is not where the original source did.

## Scope of the reference corpus

* Validated on QM **2.4.2** and **2.4.12** builds only. Other 2.4.x builds should share the format (the key and
  handler tables were identical in the two builds studied) but are untested; the audit reports a build that keeps
  the runtime key at an unknown RVA.
* Opcode and layout evidence exists only for constructs that samples exercise (see `OPCODES.md`; 36 valid
  table-1 opcodes are handler-only).
* `0x49` builtin names come from each exe's own res9, so unknown builtins still resolve by name; argument
  semantics of builtins seen only once are inferred.
* Embedded standard-library code in an exe (functions copied from QM's own library) is decoded with the same
  machinery; a few statements there can still be `TODO`.
* Static analysis only: nothing is executed and no run-time behaviour is observed.
