# Sample sources

These `.qml` files are small Quick Macros (QM) programs written for this project. Each one exercises a
handful of language constructs so that the compiled executable gives the decoder bytecode whose source is
known. They are the "ground truth" behind every `observed` entry in `docs/OPCODES.md`.

No compiled executable is shipped: an exe embeds the proprietary QM runtime. You build the exes yourself
with your own legal copy of Quick Macros (the project is not affiliated with, and contains nothing from, QM).

| folder | files | QM version used by the author |
|---|---|---|
| `set1/` | `sample01` .. `sample07` (output, windows, accessible objects, waits, strings), `Compile_Project.qml` helper | 2.4.12 |
| `set2/` | `sample08` .. `sample35` (operators, flow, types, arrays, COM objects, functions, scopes ...) and `sample36`/`sample37` (constructs QM refuses to compile into an exe; no exe expected) | 2.4.12 |

## Build the corpus

1. Install Quick Macros 2 (the samples were written against 2.4.12; other 2.4.x builds should work).
2. For every `sampleNN_*.qml` (except `sample36`/`sample37`): import it into QM as a macro, compile it
   (Ctrl+F8 compile check) and use **Make Exe**. The `BEGIN PROJECT` trailer of each file already names the output
   file as `$desktop$\corpus\<name>.exe`; any output folder is fine.
3. Copy the resulting `.exe` files into `./corpus` (create it; it is git-ignored). Sub-folders are allowed:
   the tools search the corpus recursively for `*.exe`.
4. Do **not** run the samples that act on windows or processes (`sample14`, `sample18`, and the sample03 / sample05
   action lines are commented out on purpose). The tools never execute an exe; they only read it.
5. If a sample does not compile in your QM version, comment out the failing line, recompile, and note it
   in an issue: a partial sample is still useful.

Then follow the quick start in the top-level `README.md` (`tile_check.py`, `audit_level1.py`, `qmdec.py`).

## Adding your own samples

See `docs/CONTRIBUTING.md`. Keep one construct per line so a compile error or an undecodable statement points
at exactly one construct, and keep the content generic (no personal names, paths, window titles or log files).

## Sample index

| # | file | what it exercises |
|---|---|---|
| 01 | `sample01_out_rep` | `out`, F-strings, `rep`, `continue`, bare `1` (wait 1 s) |
| 02 | `sample02_win_acc` | `win(title class)`, `Acc` root from window, `GetChildObjects`, state masks |
| 03 | `sample03_acc_find_click` | `Acc.Find`, `.a`, `.State`, `DoDefaultAction` |
| 04 | `sample04_wait_dialog` | `wait(0 WV win(title class))` |
| 05 | `sample05_process_run` | `ProcessNameToId`, `run` |
| 06 | `sample06_string_ops` | `find`, string building, F-strings |
| 07 | `sample07_acc_children_filter` | `Acc.Find` with a filter string (`value=*..* state=..`) |
| 08 | `sample08_int_ops` | all int operators, comparisons, `and`/`or`, unary ops, read-modify-write |
| 09 | `sample09_double_ops` | double arithmetic, int/double mixing |
| 10 | `sample10_loops_flow` | `for` (step, negative, nested), `rep N`, `break`/`continue`, nested `if`/`else`, `ret` |
| 11 | `sample11_str_funcs` | str methods, `find`, F-strings |
| 12 | `sample12_arrays_types` | ARRAY (int/str, 2D, create/redim/remove/sort), POINT, RECT |
| 13 | `sample13_numeric_types` | byte/word/int/long/double conversions |
| 14 | `sample14_window_funcs` | `win`, `act`/`max`/`min`/`res`/`clo`, `key`, `mou`, `mes`, clipboard (do not run) |
| 15 | `sample15_sel_goto` | `sel`/`case`, `goto` + label |
| 16 | `sample16_err_handling` | `err+` / `err-` / `err` |
| 17 | `sample17_com_objects` | CreateXml / CreateStringMap / CreateCsv |
| 18 | `sample18_calls_misc` | process functions, waits, string append, `ret 5` (do not run) |
| 19-35 | `sample19_opt` ... `sample35_funcs_misc` | `opt`, `spe`, `key`, flow misc, wait kinds, builtin functions, commands, stdlib calls, operand order, string methods, types and pointers, functions and parameters, control flow, objects, scopes and variants |
| 36-37 | `sample36_noexe_deb`, `sample37_noexe_newitem` | commands that QM refuses to compile into an exe (no exe is produced) |

`set1/Compile_Project.qml` is a helper macro that calls `CompileAllItems` and prints a summary; it is optional.

## Note on sample01-sample07

These seven sources were sanitised for publication (window titles, class names and strings replaced by neutral
placeholders such as `ExampleApp`). The tools do not depend on the string contents, but an exe you build
from these sources will have a different string pool than any exe built from earlier private versions of the same
samples. Always regenerate `baseline.json` (see README) for your own corpus.
