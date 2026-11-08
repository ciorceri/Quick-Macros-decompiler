# Building an exe from a decompiled script

How to turn the output of `qmdec.py` back into a working exe with Quick Macros 2 (QM). Verified with QM 2.4.12: a
decompiled macro compiled and built an exe.

## Why the `.qml` cannot be opened in QM

The decompiler writes plain text. QM's own `.qml` files are SQLite databases (since QM 2.4.0), and `File > Open` refuses
anything else with "Cannot open file ... Not a QM file". This is true of every text `.qml` in this repository, so the
text has to be pasted into a QM item.

## Steps

1. Decompile the exe. Set `QM_SYSTEM_QML` to your QM `System.qml` first; then the copies of QM's own library functions
   (`ShutDownProcess`, `GetWinStyle`, ...) are left out:

   ```
   set QM_SYSTEM_QML=C:\Program Files (x86)\Quick Macros 2\System.qml
   python qmdec.py program.exe -o program.qml
   ```

2. Open `program.qml` in a text editor and copy everything. The first lines are `;` comments; they are valid QM comments.
3. In QM create a new **macro** (a new item of type Macro) and paste the text. Give the macro the name
   that appears in the `; ---- function <name> ...` line near the top.
4. Compile it (Ctrl+F8, as in `samples/README.md`) and fix any error QM reports. Then run Run > Make Exe: set *Main* to the
   macro and *Make* to the folder and file name you want for the exe (for example the same folder as the source), then OK.
5. Run the exe only when you know what the script does.

## What goes into which QM item

* **Main macro and its `#sub` sections** (`#sub Name`, called as `sub.Name`): one macro item. Everything the decompiler
  writes below the first `; ---- function` line belongs to it.
* **Library functions** that Make Exe embedded (items of `System.qml`): do not create them. The macro resolves them from
  `System.qml`. `--with-library` writes them anyway; if you need them (for example without `QM_SYSTEM_QML`, when they
  cannot be told apart from your own functions), create each as a separate **function** item with exactly that name, or
  append it to the macro as a `#sub`.
* **Your own functions** called by the macro (items that are not in `System.qml`) are separate QM functions: create one
  function item per `; ---- function <name>` section, named exactly like the section.

QM compiles one item at a time and `function` must be the first code line of an item; only comments may precede it. That
is why a text that holds several functions is not valid as a single item (error: "the 'function' line must be the first
code line").

## Evidence notes

By default the output has no per-line notes. `--annotate` adds `;;inferred: ...` notes after each statement; they are
QM comments and do not change the compiled code. `TODO(evidence ...)` marks a statement that could not be decoded and must
be written by hand.
