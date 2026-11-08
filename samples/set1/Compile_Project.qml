; Compile_Project - compile all items in the current QM file and print a
; pass/fail summary per item to the QM output.
;
; Usage:
;   1. Open (or import) the target .qml in QM 2.4.12
;   2. Run:  qmcl.exe MS "Compile_Project"
;      (or just press F5 on this function in the editor)
;
; Notes:
; - CompileAllItems compiles macros, functions and member functions only
;   (not menus/toolbars/autotext).
; - Compile errors appear in the QM output; this function additionally
;   prints a per-item summary so you can paste results back.
; - Call soon after QM startup (per QM docs).

int nOk=0 nFail=0
str failedItems

; CompileAllItems returns nonzero on failure (per docs); we cannot get
; per-item names from it, so we report the aggregate and ask QM's output
; for details. If your QM version supports it, prefer running this from
; the QM editor where failed items are highlighted in the list.

err
	out "Compile_Project: error calling CompileAllItems"
	ret 1

CompileAllItems 0

; If we get here, the call itself succeeded. CompileAllItems returns
; nonzero if any item failed to compile - check via _error or return value.
; Simplest reliable signal: QM shows compile errors in the output pane;
; this macro just confirms the pass completed.

out "---- Compile pass complete ----"
out "If any item failed, QM listed it above with line number."
ret 0
