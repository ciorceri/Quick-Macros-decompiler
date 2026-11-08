; sample26_stdlib_calls - user-function and stdlib calls (opcode 0x01 call by id, sub-function)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: HIGH - stdlib functions may not exist in 2.4.12; comment failing lines. Syntax from QM help (Flow/Commands/Functions IDP_*.html).
; If a line fails, comment it ;;FAILED and put the error text in <name>.error.

int pid
pid=ProcessNameToId("notepad.exe")
ShutDownProcess "notepad.exe"
;;FAILED: Softly - unknown identifier (not in 2.4.12 stdlib)
str s="x"
s.getwintext(win())
s.getclip
s.setclip
sub.Sub1 5
int r=sub.Sub2(3)
out r

out "end"

#sub Sub1
function a
out a

#sub Sub2
function a
ret a*2


 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample26_stdlib_calls.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {2C24FF77-3792-4F22-824B-C1DA03884943}
 END PROJECT
