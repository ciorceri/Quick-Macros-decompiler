; sample23_wait_kinds - wait for forms (opcode 0x31 kinds, 0x30 wait)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium - window/handle events need only compile. Syntax from QM help (Flow/Commands/Functions IDP_*.html).
; If a line fails, comment it ;;FAILED and put the error text in <name>.error.

int h
wait 1
wait 0.5
wait -1
wait -2
wait 5 WA "Notepad"
wait 5 WC "Notepad"
wait 5 WD "Notepad"
wait 5 WP "Notepad"
h=wait(5 WA "Notepad")
int v
wait 5 V v
wait 5 K F12
;;FAILED: int vk=wait(5 KF)  (KF not available in exe, IDP_WAIT_FOR)
wait 5 M
wait 5 P 20
wait 5 ML
wait 5 H h
wait 5 -WA "Notepad"
out 1
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample23_wait_kinds.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {05F06D7F-19E2-4DBE-B841-4F5370FDF0FF}
 END PROJECT
