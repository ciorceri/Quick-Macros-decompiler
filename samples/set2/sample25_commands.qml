; sample25_commands - assorted commands (windows, mouse, files, timers, sound)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium - many commands, one per line. Syntax from QM help (Flow/Commands/Functions IDP_*.html).
; If a line fails, comment it ;;FAILED and put the error text in <name>.error.

int w=win("Notepad")
bee
bee 1
bee 440 100
tim 5
tim 0
hid w
hid- w
;;FAILED: dis w  (dis not available in exe, IDP_DIS)
siz 300 200 w
mov 10 10 w
men "File" w
but "OK" w
lef 10 10 w
rig 10 10 w
mid 10 10 w
dou 10 10 w
paste "text"
outp "text"
mkdir "c:\temp\qmtest"
del "c:\temp\qmtest\x.txt"
cop "c:\a.txt" "c:\b.txt"
mac "Other"
lock
lock-
out 1
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample25_commands.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {2D7D0DE9-0265-4AD7-8BF9-16CB73628F12}
 END PROJECT
