; sample19_opt - opt options (opcode 0xc8): one option per line, out 1 as separator
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: low - syntax taken from the QM help (Commands\IDP_*.html). If a line
; fails, comment it with ;;FAILED and tell me the error text.

opt hidden 1
out 1
opt clip 1
out 1
opt err 1
out 1
opt waitmsg 1
out 1
opt waitmsg 2
out 1
opt waitcpu 1
out 1
opt slowmouse 1
out 1
opt hidden -1
out 1
opt hidden
out 1
opt save
out 1
opt restore
out 1
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample19_opt.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {46D99D75-CDF3-4BE7-967C-73694A21B84F}
 END PROJECT
