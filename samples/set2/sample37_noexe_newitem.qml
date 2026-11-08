; sample37_noexe_newitem - newitem - help says not available in exe
; DO NOT RUN the exe; compile only. EXPECTED TO FAIL to compile (help: not available in exe).
; Put the error text in <name>.error. One command per file so one error cannot hide another.

;;int r=newitem("x" "text" "Macro")
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample37_noexe_newitem.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {F4FD4D53-3BEC-481D-A1A9-68907BFF5991}
 END PROJECT
