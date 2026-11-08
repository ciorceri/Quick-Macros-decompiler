; sample36_noexe_deb - deb (debug mode) - help says not available in exe
; DO NOT RUN the exe; compile only. EXPECTED TO FAIL to compile (help: not available in exe).
; Put the error text in <name>.error. One command per file so one error cannot hide another.

;;deb
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample36_noexe_deb.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {31B88E4C-BD22-44F5-9198-118300DBE60E}
 END PROJECT
