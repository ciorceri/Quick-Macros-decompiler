; sample20_spe - spe autodelay (opcode 0xda): set, default, inherit, get
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: low - syntax taken from the QM help (Commands\IDP_*.html). If a line
; fails, comment it with ;;FAILED and tell me the error text.

spe 10
out 1
spe
out 1
spe -1
out 1
spe -2
out 1
int sp=spe
out sp
sp=spe(-1)
out sp
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample20_spe.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {8BBD3E2A-F525-406D-8EE4-4FC5064A6E66}
 END PROJECT
