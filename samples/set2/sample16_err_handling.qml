; sample16 - error handling
; Purpose: err-handling statements (err+ / err-, err with block).
; Risk: HIGH - syntax from memory.

err+
int x=5
x/0
err-
out "after err- block"
err
	out "error handler"
int y=10
out y

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample16_err_handling.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {1529135C-38FE-4CE8-9C9F-DDB368FB8CBD}
 END PROJECT
