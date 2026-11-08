; sample04 - wait for window/dialog
; Tests: wait(0 WV win(title class)), return value
;
; Expected behavior when run: waits for the ExampleApp "Log Entry" dialog
; forever; prints when it appears. Safe - only waits.

str logDialogTitle="ExampleApp   v1.0 - Log Entry"
str appClass="ExampleWndClass"

rep
	int dlg=wait(0 WV win(logDialogTitle appClass))
	if(!dlg) continue
	out "Log Entry dialog appeared"
	1

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample04_wait_dialog.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {EAD2B029-D0B5-4D9A-AD2A-1DF4BD7A9D45}
 END PROJECT
