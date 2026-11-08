; sample03 - Acc find + DoDefaultAction (button/checkbox click)
; Tests: Acc x.Find(w role name "" 0), x.a, x.State, x.DoDefaultAction
;
; Expected behavior when run: if ExampleApp is open, finds the Option A
; checkbox and prints its state. Only clicks if it is unchecked - safe.

str appTitle="ExampleApp   v1.0"
str appClass="ExampleWndClass"

int w=win(appTitle appClass)
if(!w)
	out "ExampleApp window not found"
	ret

Acc cb
cb.Find(w "CHECKBUTTON" "Option A" "" 0)
if(cb.a)
	int st=cb.State
	out "Option A found, state=0x%X" st
	if(!(st&0x10)) ;;0x10 = STATE_SYSTEM_CHECKED
		out "Option A is unchecked - would click it"
		;;cb.DoDefaultAction ;;uncomment to actually click
else out "Option A checkbox not found"
 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample03_acc_find_click.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {90D157CA-9520-41F6-8312-7F907B630F74}
 END PROJECT
