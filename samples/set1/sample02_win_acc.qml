; sample02 - window find + accessibility setup
; Tests: win(title class), Acc root.FromWindow(w), GetChildObjects, State masks
;
; Expected behavior when run: finds ExampleApp (or any window) and prints the
; count of TEXT objects. Safe - only reads.

str appTitle="ExampleApp   v1.0" ;;exact title incl. 3 spaces
str appClass="ExampleWndClass"

int w=win(appTitle appClass)
if(!w)
	out "ExampleApp window not found"
	ret
out "ExampleApp window found"

Acc root.FromWindow(w)
ARRAY(Acc) all
root.GetChildObjects(all -1 "TEXT")
out F"TEXT objects found: {all.len}"

int i
for i 0 all.len
	int st=all[i].State
	if((st&0x100000) and (st&0x200000)) out "row %i state=0x%X" i st
 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample02_win_acc.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {21C661E8-0D88-4010-BF0A-C02F9C5BB5F3}
 END PROJECT
