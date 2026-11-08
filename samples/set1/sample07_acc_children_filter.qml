; sample07 - Acc find with filter string (value+state filter strings)
; Tests: acc find filter syntax value=*...* and state=... masks
;
; Expected behavior when run: if ExampleApp is open, finds list TEXT
; rows matching a tag. Safe - only reads.
;
; NOTE: this is the construct we are least sure about - the exact QM API
; form for the filter string is inferred from extracted strings
; ("value=*ALPHA7*", "state=0x100000 0x20000040"). If this fails to
; compile, that is the key finding.

str appTitle="ExampleApp   v1.0"
str appClass="ExampleWndClass"
str myTag="ALPHA7"

int w=win(appTitle appClass)
if(!w)
	out "ExampleApp window not found"
else
	Acc a
	a.Find(w "TEXT" "" "value=*ALPHA7* state=0x100000 0x20000040" 0)
	if(a.a)
		out F"found matching row, value={a.Value}"
	else out "no matching list row"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample07_acc_children_filter.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {6D429767-3FCB-4812-9ECC-1E608C402E0D}
 END PROJECT
