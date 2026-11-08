; sample15 - sel/case and goto
; Purpose: switch-like sel statement, goto + label.
; Risk: HIGH - exact sel/case and label syntax is from memory. If a line
; fails, tell me the error text; comment the failing block and recompile.

int x=3
sel x
	case 1
	out "one"
	case 2
	out "two"
	case 3
	out "three"
	case else
	out "other"

int n=0
 lab1
n+1
if(n<5) goto lab1
out n

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample15_sel_goto.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {EDBC58CE-8630-448D-957E-92080A6CC1D5}
 END PROJECT
