; sample32_control_flow - loop and branch variants: nested loops, break/continue in each loop kind, sel with strings/ranges/flags, else-if chains, rep with count, for with step, ifa/iff/ifk else, goto/labels, ret in loops, end with codes
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium. Syntax from QM help (Language/Functions/Flow IDP_*.html).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. QM's error offset /NNN = start of the failing line.

int i j n
for i 0 5
	for j 0 5
		if(j=2) continue
		if(j=4) break
		n+j
	if(i=3) break
for i 10 0 -2
	n+i
for i 0 10 3
	n+i
rep 4
	n+1
	if(n>100) break
	if(n=7) continue
rep
	n+1
	if(n>20) break
str s="a[]b[]c"
str e
foreach e s
	if(e="b") continue
	if(e="c") break
	out e
sel n
	case 1 out "one"
	case [2,5] out "list"
	case 7 out "seven"
	case else out "other"
sel s
	case "a" out "A"
	case "b" out "B"
	case else out "?"
sel s 3
	case "A*" out "wild"
	case else out "no"
if(n=1)
	out 1
else if(n=2)
	out 2
else if(n=3)
	out 3
else
	out 4
if(n>0 and n<10) out "and"
if(n=1 or n=2) out "or"
if(!n) out "not"
if(n=1 or (n>2 and n<5)) out "mix"
ifa "Notepad"
	out "a"
else
	out "b"
iff "c:\a.txt"
	out "f"
else
	out "g"
ifk F2
	out "k"
else
	out "l"
goto top
 top
n=n+1
if(n<30) goto top
n=iif(n>5 n 0)
n=iif(n<3 iif(n=1 5 6) 7)
out n

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample32_control_flow.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {CA58204D-C763-4E98-A330-8DE62FF4829E}
 END PROJECT
