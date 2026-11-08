; sample22_flow_misc - end/err/atend/ret/foreach/ifa/iff/ifk/tim/bee (opcodes 0x9a 0x88 0x99 0xd9 0x3a 0x37 selectors)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium. Syntax from QM help (Flow/Commands/Functions IDP_*.html).
; If a line fails, comment it ;;FAILED and put the error text in <name>.error.

int n=1
int h
if(n=2) end
if(n=3) end "text"
if(n=4) end "warn" 8
if(n=5) end F"n={n}" 1
out 1
err
	out "e1"
out 2
err+
	out "e2"
err-
out 3
atend sub.Cleanup
out 4
str s="a[]b[]c"
str e
foreach e s
	out e
foreach e "x[]y"
	out e
int i
for i 0 3
	out i
rep 3
	out i
if(n=6) ret
out 5
if(n=7) goto done
out 6
 done
out 7

out "end"

#sub Cleanup
out "cleanup"


 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample22_flow_misc.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {5825610F-FE46-4539-B5D4-123D790D8D43}
 END PROJECT
