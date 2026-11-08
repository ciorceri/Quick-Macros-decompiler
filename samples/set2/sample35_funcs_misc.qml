; sample35_funcs_misc - childtest/acctest/wintest, findcr/findcs/findcn, ren, htm, inpp, scan
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: HIGH - several functions need windows/objects; only compiled, never run. Targets table-1 opcodes never seen so far (analysis/unseen_opcodes.json; names there are inferred).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. QM's error offset /NNN = start of the failing line.

int w=win("Notepad")
int c=child("Edit" "Edit" w)
int ok=childtest(c "Edit" "Edit")
str s="a:b/c d"
int n
n=findcr(s ':')
n=findcr(s "/")
n=findcs(s ":/" 1)
n=findcs(s ":/")
n=findcn(s " ")
n=findcn(s ":/ ")
ren "c:\a.txt" "c:\b.txt"
ren* "c:\a.txt" "b.txt"
Acc a=acc("OK" "PUSHBUTTON" w)
int at=acctest(a "OK")
IDispatch h=htm("A" "x")
inpp "pw" "text" "caption"
int rp=inpp("pw" "text")
n=scan("c:\x.bmp")
n=scan("c:\x.bmp" w)
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample35_funcs_misc.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {A441770D-C0CF-4D43-9D9B-A68C92D8F3E4}
 END PROJECT
