; sample24_builtin_funcs - builtin function calls to map 0x49 ids (5, 6, 221, 224, 225, 503, 523)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium - one call per line, assigned to a variable. Syntax from QM help (Flow/Commands/Functions IDP_*.html).
; If a line fails, comment it ;;FAILED and put the error text in <name>.error.

int a b
str s="one two"
str t u
a=win("Notepad")
b=child("Edit" "" a)
b=id(15 a)
a=empty(s)
a=len(s)
a=find(s "two")
a=findb(s "o")
a=findc(s "o")
a=findl(s 1)
a=findrx(s "t.o")
a=findt(s 1)
a=findw(s "two")
a=matchw(s "one*")
a=numlines(s)
a=val("123")
a=iif(a>0 1 2)
a=sizeof(int)
ARRAY(str) ta
a=tok(s ta)
a=perf
a=pixel(1 1)
a=ProcessNameToId("notepad.exe")
str d=dir("c:\*.*")
;;DROPPED: scan needs an image argument (IDP_SCAN)
out a
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample24_builtin_funcs.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {2BD1F040-44D8-4071-AFF0-CA4E82FE6AC5}
 END PROJECT
