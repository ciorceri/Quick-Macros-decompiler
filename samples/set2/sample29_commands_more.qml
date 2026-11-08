; sample29_commands_more - commands/functions not yet seen: web, zip, net, shutdown, run forms, ont, min/max/res as functions, inp, rget/rset, uuidof, qmitem, call, xm/ym, ifa/iff/ifk, deb, wait kinds
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: HIGH - many forms; comment failing lines. Syntax from QM help (Commands/Flow/Functions/str/Language IDP_*.html).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. Keep one construct per line.

int w=win("Notepad")
int a b
str s
ont w
ont- w
a=ont(w)
a=min(w)
a=max(w)
a=res(w)
a=xm(0 w)
a=ym(0 w)
ifa w
	out 1
ifa- w
	out 2
iff "c:.txt"
	out 3
iff- "c:.txt"
	out 4
ifk F2
	out 5
ifk- (1)
	out 6
run "notepad.exe"
run "notepad.exe" "c:.txt"
run "notepad.exe" "" "" "c:	emp"
run "c:.txt" "" "print"
a=run("notepad.exe")
web "http://www.example.com"
web "Back"
zip "c:.zip" "c:.txt"
zip- "c:.zip" "c:\out"
int v=5
a=rget(v "name" "Software\QMTest")
a=rset(v "name" "Software\QMTest")
a=inp(v "text" "caption")
a=qmitem("Macro1")
a=net("127.0.0.1" "pw" "Macro1")
shutdown 0
shutdown 5
mes "Q" "cap" "YN"
mes F"v={v}"
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample29_commands_more.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {F4283FD1-02C3-435C-A4C5-2C81DF13399E}
 END PROJECT
