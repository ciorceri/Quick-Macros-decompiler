; sample14 - window / UI functions
; Purpose: win with no args (active window), act/max/min/res, mes, key,
;          mou, clipboard. DO NOT RUN - it would act on windows.
; Risk: medium

int w=win
int w2=win("Untitled - Notepad" "Notepad")
str s
if(w2)
	act w2
	max w2
	min w2
	res w2
	key Ah
	key Y
	key "hello"
	mou 100 200
	clo w2
s.getclip
out s
s="from macro"
s.setclip
mes "done"
0.5
2

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample14_window_funcs.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {65C8C3D1-B29D-40ED-A763-3DD16CA546E4}
 END PROJECT
