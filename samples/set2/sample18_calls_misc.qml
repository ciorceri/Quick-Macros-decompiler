; sample18 - misc stdlib/builtin calls and statements
; Purpose: process functions, sleep-style waits, clipboard, mac call, ret value.
; Risk: low-medium. DO NOT RUN.

int pid=ProcessNameToId("notepad.exe")
out pid
int h=win
out h
str s="abc"
str t
t=s
t+"def"
out t
int i
for i 1 3
	0.25
out "done"
ret 5

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample18_calls_misc.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {D7F0DC0D-526C-4457-BB99-714FD3921680}
 END PROJECT
