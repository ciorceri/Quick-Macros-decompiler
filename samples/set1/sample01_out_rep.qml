; sample01 - basic output, F-strings, rep loop, wait
; Tests: out, out F"...", str concat, rep, continue, wait 1s
;
; Expected behavior when run: prints loop messages forever, 1 s apart.
; Compile as: sample01

int loopCount=0

rep
	out "Start new loop of processing"
	loopCount+1
	out F"The loop count is {loopCount}"
	int nLines=42
	out F"The number of lines of text in the window is {nLines}"
	out F"The number of matching lines is {nLines}"
	1
 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample01_out_rep.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {B19BD10C-AFAD-46E3-AA96-A06DF852127B}
 END PROJECT
