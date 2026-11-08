; sample05 - process check + launch
; Tests: ProcessNameToId(name), run path
;
; Expected behavior when run: prints whether notepad is running; launches
; it if not. Harmless test process.

str testExeName="notepad.exe"

int pid=ProcessNameToId(testExeName)
if(pid=0)
	out "not running - would launch"
	;;run "C:\\Windows\\System32\\notepad.exe" ;;uncomment to actually launch
else out F"running, pid={pid}"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample05_process_run.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {3A8B7611-FE93-4D83-8BA3-007AACE7EF08}
 END PROJECT
