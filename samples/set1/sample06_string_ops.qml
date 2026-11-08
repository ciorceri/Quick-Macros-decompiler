; sample06 - string operations used in the reconstructions
; Tests: str find(pattern), str comparisons, str building, find() function
;
; Expected behavior when run: prints match results. Safe.

str myTag="ALPHA7"
str pingPattern="  PING "
str latest="  PING BRAVO9 X1"

if(find(latest pingPattern)>=0)
	out "Latest string has PING so no need to analyse"
else
	out "no PING in latest"

str line1="1230  PING BRAVO9 X1"
str line2="1245  BRAVO9 ALPHA7 +5"
int nMatch=0
if(find(line1 myTag)>=0) nMatch+1
if(find(line2 myTag)>=0) nMatch+1
out F"The number of matching lines is {nMatch}"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample06_string_ops.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {F083F5FE-B5FA-4858-B6C7-597F6D468006}
 END PROJECT
