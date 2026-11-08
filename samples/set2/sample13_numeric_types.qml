; sample13 - numeric types
; Purpose: byte, word, long (64-bit), double, int conversions and mixed use.
; Risk: low-medium

byte by=200
word wo=60000
int i=100000
long l=1
double d
l=l<<40
out l
by+10
out by
wo+10
out wo
i=by
out i
i=wo
out i
l=i
out l
d=l
out d
d=i
out d
i=d
out i
l=l*3
l=l/7
out l
l=l%1000
out l
if(l>i) out "l>i"
if(by<wo) out "by<wo"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample13_numeric_types.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {58E02CB1-6F6D-41A6-B3D3-466F74E966BF}
 END PROJECT
