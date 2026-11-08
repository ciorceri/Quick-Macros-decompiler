; sample09 - double arithmetic, int<->double mixing, comparisons
; Purpose: exercise the double (type byte) operator family.
; Risk: low

double d=3.5
double e=1.25
double r
int i=7

r=d+e
out r
r=d-e
out r
r=d*e
out r
r=d/e
out r
r=d+i
out r
r=i*e
out r
r=-d
out r
i=d
out i
r=i
out r
if(d>e) out "d>e"
if(d<e) out "d<e"
if(d>=3.5) out "d>=3.5"
if(d<=e) out "d<=e"
if(d=3.5) out "d==3.5"
if(d!=e) out "d!=e"
d+0.5
d*2
out d
out "%f %f" d e

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample09_double_ops.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {3161997C-B7FC-4717-B969-BA2F7C23057C}
 END PROJECT
