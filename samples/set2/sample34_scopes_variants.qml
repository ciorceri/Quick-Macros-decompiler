; sample34_scopes_variants - thread/global variables, parent variables in #sub with v attribute, win without args, pointer indexing, VARIANT conversions, str assign from number, call, getopt, ARRAY redim
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium - IDP_SCOPE, IDP_SUB, IDP_WIN, IDP_CALL, IDP_GETOPT. Targets table-1 opcodes never seen so far (analysis/unseen_opcodes.json; names there are inferred).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. QM's error offset /NNN = start of the failing line.

int- t_i=5
int- t_j
t_j=t_i+1
int-- t_k=2
out t_k
int+ g_a
int+ g_b=5
str+ g_s="x"
g_a=g_a+1
g_s+"y"
out g_a
int pv=3
int r=sub.UseParent(1)
out r
int w=win
out w
int i=7
int* p=&i
int k=p[0]
byte b=9
byte* pb=&b
k=pb[0]
word wd=3
word* pw=&wd
k=pw[0]
VARIANT v=5
int iv=v
double dv=v
int nv=!v
v=-v
v=~v
str s
s=5
out s
r=call(&sub.Foo 5)
r=call("Foo" 1)
lpstr gname=getopt(itemname)
r=getopt(speed)
r=getopt(nargs)
ARRAY(int) a
a.create(3)
a.redim(5)
out a.len
out "end"

#sub UseParent v
function# n
ret pv+n

#sub Foo
function# a
ret a

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample34_scopes_variants.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {BA236947-A74B-4E3F-9B86-958C148E8D27}
 END PROJECT
