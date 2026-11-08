; sample30_types_pointers - intrinsic types, pointers, int64, rmw ops, arrays, user types (never-seen load/store/rmw opcodes 0x16 0x17 0x18 0x1a 0x1d 0x22 0x23 0x2e)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium. Syntax from QM help (Commands/Flow/Functions/str/Language IDP_*.html).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. Keep one construct per line.

int i=5
int* p=&i
int a=*p
*p=10
long L=1234567890123
long M=L+1
L+1
L*2
L-3
L<<2
L>>1
L&255
L|1
L^7
word w=65535
byte b=200
w+1
b+1
double d=1.5
d*2
double* dp=&d
double dd=*dp
long* lp=&L
long LL=*lp
*lp=99
type MYT int'a double'b str's byte'c[4]
MYT t
t.a=1
t.b=2.5
t.s="str"
t.c[1]=7
MYT* tp=&t
tp.a=5
int k=tp.a
ARRAY(int) ai
ai.create(3)
ai[0]=1
ai[1]=ai[0]+1
ARRAY(long) al
al.create(2)
al[1]=5000000000
str* sp=&t.s
out *sp
lpstr ls="abc"
out ls
int h=0x7fffffff
h+1
int u=-5
u=-u
u=~u
u=!u
int sh=1<<4
sh=sh>>2
sh=sh%3
sh=sh&1
sh=sh|2
sh=sh^3
double dv=10.0/4
dv=dv-1
out dv
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample30_types_pointers.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {89C9D6A4-E27B-44C2-809F-7AA6F5190538}
 END PROJECT
