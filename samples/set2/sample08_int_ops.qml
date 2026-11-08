; sample08 - integer operators and comparisons
; Purpose: exercise the binary-operator table (table 2) and unary ops.
; Safe: only does arithmetic and prints. DO NOT need to run it.
; Risk: low

int a=17
int b=5
int r

r=a+b
out r
r=a-b
out r
r=a*b
out r
r=a/b
out r
r=a%b
out r
r=a&b
out r
r=a|b
out r
r=a^b
out r
r=a<<2
out r
r=a>>1
out r
r=~a
out r
r=-a
out r
r=!a
out r
r=(a<b)
out r
r=(a<=b)
out r
r=(a>b)
out r
r=(a>=b)
out r
r=(a=b)
out r
r=(a!=b)
out r
r=a>b and a<100
out r
r=a<b or a>10
out r
a+1
a-2
a*3
out a

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample08_int_ops.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {541ACC9B-1950-459F-8848-3535639F53E9}
 END PROJECT
