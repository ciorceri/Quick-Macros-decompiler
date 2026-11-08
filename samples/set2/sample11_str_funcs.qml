; sample11 - string methods and formatting
; Purpose: str methods, concatenation, comparison, format, F-strings.
; Risk: medium - method names from QM docs memory; comment out a line if
; it fails to compile and tell me which one.

str s="Hello World"
str t u
int n
s+" 2024"
out s
n=s.len
out n
t.left(s 5)
out t
t.right(s 4)
out t
t.get(s 6 5)
out t
u=s
u.ucase
out u
u.lcase
out u
u="  trim me  "
u.trim
out u
n=find(s "World")
out n
n=find(s "zzz")
out n
if(s="Hello World 2024") out "equal"
if(s!="x") out "notequal"
t.from(s "!")
out t
t.format("%i-%s" 42 "x")
out t
out F"n={n} s={s}"
out "%s has %i chars" s s.len
t=""
t.addline("one")
t.addline("two")
out t

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample11_str_funcs.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {160E0038-10AE-4A01-BC1B-CE4223CB9B8D}
 END PROJECT
