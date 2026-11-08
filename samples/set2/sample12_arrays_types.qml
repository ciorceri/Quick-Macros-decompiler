; sample12 - arrays and built-in structure types
; Purpose: ARRAY(int)/ARRAY(str), 2D array, create/redim/len/remove/sort,
;          POINT / RECT members.
; Risk: medium

ARRAY(int) a
ARRAY(str) b
ARRAY(int) c
int i
a.create(5)
for i 0 a.len
	a[i]=i*i
for i 0 a.len
	out a[i]
a.redim(8)
out a.len
a.remove(0)
out a.len
a.sort
b.create(3)
b[0]="x"
b[1]="y"
b[2]="z"
for i 0 b.len
	out b[i]
c.create(3 4)
c[1 2]=99
out c[1 2]
POINT p
p.x=10
p.y=20
out "%i %i" p.x p.y
RECT r
r.left=1
r.top=2
r.right=30
r.bottom=40
out r.right-r.left

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample12_arrays_types.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {4165757F-0B9A-43A4-B3FE-E27F6D3BCC00}
 END PROJECT
