; sample31_functions_params - user functions via #sub: parameters (int, optional, lpstr, str&), return values, recursion, callbacks, atend with arg, dll declarations and calls
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium-high. Syntax from QM help (Language/Functions/Flow IDP_*.html).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. QM's error offset /NNN = start of the failing line.

int r=sub.Add(3 4)
r=sub.Add(r 1)
r=sub.Opt(5)
r=sub.Opt(5 6)
str s
r=sub.StrRef("file.txt" &s)
out s
r=sub.Fact(5)
lpstr ls="abc"
r=sub.Len(ls)
double d=sub.Half(5)
out d
atend sub.AtEnd 7
dll user32 #MessageBeep uType
MessageBeep 0
dll user32 #GetCursorPos POINT*lpPoint
POINT pt
GetCursorPos &pt
out pt.x
dll user32 #FindWindow $lpClassName $lpWindowName
r=FindWindow("Notepad" 0)
out "end"

#sub Add
function# a b
ret a+b

#sub Opt
function# a [b]
ret a+b

#sub StrRef
function# lpstr'sFile str&sr
sr.from("x" sFile)
ret sr.len

#sub Fact
function# n
if(n<=1) ret 1
ret n*sub.Fact(n-1)

#sub Len
function# lpstr'p
ret len(p)

#sub Half
function^ a
ret a/2

#sub AtEnd
function a
out a


 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample31_functions_params.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {A6DEB40E-3754-4AC6-87FB-3598BBBCDDC0}
 END PROJECT
