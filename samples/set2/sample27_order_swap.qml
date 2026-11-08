; sample27_order_swap - same constructs as samples 11/19-25 but in the OPPOSITE ORDER, to break order-only labels (left/right, lcase/ucase, getclip/setclip, wait K/M, mov/siz, hid)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: low. Syntax from QM help (Commands/Flow/Functions/str/Language IDP_*.html).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. Keep one construct per line.

str s="Hello World"
str t u
t.right(s 3)
out t
t.left(s 2)
out t
u="MiXed"
u.lcase
out u
u.ucase
out u
t.setclip
t.getclip
int w=win("Notepad")
siz 400 300 w
mov 20 30 w
hid- w
hid w
wait 5 M
wait 5 K F12
wait 5 ML
wait 5 -WC "Notepad"
mov+ 1 2 3 4 w
mkdir "c:	emp\qmtest" "c:	emp"
mes "one" "cap"
mes "two" "cap" "OC"
mes- "three"
mou 5 6
mou 5 6 w
mou+ 1 2
mou- 3 4
mou
opt hidden 0
opt clip 0
spe 100
wait 0
wait 1
find(s "o" 2)
find(s "O" 0 1)
int x=find(s "o" 2)
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample27_order_swap.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {B82DB857-D3B4-43E6-B149-84B2B6A4C8E0}
 END PROJECT
