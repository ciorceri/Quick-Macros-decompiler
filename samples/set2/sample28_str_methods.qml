; sample28_str_methods - many str methods (never-seen opcodes in the str family)
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: medium - one method per line; comment failing lines. Syntax from QM help (Commands/Flow/Functions/str/Language IDP_*.html).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. Keep one construct per line.

str s="a b c"
str t u
int n
s.addline("x")
s.addline("y" 1)
t.insert("ZZ" 1)
t.remove(1 1)
t="hello"
t.replace("J" 0 1)
t.swap(u)
n=t.beg("he")
n=t.begi("HE")
n=t.end("lo")
n=t.endi("LO")
n=t.mid("el" 1)
n=t.midi("EL" 1)
t.set("Q" 1 1)
t.set(65 0 1)
n=s.getl("l1[]l2" 1)
n=s.gett("a b c" 1)
t.fromn("abc" 3 "def" 3)
t.escape
t.escape(1)
t.trim
t.trim("x")
t.all(100)
t.all(-1)
t.all
n=s.findreplace("a" "b")
n=s.replacerx("b" "c")
t.timeformat("{D}")
u.unicode("abc")
u.ansi
s.fix(2)
s.lcase
s.ucase
t.left(s 1)
t.right(s 1)
t.get(s 1 1)
t.geta(s 1 1)
t.from(s "!" "?")
;; FAILED t.fromn
t.format("%i" 5)
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample28_str_methods.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {5E414166-E6A9-4309-8D22-C01E4BFC0CA0}
 END PROJECT
