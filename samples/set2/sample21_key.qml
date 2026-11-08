; sample21_key - key forms (opcode 0xb7): single keys, modifiers, group, text, variable, F-string
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: low - syntax taken from the QM help (Commands\IDP_*.html). If a line
; fails, comment it with ;;FAILED and tell me the error text.

key An
out 1
;;FAILED: key A(n) - unknown identifier (parentheses = string variable per IDP_KEY)
out 1
key Cc
out 1
key a/2
out 1
key A{ev}
out 1
key Wf CSF2
out 1
key TT Y F2 N3
out 1
key "Text"
out 1
key "a[][9]b"
out 1
str ks="Text[]more"
key (ks)
out 1
int kx=5
key F"x={kx}"
out 1
key+ C
out 1
key- C
out 1
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample21_key.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {0A17052A-B485-47BB-B28F-575F63ACBA55}
 END PROJECT
