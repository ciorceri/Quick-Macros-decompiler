; sample17 - built-in object factories (names found in the runtime handler
; 0x39: CreateStringMap / CreateCsv / CreateXml) and a Dispatch object.
; Risk: HIGH - member names from memory; comment out failing lines.

IXml x=CreateXml
x.FromString("<root><a>1</a></root>")
str xs; x.ToString(xs)
out xs
IStringMap m=CreateStringMap(1)
m.Add("k" "v")
out m.Get("k")
ICsv c=CreateCsv
c.FromString("a,b,c")
out c.RowCount

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample17_com_objects.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {38BEBA10-6B02-4155-8A6A-F19CCD388999}
 END PROJECT
