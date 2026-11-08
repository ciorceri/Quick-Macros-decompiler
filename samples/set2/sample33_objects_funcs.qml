; sample33_objects_funcs - acc / htm / scan / call / share / dir / tok2-style functions, COM objects (IXml, ICsv, IStringMap members), VARIANT/BSTR, ARRAY of str/POINT, user types with arrays
; DO NOT RUN the exe; it is only compiled and analysed offline.
; Risk: HIGH - many forms from memory of the help; comment failing lines. Syntax from QM help (Language/Functions/Flow IDP_*.html).
; If a line fails: put ';;' at the START of the line (a trailing comment does NOT disable it),
; add the error text to <name>.error, recompile. QM's error offset /NNN = start of the failing line.

int w=win("Notepad")
Acc a
a.Find(w "PUSHBUTTON" "OK" "class=Button" 0x1005)
int h=0
str s
str t
IXml x=CreateXml
x.FromString("<r><a>1</a><b>2</b></r>")
IXmlNode n=x.RootElement
x.ToString(s)
out s
int cnt=n.ChildCount
ICsv c=CreateCsv
c.FromString("a,b[]c,d")
out c.RowCount
out c.ColumnCount
t=c.Cell(1 1)
c.Cell(0 0)="z"
c.ToString(s)
IStringMap m=CreateStringMap(1)
m.Add("k" "v")
t=m.Get("k")
ARRAY(str) as
as.create(3)
as[0]="a"
as[1]="b"
int u=as.len
as.redim(5)
as.remove(1)
ARRAY(POINT) ap
ap.create(2)
ap[0].x=5
ap[1].y=6
POINT p
p.x=1
p.y=2
RECT r
r.left=1
r.right=r.left+10
VARIANT v=5
v=7
BSTR b="bstr"
int len2=b.len
type UT x1 y1 byte'a2[3]
UT ut
ut.x1=3
ut.a2[2]=9
out ut.x1+ut.a2[2]
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample33_objects_funcs.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {E1355428-7A09-4BF6-B9D1-624EE75D5C47}
 END PROJECT
