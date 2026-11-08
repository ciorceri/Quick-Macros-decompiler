; sample10 - loops and flow control
; Purpose: for (with step, negative range), nested for, rep N, rep+break,
;          continue, if / else chains, ret.
; Risk: low (else on its own line, indentation blocks)

int i j n
for i 0 5
	out i
for i 0 10 2
	out i
for i 10 0 -1
	out i
for i 0 3
	for j 0 3
		n+1
out n
rep 4
	n+1
out n
n=0
rep
	n+1
	if(n<3) continue
	if(n>6) break
	out n
for i 0 20
	if(i=3)
		out "three"
	else
		if(i=4)
			out "four"
		else
			if(i=5) break
if(n>100)
	ret
out "end"

 BEGIN PROJECT
 main_function  Macro1
 exe_file  $desktop$\corpus\sample10_loops_flow.exe
 icon  <default>
 manifest  $qm$\default.exe.manifest
 flags  6
 guid  {3AD5BD72-E107-4ACA-A440-B5DE7094ACD0}
 END PROJECT
