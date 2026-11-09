from mips import *
import csv,re,subprocess
c=CPU('../../ddx/crm.so')
syms={}
for row in csv.reader(open('../../docs/inventory/functions.tsv'),delimiter='\t'):
    if row and row[0].endswith('crm.so') and row[4].startswith('0x'): syms[int(row[4],16)]=row[6]
import sys
for fn,name,sites in [(0x4c2590,'cfb8Stipple32FS',[0x4c2854]),(0x4c4d20,'cfb8OpaqueStipple32FS',[0x4c4db8,0x4c4ea4]),(0x4c5c10,'cfbUnnaturalStippleFS',[0x4c5ca4,0x4c5db4,0x4c61a4]),(0x4e6f20,'cfb8FillRectOpaqueStippled32',[0x4e6fac])]:
    out=subprocess.run([sys.executable,'crmdis.py',name],capture_output=True,text=True).stdout.split('\n')
    for site in sites:
        k=[i for i,l in enumerate(out) if l.startswith('%x:'%site)][0]
        # nearest preceding 'lw $t9, off($gp)' or ($at)
        for j in range(k,k-60,-1):
            m=re.search(r'lw\s+\$t9, (-?0x[0-9a-f]+|-?\d+)\(\$(gp|at)\)',out[j])
            if m: off=int(m.group(1),0); base=m.group(2); print(name,hex(site),out[j].split('\t',1)[0],m.group(0),end=' ')
            if m: break
        # gp value: routine sets gp = t9 + const; module gp is 0x5b0ea0
        v=c.r32(0x5b0ea0+off); print('->',hex(v),syms.get(v)); 
