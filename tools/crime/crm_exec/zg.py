from mips import *
import subprocess,re,sys
c=CPU('../../ddx/crm.so')
for name in ['cfbSetSpans','cfb16SetSpans','cfb32SetSpans','cfbGetSpans','cfb16GetSpans','cfb32GetSpans','cfbPolyPoint']:
    out=subprocess.run([sys.executable,'crmdis.py',name],capture_output=True,text=True).stdout
    offs=sorted({int(m.group(1),0) for m in re.finditer(r'lw\s+\$\w+, (-0x[0-9a-f]+)\(\$(?:at|gp)\)',out)})
    print(name,[(hex(o),hex(c.r32(0x5b0ea0+o))) for o in offs if o<-0x6000 and c.r32(0x5b0ea0+o)==0])
