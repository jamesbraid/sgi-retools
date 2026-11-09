import os
exec(open("sp0.py").read().split("pts=c.alloc(32)")[0])
c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack(">hh",3,2)); c.put(ST+12,struct.pack('>HH',20,5)); c.w32(ST+28,4)
pts=c.alloc(32); c.put(pts,struct.pack('>hhhh',3,5,9,6)); wd=c.alloc(16); c.w32(wd,20); c.w32(wd+4,7)
FN=int(os.environ["FN"],0)
try:
    if os.environ.get('RECT'): c.call(FN,[v.D,v.GC,1,pts])
    else: c.call(FN,[v.D,v.GC,2,pts,wd,1])
except Halt as e: print('halt',e)
for k in regions: print(k,sorted((o,n) for kk,o,n in log if kk==k))
