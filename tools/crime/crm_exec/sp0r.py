import os
exec(open("sp0.py").read().split("pts=c.alloc(32)")[0])
bx=c.alloc(32); c.put(bx,struct.pack('>hhhh',3,5,20,9))
FN=int(os.environ["FN"],0)
try: c.call(FN,[v.D,v.GC,1,bx])
except Halt as e: print('halt',e)
for k in regions: print(k,sorted((o,n) for kk,o,n in log if kk==k))
print([hex(c.r32(v.fb+i)) for i in range(5*64+3,5*64+12,4)] )
