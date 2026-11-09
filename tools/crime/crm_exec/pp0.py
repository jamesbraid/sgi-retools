import os
exec(open("sp0.py").read().split("pts=c.alloc(32)")[0])
pts=c.alloc(32); c.put(pts,struct.pack('>hhhh',3,5,9,6))
c.w8(v.G,3); c.w32(v.G+12,0x0b0b0b0b)
FN=int(os.environ["FN"],0)
try: c.call(FN,[v.D,v.GC,0,2,pts])
except Halt as e: print('halt',e)
for k in regions: print(k,sorted((o,n) for kk,o,n in log if kk==k))
print([hex(v.img()[y*64+x]) for (x,y) in ((3,5),(9,6))])
wl=[]
c.watch=lambda a,n,val: wl.append((hex(a-v.fb) if v.fb<=a<v.fb+4096 else hex(a),n,hex(val)))
c.call(FN,[v.D,v.GC,0,2,pts]); print(wl[:10])
print('D x,y',c.r32(v.D+8))
