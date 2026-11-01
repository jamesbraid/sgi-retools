import os
exec(open("h2.py").read())
v=Env(bpp=8); c=v.c
# a stipple pixmap record and spans
ST=c.alloc(64); SD=c.alloc(256); c.put(ST,bytes(64))
log=set(); regions={'GC':(v.GC,512),'GCP':(v.GCP,64),'G':(v.G,256),'D':(v.D,64),'S':(v.S,1024),'P':(v.P,256),'ST':(ST,64),'DP':(v.DP,64)}
def rw(a,n):
    for k,(b,l) in regions.items():
        if b<=a<b+l: log.add((k,a-b,n))
c.rwatch=rw
v.setclip([(0,0,64,64)])
c.w32(v.G+4,ST); c.put(ST+12,struct.pack('>HH',32,4)); c.w32(ST+28,4); c.w32(ST+32,SD); c.w8(ST,1)
c.w8(v.GC+5,3); c.w32(v.GC+20,0xffffffff)
pts=c.alloc(32); c.put(pts,struct.pack('>hhhh',3,5,9,6)); wd=c.alloc(16); c.w32(wd,20); c.w32(wd+4,7)
FN=int(os.environ.get("FN","0x4c2590"),0)
try: c.call(FN,[v.D,v.GC,2,pts,wd,1])
except Halt as e: print('halt',e)
for k in regions:
    print(k,sorted((o,n) for kk,o,n in log if kk==k))
