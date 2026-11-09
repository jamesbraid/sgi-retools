exec(open("mt.py").read().split("v=Env(bpp=1")[0])
v=Env(bpp=1,W=64,H=64,pitch=8)
c=v.c
def bits(v):
    im=v.img(); out=set()
    for y in range(v.H):
        for x in range(v.W):
            w=int.from_bytes(im[y*8+(x>>5)*4:y*8+(x>>5)*4+4],'big')
            if (w>>(31-(x&31)))&1: out.add((x,y))
    return out
def runm(fn,pts,clip,rop=15,seg=False,mode=0,cap=1,**kw):
    v.clear(); v.setclip(clip); setup(v,rop=rop,cap=cap,**kw)
    pp=c.alloc(4*len(pts)+8)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    if seg: c.call(fn,[v.D,v.GC,len(pts)//2,pp])
    else: c.call(fn,[v.D,v.GC,mode,len(pts),pp])
    return bits(v)
for rop in (0,15,10,5,3,6,12):
    v.clear()
    got=runm(0x52f320,[(5,5),(9,5)],[(0,0,64,64)],rop=rop)
    print('rop',rop,sorted(got))
