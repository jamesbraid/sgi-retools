exec(open("gs1.py").read().split("\nif __name__")[0])
def probe(bpp,x,y,w,wmax,pt='pixmap'):
    W=64; v=Env(bpp=bpp,W=W,H=64); c=v.c; bs=bpp//8
    c.w8(v.D+3,bpp)
    if pt=='pixmap': c.w8(v.D,1); c.w32(v.D+28,v.pitch); c.w32(v.D+32,v.fb)
    c.put(v.fb,bytes((i*7+1)&255 for i in range(v.pitch*v.H)))
    pp=c.alloc(8); wd=c.alloc(8); c.put(pp,struct.pack('>hh',x,y)); c.w32(wd,w)
    dst=c.alloc(512); c.put(dst,bytes([0xAA])*512)
    c.call(GF[bpp],[v.D,wmax,pp,wd,1,dst])
    got=c.bytes(dst,w*bs+8); src=c.bytes(v.fb+(y*W+x)*bs,w*bs)
    return got[:w*bs]==src, [i for i in range(0,len(got)) if got[i]==0xAA][:1]
for bpp in (8,16,32):
    print(bpp,'x=60 w=10 wmax=64',probe(bpp,60,3,10,64),'w=30 wmax=20',probe(bpp,2,3,30,20),'w=30 wmax=64',probe(bpp,2,3,30,64))
