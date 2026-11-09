exec(open("ss1.py").read().split("\nif __name__")[0])
def one(spans,clip,alu=3,pm=0xffffffff,bpp=8,srcfill=None):
    W=64; v=Env(bpp=bpp,W=W,H=64); c=v.c; bs=bpp//8; install_pad(c); install_ffs(c)
    c.put(v.D+12,struct.pack('>HH',W,64)); c.w8(v.D+3,bpp); c.w8(v.D+2,{8:8,16:16,32:24}[bpp]); v.setclip(clip)
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,3); c.w8(v.GC+5,alu); c.w32(v.GC+20,pm)
    c.put(v.fb,bytes([0x55])*(v.pitch*64))
    n=len(spans); pp=c.alloc(4*n+8); wd=c.alloc(4*n+8)
    for i,(x,y,w) in enumerate(spans): c.put(pp+4*i,struct.pack('>hh',x,y)); c.w32(wd+4*i,w)
    srcb=bytearray()
    for k,(x,y,w) in enumerate(spans):
        row=bytes((0x10*(k+1)+i) for i in range(w*bs)); srcb+=row+bytes((-len(row))%4)
    src=c.alloc(len(srcb)+8); c.put(src,bytes(srcb))
    c.call(SF[bpp],[v.D,v.GC,src,pp,wd,n,1]); img=v.img()
    return [(x,y,hex(img[y*64+x])) for y in range(64) for x in range(64) if img[y*64+x]!=0x55]
print(one([(16,11,2)],[(1,10,47,14)]))
print(one([(16,11,2)],[(1,10,47,14),(1,16,42,28)]))
print(one([(38,1,20),(16,11,2)],[(1,10,47,14),(1,16,42,28)]))
