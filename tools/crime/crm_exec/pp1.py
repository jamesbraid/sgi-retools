# cfb{,16,32}PolyPoint: raster-op byte 3 or general, relative or absolute points, clip regions, ffs path
exec(open("lt.py").read()); exec(open("stubs.py").read()); exec(open("sp3.py").read().split("def model")[0].split("\n",1)[1]) if False else None
import os
FN={8:0x4e35c0,16:0x4e2a10,32:0x4e2fe0}
def ropf(alu,s,d): return [0,s&d,s&~d,s,~s&d,d,s^d,s|d,~(s|d),~(s^d),~d,s|~d,~s,~s|d,~(s&d),-1][alu]
def mkclip(rng):
    n=rng.choice([1,1,2,3]); y=rng.randint(0,10)
    if n==1: return [(rng.randint(0,10),rng.randint(0,10),rng.randint(40,64),rng.randint(40,64))]
    bx=[]
    for i in range(n):
        y2=y+rng.randint(4,15); bx.append((rng.randint(0,12),y,rng.randint(30,64),min(y2,64))); y=y2+rng.randint(0,3)
    return [b for b in bx if b[3]>b[1]]
def trial(bpp,rng,pitchpow2=True):
    W=64 if pitchpow2 else 48; v=Env(bpp=bpp,W=W,H=64); c=v.c; ffs=install_ffs(c); bs=bpp//8; m=(1<<bpp)-1
    clip=[(b[0],b[1],min(b[2],W),b[3]) for b in mkclip(rng)]; clip=[b for b in clip if b[2]>b[0]] or [(0,0,W,64)]; v.setclip(clip); ox,oy=rng.randint(-3,3),rng.randint(-3,3); c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    rop=rng.choice([3,3,6,5,rng.randrange(16)]); rep=lambda x:{8:x*0x01010101,16:x*0x00010001,32:x}[bpp]&0xffffffff
    xw=rep(rng.getrandbits(bpp)); aw=rep(rng.getrandbits(bpp))
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,rop); c.w32(v.G+12,xw); c.w32(v.G+16,aw)
    base=bytes(rng.getrandbits(8) for _ in range(v.pitch*v.H)); c.put(v.fb,base)
    n=rng.randint(1,12); mode=rng.choice([0,1])
    pts=[(rng.randint(-5,W+5),rng.randint(-5,69)) for _ in range(n)]
    if mode==1: pts=[(rng.randint(0,W),rng.randint(0,60))]+[(rng.randint(-12,12),rng.randint(-12,12)) for _ in range(n-1)]
    pp=c.alloc(4*n+8)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    try: c.call(FN[bpp],[v.D,v.GC,mode,n,pp])
    except Halt as e: return 'halt',str(e),0
    img=v.img()
    ab=[];cx=cy=0
    for i,(x,y) in enumerate(pts):
        if mode==1 and i>0: cx+=x; cy+=y
        else: cx,cy=x,y
        ab.append((cx,cy))
    out=bytearray(base)
    if rop!=5:
        for (x,y) in ab:
            px,py=x+ox,y+oy
            if not any(b[0]<=px<b[2] and b[1]<=py<b[3] for b in clip): continue
            if not(0<=px<W and 0<=py<64): continue
            o=(py*W+px)*bs; d=int.from_bytes(out[o:o+bs],'big')
            # copy: xor word; any other: (dst & and) ^ xor, as the validate step pre-computes for the raster op
            nv=(xw&m) if rop==3 else (((d&aw)^xw)&m)
            out[o:o+bs]=nv.to_bytes(bs,'big')
    return ('ok' if bytes(out)==img else 'BAD'),(mode,rop,len(ffs.args)),0
if __name__=='__main__':
    bpp=int(os.environ['BPP']); rng=random.Random(2); cnt=collections.Counter(); ex=[]
    for it in range(int(os.environ.get('NIT','150'))):
        r=trial(bpp,rng,rng.random()<.5); cnt[(r[0],'mode%d'%r[1][0] if r[0]!='halt' else '', 'ffs' if r[0]!='halt' and r[1][2] else '')]+=1
        if r[0]!='ok' and len(ex)<3: ex.append(r)
    print(dict(cnt)); [print(e) for e in ex]
