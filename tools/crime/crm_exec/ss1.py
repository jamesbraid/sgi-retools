# cfb{,16,32}SetSpans: client rows (word padded) into the drawable, clipped, with raster op and plane mask
exec(open("pp1.py").read().split("def trial")[0]); exec(open("stubs.py").read())
SF={8:0x4f67f0,16:0x4f5470,32:0x4f6180}
def trial(bpp,rng,sorted_):
    W=64; v=Env(bpp=bpp,W=W,H=64); c=v.c; bs=bpp//8; install_ffs(c); m=(1<<bpp)-1
    c.put(v.D+12,struct.pack('>HH',W,64)); c.w8(v.D+3,bpp); c.w8(v.D+2,{8:8,16:16,32:24}[bpp]); install_pad(c)
    clip=mkclip(rng); v.setclip(clip)
    alu=rng.choice([3,3,rng.randrange(16)]); pm=rng.choice([0xffffffff,rng.getrandbits(32)])
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,3)
    c.w8(v.GC+5,alu); c.w32(v.GC+20,pm)
    base=bytes(rng.getrandbits(8) for _ in range(v.pitch*v.H)); c.put(v.fb,base)
    n=rng.randint(1,6); ys=rng.sample(range(64),n)
    if sorted_: ys.sort()
    spans=[(rng.randint(0,50),y,rng.randint(1,30)) for y in ys]
    spans=[(x,y,min(w,W-x)) for x,y,w in spans]
    pp=c.alloc(4*n+8); wd=c.alloc(4*n+8)
    for i,(x,y,w) in enumerate(spans): c.put(pp+4*i,struct.pack('>hh',x,y)); c.w32(wd+4*i,w)
    srcb=bytearray(); offs=[]
    for (x,y,w) in spans:
        offs.append(len(srcb)); srcb+=bytes(rng.getrandbits(8) for _ in range(w*bs)); srcb+=bytes((-w*bs)%4)
    src=c.alloc(len(srcb)+8); c.put(src,bytes(srcb))
    try: c.call(SF[bpp],[v.D,v.GC,src,pp,wd,n,int(sorted_)])
    except Halt as e: return 'halt',str(e)
    out=bytearray(base); pmm=pm&m
    for (x,y,w),o0 in zip(spans,offs):
        for i in range(w):
            px=x+i
            if not any(b[0]<=px<b[2] and b[1]<=y<b[3] for b in clip): continue
            s=int.from_bytes(srcb[o0+i*bs:o0+i*bs+bs],'big'); o=(y*W+px)*bs; d=int.from_bytes(out[o:o+bs],'big')
            nv=(d&~pmm)|(ropf(alu,s,d)&pmm); out[o:o+bs]=(nv&m).to_bytes(bs,'big')
    img=v.img(); dif=[((i//bs)%W,(i//bs)//W) for i in range(0,len(img),bs) if img[i:i+bs]!=bytes(out)[i:i+bs]]
    return ('ok' if bytes(out)==img else 'BAD'),(alu,hex(pm),spans,clip,len(dif),dif[:6])
if __name__=='__main__':
    bpp=int(os.environ['BPP']); rng=random.Random(4); cnt=collections.Counter(); ex=[]
    for it in range(int(os.environ.get('NIT','100'))):
        so=rng.random()<.5; r=trial(bpp,rng,so); cnt[(r[0],'sorted' if so else 'unsorted')]+=1
        if r[0]!='ok' and len(ex)<3: ex.append(r)
    print(dict(cnt)); [print(e) for e in ex]
