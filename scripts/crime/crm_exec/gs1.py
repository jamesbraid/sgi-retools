# cfb{,16,32}GetSpans: rows of pixels out of a drawable into a word-aligned buffer
exec(open("pp1.py").read().split("def mkclip")[0]); exec(open("stubs.py").read())
GF={8:0x4c73a0,16:0x4c8400,32:0x4c7d70}
def trial(bpp,rng,ptype):
    W=64; v=Env(bpp=bpp,W=W,H=64); c=v.c; bs=bpp//8; ffs=install_ffs(c)
    c.w8(v.D+3,bpp)   # drawable depth byte read by the switch
    if ptype=='pixmap': c.w8(v.D,1); c.w32(v.D+28,v.pitch); c.w32(v.D+32,v.fb)
    base=bytes(rng.getrandbits(8) for _ in range(v.pitch*v.H)); c.put(v.fb,base)
    n=rng.randint(1,6); wmax=rng.choice([64,40,20])
    spans=[(rng.randint(0,63),rng.randint(0,63),rng.randint(1,40)) for _ in range(n)]
    pp=c.alloc(4*n+8); wd=c.alloc(4*n+8)
    for i,(x,y,w) in enumerate(spans): c.put(pp+4*i,struct.pack('>hh',x,y)); c.w32(wd+4*i,w)
    dst=c.alloc(4*W*n+64); c.put(dst,bytes([0xAA])*(4*W*n+64))
    try: c.call(GF[bpp],[v.D,wmax,pp,wd,n,dst])
    except Halt as e: return 'halt',str(e)
    spans=[(x,y,min(w,W-x)) for x,y,w in spans]   # the routine clamps the width to the drawable's right edge
    exp=bytearray(); 
    for (x,y,w) in spans:
        row=bytearray(base[(y*W+x)*bs:(y*W+x+w)*bs]); pad=(-len(row))%4
        exp+=row+bytes(pad)
    got=c.bytes(dst,len(exp))
    # padding bytes are not part of the contract: compare pixel bytes only
    off=0; ok=True; padinfo=set()
    for (x,y,w) in spans:
        L=w*bs; pad=(-L)%4
        if got[off:off+L]!=exp[off:off+L]: ok=False
        padinfo.add(bytes(got[off+L:off+L+pad]).hex()); off+=L+pad
    return ('ok' if ok else 'BAD'),(wmax,spans[:3],padinfo)
if __name__=='__main__':
    bpp=int(os.environ['BPP']); rng=random.Random(4); cnt=collections.Counter(); ex=[]
    for it in range(int(os.environ.get('NIT','100'))):
        pt=rng.choice(['pixmap','window']); r=trial(bpp,rng,pt); cnt[(r[0],pt)]+=1
        if r[0]!='ok' and len(ex)<3: ex.append(r)
    print(dict(cnt)); [print(e) for e in ex]
