exec(open("sp1.py").read().split("\nif __name__")[0])
def ropf(alu,s,d): return [0,s&d,s&~d,s,~s&d,d,s^d,s|d,~(s|d),~(s^d),~d,s|~d,~s,~s|d,~(s&d),-1][alu]
def mkclip(rng,W=64,H=64):
    n=rng.choice([1,1,2,3]); boxes=[]; y=rng.randint(0,10)
    if n==1: return [(rng.randint(0,10),rng.randint(0,10),rng.randint(40,64),rng.randint(40,64))]
    for i in range(n):
        y2=y+rng.randint(4,15); boxes.append((rng.randint(0,12),y,rng.randint(30,64),min(y2,H))); y=y2+rng.randint(0,3)
    return [b for b in boxes if b[3]>b[1]]
def model(bpp,img0,spans,clip,words,H,fg,bg,alu,pm,opaque,ox=0,oy=0):
    bs=bpp//8; W=64; m=(1<<bpp)-1; out=bytearray(img0); pmm=pm&m
    for (x,y,w) in spans:
        for xx in range(x,x+w):
            if not any(b[0]<=xx<b[2] and b[1]<=y<b[3] for b in clip): continue
            bit=(words[y%H]>>(31-(xx%32)))&1
            if not bit and not opaque: continue
            src=fg if bit else bg; o=(y*W+xx)*bs; d=int.from_bytes(out[o:o+bs],'big')
            n=(d&~pmm)|(ropf(alu,src&m,d)&pmm); out[o:o+bs]=(n&m).to_bytes(bs,'big')
    return bytes(out)
def trial(fn,bpp,rng,opaque,rops=True):
    H=rng.choice([1,2,3,4,5,8,16,32]); words=[rng.getrandbits(32) for _ in range(H)]
    clip=mkclip(rng); m=(1<<bpp)-1
    fg=rng.randint(1,m); bg=rng.randint(1,m); alu=rng.randrange(16) if rops else 3
    pm=rng.choice([0xffffffff,rng.getrandbits(32)]) if rops else 0xffffffff
    ox,oy=rng.randint(-3,3),rng.randint(-3,3)
    rep=lambda v:{8:v*0x01010101,16:v*0x00010001,32:v}[bpp]&0xffffffff
    f0=ropf(alu,rep(fg),0)&0xffffffff; f1=ropf(alu,rep(fg),0xffffffff)&0xffffffff; pmw=rep(pm&m) if bpp<32 else pm
    xw=f0&pmw; aw=((f0^f1)|~pmw)&0xffffffff     # the and/xor pair a validate step derives from the raster op and plane mask
    v=setup(bpp,clip,ox,oy,H,words,fg,bg,alu,pm,xw,aw)
    c=v.c; base=bytes(rng.getrandbits(8) for _ in range(v.pitch*v.H)); c.put(v.fb,base)
    spans=[(rng.randint(-5,60),y,rng.randint(1,40)) for y in rng.sample(range(64),rng.randint(1,6))]   # spans of one call never overlap
    fs=int(os.environ.get('SORTED','1'))
    if fs: spans.sort(key=lambda t:t[1])
    rect=os.environ.get('KIND')=='rect'
    if rect:
        boxes=[(rng.randint(0,50),rng.randint(0,50)) for _ in range(rng.randint(1,4))]
        boxes=[(x,y,x+rng.randint(1,14),y+rng.randint(1,10)) for x,y in boxes]
        clip=[(0,0,64,64)]; v.setclip(clip)
        spans=[(b[0],yy,b[2]-b[0]) for b in boxes for yy in range(b[1],b[3])]
    try:
        if rect:
            c=v.c; bx=c.alloc(8*len(boxes)+8)
            for i,b in enumerate(boxes): c.put(bx+8*i,struct.pack('>hhhh',*b))
            c.call(fn,[v.D,v.GC,len(boxes),bx]); img=v.img()
        else: img=run(v,fn,spans,fs)
    except Halt as e: return 'halt',str(e)
    want=model(bpp,base,spans,clip,words,H,fg,bg,alu,pm,opaque)
    if img!=want:
        dif=[(i%64,i//64) for i in range(len(img)) if img[i]!=want[i]] if bpp==8 else '?'
        return 'BAD',dict(H=H,alu=alu,pm=hex(pm),clip=clip,spans=spans,org=(ox,oy),ndiff=len(dif),dif=dif[:6])
    return 'ok',None
if __name__=='__main__':
    FN=int(os.environ.get('FN','0x4c2590'),0); bpp=int(os.environ.get('BPP','8')); opaque=os.environ.get('OPAQUE')=='1'; rops=os.environ.get('ROPS','1')=='1'
    rng=random.Random(4); cnt=collections.Counter(); ex=[]
    for it in range(int(os.environ.get('NIT','150'))):
        r=trial(FN,bpp,rng,opaque,rops); cnt[r[0]]+=1
        if r[0]!='ok' and len(ex)<3: ex.append(r)
    print(dict(cnt)); [print(e) for e in ex]
