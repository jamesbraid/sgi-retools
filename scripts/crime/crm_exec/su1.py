# unnatural stipple (stipple pixmap of any size, patOrg, drawable origin) span and rectangle fillers
exec(open("sp3.py").read().split("\nif __name__")[0])
def trial_u(fn,bpp,rng,rect=False,orderbits='msb'):
    W=rng.choice([1,2,3,5,8,13,16,20,31,32,33,45]) if not os.environ.get('NOW1') else rng.choice([int(x) for x in os.environ.get('WSET','2,3,5,8,13,16,20,31,32,33,45').split(',')]); Hh=rng.choice([1,2,3,4,7,9])
    pitch=((W+31)//32)*4
    rows=[[rng.getrandbits(1) for _ in range(W)] for _ in range(Hh)]
    v=mk(bpp); c=v.c; m=(1<<bpp)-1
    clip=mkclip(rng) if not rect else [(0,0,64,64)]
    v.setclip(clip)
    ox,oy=rng.randint(-3,3),rng.randint(-3,3); px,py=rng.randint(-40,40),rng.randint(-40,40)
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    ST=c.alloc(64); SD=c.alloc(pitch*Hh+16); c.w8(ST,1); c.put(ST+12,struct.pack('>HH',W,Hh)); c.w32(ST+28,pitch); c.w32(ST+32,SD)
    for r in range(Hh):
        for xx in range(W):
            if rows[r][xx]:
                o=SD+r*pitch+(xx//32)*4; w=c.r32(o); c.w32(o,w|(1<<(31-xx%32)))
    fg=rng.randint(1,m); bg=rng.randint(1,m); alu=rng.randrange(16); pm=rng.choice([0xffffffff,rng.getrandbits(32)])
    opaque=rng.random()<.5
    c.w8(v.GC+5,alu); c.w32(v.GC+20,pm); c.w32(v.GC+24,fg); c.w32(v.GC+28,bg); c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack('>hh',px,py))
    c.w32(v.GC+16,(3 if opaque else 2)<<24)
    base=bytes(rng.getrandbits(8) for _ in range(v.pitch*v.H)); c.put(v.fb,base)
    if rect:
        boxes=[(rng.randint(max(0,ox),50),rng.randint(max(0,oy),50)) for _ in range(rng.randint(1,3))]
        boxes=[(x,y,x+rng.randint(1,14),y+rng.randint(1,10)) for x,y in boxes]
        spans=[(b[0],yy,b[2]-b[0]) for b in boxes for yy in range(b[1],b[3])]
        bx=c.alloc(8*len(boxes)+8)
        for i,b in enumerate(boxes): c.put(bx+8*i,struct.pack('>hhhh',*b))
    else:
        ys=rng.sample(range(max(0,oy),64),rng.randint(1,6)); spans=sorted([(rng.randint(max(ox,-5),60),y,rng.randint(1,40)) for y in ys],key=lambda t:t[1])   # spans lie inside the drawable: x>=origin x, y>=origin y   # spans of one call never overlap
    try:
        if rect: c.call(fn,[v.D,v.GC,len(boxes),bx]); img=v.img()
        else: img=run(v,fn,spans,1)
    except Halt as e: return 'halt',str(e)
    out=bytearray(base); bs=bpp//8; pmm=pm&m
    for (x,y,w) in spans:
        for xx in range(x,x+w):
            if not any(b[0]<=xx<b[2] and b[1]<=y<b[3] for b in clip): continue
            sx=(xx-ox-px)%W; sy=(y-oy-py)%Hh
            bit=rows[sy][sx]
            if not bit and not opaque: continue
            src=fg if bit else bg; o=(y*64+xx)*bs; d=int.from_bytes(out[o:o+bs],'big')
            n=(d&~pmm)|(ropf(alu,src&m,d)&pmm); out[o:o+bs]=(n&m).to_bytes(bs,'big')
    if bytes(out)!=img:
        dif=[i for i in range(0,len(img),bs) if img[i:i+bs]!=bytes(out)[i:i+bs]]
        return 'BAD',W,dict(W=W,H=Hh,org=(ox,oy),pat=(px,py),alu=alu,pm=hex(pm),opaque=opaque,nd=len(dif),first=dif[:3],spans=spans,clip=clip,got=[img[i:i+bs].hex() for i in dif[:3]],want=[bytes(out)[i:i+bs].hex() for i in dif[:3]],fg=hex(fg),bg=hex(bg),bs=bs)
    return 'ok',W
if __name__=='__main__':
    FN=int(os.environ['FN'],0); bpp=int(os.environ.get('BPP','8')); rect=os.environ.get('KIND')=='rect'
    rng=random.Random(6); cnt=collections.Counter(); ex=[]
    for it in range(int(os.environ.get('NIT','150'))):
        r=trial_u(FN,bpp,rng,rect); cnt[(r[0],'W=1' if r[1]==1 else 'W>1')]+=1
        if r[0]!='ok' and len(ex)<8: ex.append(r)
    print(dict(cnt)); [print(e) for e in ex]
