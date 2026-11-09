exec(open("su1.py").read().split("\nif __name__")[0])
FN=int(os.environ['FN'],0); bpp=int(os.environ.get('BPP','8'))
def one(W,alu,opaque,seed=1):
    rng=random.Random(seed); Hh=3; pitch=4; m=(1<<bpp)-1
    rows=[[rng.getrandbits(1) for _ in range(W)] for _ in range(Hh)]
    v=mk(bpp); c=v.c; v.setclip([(0,0,64,64)])
    ST=c.alloc(64); SD=c.alloc(64); c.w8(ST,1); c.put(ST+12,struct.pack('>HH',W,Hh)); c.w32(ST+28,pitch); c.w32(ST+32,SD)
    for r in range(Hh):
        for xx in range(W):
            if rows[r][xx]: o=SD+r*pitch; c.w32(o,c.r32(o)|(1<<(31-xx)))
    fg,bg=0x3a&m,0x45&m
    c.w8(v.GC+5,alu); c.w32(v.GC+20,0xffffffff); c.w32(v.GC+24,fg); c.w32(v.GC+28,bg); c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack('>hh',0,0)); c.w32(v.GC+16,(3 if opaque else 2)<<24)
    base=bytes(rng.getrandbits(8) for _ in range(v.pitch*v.H)); c.put(v.fb,base)
    spans=[(5,y,30) for y in (3,4,5,6)]
    img=run(v,FN,spans,1)
    out=bytearray(base); bs=bpp//8
    for (x,y,w) in spans:
        for xx in range(x,x+w):
            bit=rows[y%Hh][xx%W]
            if not bit and not opaque: continue
            src=fg if bit else bg; o=(y*64+xx)*bs; d=int.from_bytes(out[o:o+bs],'big')
            n=ropf(alu,src,d)&m; out[o:o+bs]=n.to_bytes(bs,'big')
    return bytes(out)==img
for W in (1,2,3,4,5,8,16):
    print(W,'transparent bad alus',[a for a in range(16) if not one(W,a,False)],'opaque bad alus',[a for a in range(16) if not one(W,a,True)])
