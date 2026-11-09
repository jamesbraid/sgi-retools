exec(open("su1.py").read().split("\nif __name__")[0])
FN=0x4c5c10; bpp=8
rng=random.Random(3)
for trial in range(400):
    W=2; Hh=7; rows=[[rng.getrandbits(1) for _ in range(W)] for _ in range(Hh)]
    v=mk(8); c=v.c; clip=[(0,0,55,12),(10,15,59,30),(4,30,31,43)]; v.setclip(clip)
    ox,oy,px,py=2,3,23,13
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    ST=c.alloc(64); SD=c.alloc(64); c.w8(ST,1); c.put(ST+12,struct.pack('>HH',W,Hh)); c.w32(ST+28,4); c.w32(ST+32,SD)
    for r in range(Hh):
        for xx in range(W):
            if rows[r][xx]: o=SD+r*4; c.w32(o,c.r32(o)|(1<<(31-xx)))
    fg,bg=0x72,0xe3
    c.w8(v.GC+5,14); c.w32(v.GC+20,0xffffffff); c.w32(v.GC+24,fg); c.w32(v.GC+28,bg); c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack('>hh',px,py)); c.w32(v.GC+16,2<<24)
    base=bytes(rng.getrandbits(8) for _ in range(64*64)); c.put(v.fb,base)
    spans=[(53,0,17),(28,1,39),(48,18,3),(26,38,21),(32,41,6)]
    img=run(v,FN,spans,1)
    out=bytearray(base)
    for (x,y,w) in spans:
        for xx in range(x,x+w):
            if not any(b[0]<=xx<b[2] and b[1]<=y<b[3] for b in clip): continue
            bit=rows[(y-oy-py)%Hh][(xx-ox-px)%W]
            if not bit: continue
            o=y*64+xx; out[o]=ropf(14,fg,out[o])&255
    d=[(i%64,i//64) for i in range(len(img)) if img[i]!=out[i]]
    if d:
        import itertools
        print('trial',trial,'rows',rows,len(d)); print(sorted(collections.Counter(y for x,y in d).items())); print([(x,y,hex(img[y*64+x]),hex(out[y*64+x]),hex(base[y*64+x])) for x,y in d[:6]]); break
else: print('no failure in 400 random backgrounds')
