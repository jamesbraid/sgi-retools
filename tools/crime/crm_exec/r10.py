exec(open("r6.py").read().split("\nif __name__==")[0])
F={8:{'Copy':0x429580,'General':0x49a460,'Xor':0x4a1f90},16:{'Copy':0x4944f0,'General':0x499680,'Xor':0x4a40b0},32:{'Copy':0x4954b0,'General':0x49f0b0,'Xor':0x49fe80}}
random.seed(23)
for bpp in (8,16,32):
    v=mk(bpp); c=v.c; bs=bpp//8; m=(1<<bpp)-1
    for kind in ('Copy','General','Xor'):
        bad=0
        for it in range(40):
            X=random.getrandbits(bpp);A=random.getrandbits(bpp)
            rep=lambda w: int.from_bytes((w.to_bytes(bs,'big')*(4//bs)),'big') if bs<4 else w
            bgb=bytes(random.getrandbits(8) for _ in range(v.pitch*v.H+64))
            v.clear(); c.put(v.fb,bgb); v.setclip([(0,0,64,64)])
            c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,3 if kind=='Copy' else 6); c.w32(v.G+12,rep(X)); c.w32(v.G+16,rep(A)); c.w32(v.GC+16,0)
            pts=[(random.randint(8,56),random.randint(8,56)) for _ in range(3)]
            pp=c.alloc(32)
            for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
            o=c.alloc(32); c.put(c.sp0,bytes(32)); c.wr(c.sp0,8,o+8); c.wr(c.sp0+8,8,o+12)
            c.call(F[bpp][kind],[v.D,v.GC,0,3,pp,pp,o,o+4])
            im=v.img(); exp=bytearray(bgb[:len(im)])
            seq=lp(pts[0],pts[1])[:-1]+lp(pts[1],pts[2])[:-1]
            for p in seq:
                off=(p[1]*v.W+p[0])*bs; old=int.from_bytes(exp[off:off+bs],'big')
                new={'Copy':X,'General':(old&A)^X,'Xor':old^X}[kind]&m
                exp[off:off+bs]=new.to_bytes(bs,'big')
            if bytes(exp)!=im: bad+=1
        print(bpp,kind,'random and/xor: bad',bad,'of 40')
