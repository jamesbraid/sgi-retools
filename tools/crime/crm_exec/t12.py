exec(open("lt2.py").read())
GX=[lambda s,d:0,lambda s,d:s&d,lambda s,d:s&~d,lambda s,d:s,lambda s,d:~s&d,lambda s,d:d,lambda s,d:s^d,lambda s,d:s|d,lambda s,d:~(s|d),lambda s,d:~(s^d),lambda s,d:~d,lambda s,d:s|~d,lambda s,d:~s,lambda s,d:~s|d,lambda s,d:~(s&d),lambda s,d:~0]
cfgs=[(8,0x4d32c0,'cfbLineSD',False),(16,0x4cabf0,'cfb16LineSD',False),(32,0x4d71b0,'cfb32LineSD',False),(8,0x4f1ce0,'cfbSegmentSD',True),(16,0x4e8d00,'cfb16SegmentSD',True),(32,0x4ee6a0,'cfb32SegmentSD',True)]
random.seed(2)
for bpp,fn,name,seg in cfgs:
    v=mk(bpp); c=v.c; m=(1<<bpp)-1; bs=bpp//8; bad=0; n=0; BA={}
    for alu in range(16):
        for trial in range(3):
            bgp=random.getrandbits(bpp)|1; pm=random.getrandbits(bpp) if trial else m
            old=bytes(random.getrandbits(8) for _ in range(v.pitch*v.H+64))
            v.clear(); c.put(v.fb,old)
            # reuse rund but it clears fb: do manually
            v.setclip([(0,0,64,64)])
            c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,3); c.w32(v.G+12,0); c.w32(v.G+16,0xffffffff)  # fg = no change (and=all ones, xor=0)
            c.put(v.GC,bytes(80)); c.w32(v.GC+76,v.GCP); c.w8(v.GC+5,alu); c.w16(v.GC+8,0); c.w16(v.GC+10,2)
            dp=c.alloc(8); c.put(dp,bytes([1,1])); c.w32(v.GC+12,dp); c.w32(v.GC+16,(2<<30)|(1<<28))
            c.w32(v.GC+20,pm&0xffffffff); c.w32(v.GC+28,bgp&0xffffffff)
            c.w8(v.G,6)  # non-copy rop so (old&and)^xor used for fg: and=ones,xor=0 leaves fg pixels unchanged
            pts=[(4,10),(40,10)]
            pp=c.alloc(16)
            for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
            if seg: c.call(fn,[v.D,v.GC,1,pp])
            else: c.call(fn,[v.D,v.GC,0,2,pp])
            im=v.img()
            for k,p in enumerate(lp(*pts)[:-1]):
                o=(p[1]*v.W+p[0])*bs
                od=int.from_bytes(old[o:o+bs],'big'); nw=int.from_bytes(im[o:o+bs],'big')
                if k%2==1:
                    exp=((GX[alu](bgp,od)&pm)|(od&~pm))&m
                else: exp=od
                n+=1
                if nw!=exp:
                    bad+=1; BA[alu]=BA.get(alu,0)+1
                    if bad<3: print(name,'alu',alu,'pm',hex(pm),'bg',hex(bgp),'old',hex(od),'got',hex(nw),'exp',hex(exp))
    print(name,n,"bad",bad,BA)
