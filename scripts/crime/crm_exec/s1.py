exec(open("r6.py").read().split("\nif __name__==")[0])
F={8:{'Copy':0x439a50,'General':0x4a8890,'Xor':0x4a9700},16:{'Copy':0x4a63b0,'General':0x4a79d0,'Xor':0x4aadb0},32:{'Copy':0x429fd0,'General':0x4a6e50,'Xor':0x4aa2f0}}
def runseg(fn,segs,box,cap,rop=3,ox=0,oy=0,col=0x0b0b0b0b,andv=0,bg=None):
    v.clear()
    if bg is not None: c.put(v.fb,bg)
    v.setclip([box]); c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,rop); c.w32(v.G+12,col); c.w32(v.G+16,andv); c.w32(v.GC+16,cap<<28)
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    pp=c.alloc(8*len(segs)+16)
    for i,(a,b) in enumerate(segs): c.put(pp+8*i,struct.pack('>hhhh',a[0],a[1],b[0],b[1]))
    ret=c.call(fn,[v.D,v.GC,len(segs),pp])
    ret=ret&0xffffffff; ret=ret-(1<<32) if ret>=1<<31 else ret
    return ret,v.img()
if __name__=='__main__':
    v=mk(8); c=v.c
    for segs in ([((10,10),(30,20)),((5,5),(50,50))],[((10,10),(100,20)),((5,5),(50,50))],[((5,5),(50,50)),((0,0),(10,10)),((70,5),(20,20))]):
        for cap in (0,1):
            ret,im=runseg(F[8]['Copy'],segs,(0,0,64,64),cap)
            print(segs,cap,'ret',ret,'pix',sum(1 for b in im if b))
    random.seed(29)
    for bpp in (8,16,32):
        v=mk(bpp); c=v.c; bs=bpp//8; m=(1<<bpp)-1
        for kind in ('Copy','General','Xor'):
            bad=0;n=0
            for it in range(250):
                ns=random.randint(1,5)
                if random.random()<.5: segs=[((random.randint(5,58),random.randint(5,58)),(random.randint(5,58),random.randint(5,58))) for _ in range(ns)]
                else: segs=[((random.randint(-10,74),random.randint(-10,74)),(random.randint(-10,74),random.randint(-10,74))) for _ in range(ns)]
                if random.random()<.2: segs[0]=(segs[0][0],segs[0][0])
                ox,oy=random.randint(-3,3),random.randint(-3,3)
                box=(random.randint(0,12),random.randint(0,12),random.randint(52,64),random.randint(52,64))
                cap=random.choice([0,1]); bz=random.choice([0,255,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
                X=random.getrandbits(bpp);A=random.getrandbits(bpp)
                rep=lambda w: int.from_bytes((w.to_bytes(bs,'big')*(4//bs)),'big') if bs<4 else w
                bgb=bytes(random.getrandbits(8) for _ in range(v.pitch*v.H+64))
                ret,im=runseg(F[bpp][kind],segs,box,cap,rop=(3 if kind=='Copy' else 6),ox=ox,oy=oy,col=rep(X),andv=rep(A),bg=bgb)
                # reference
                def ins(p): return box[0]<=p[0]<box[2] and box[1]<=p[1]<box[3]
                exp=bytearray(bgb[:len(im)]); rr=-1
                for k,(a,b) in enumerate(segs):
                    a2=(a[0]+ox,a[1]+oy); b2=(b[0]+ox,b[1]+oy)
                    if not(ins(a2) and ins(b2)): rr=k+1; break
                    px=lp(a2,b2)
                    if a2!=b2: px=px if cap else px[:-1]
                    elif not cap: px=[]
                    for p in px:
                        off=(p[1]*v.W+p[0])*bs; old=int.from_bytes(exp[off:off+bs],'big')
                        new={'Copy':X,'General':(old&A)^X,'Xor':old^X}[kind]&m
                        exp[off:off+bs]=new.to_bytes(bs,'big')
                n+=1
                if ret!=rr or bytes(exp)!=im:
                    bad+=1
                    if bad<3: print(bpp,kind,'mismatch',segs,box,(ox,oy),cap,'ret',ret,'ref',rr)
            print(bpp,kind,n,'bad',bad)
