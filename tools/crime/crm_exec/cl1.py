exec(open("lt.py").read())
import collections
FN={8:{'Copy':0x46af50,'General':0x49c6a0,'Xor':0x4a0bb0},16:{'Copy':0x4971a0,'General':0x49b190,'Xor':0x4a2c40},32:{'Copy':0x495e70,'General':0x49dba0,'Xor':0x4a4df0}}
def clipped(v,fn,x1,y1,x2,y2,box,shorten,ox=0,oy=0,xorw=0x0b0b0b0b,andw=0xffffffff,bg=None,rop=3):
    c=v.c; v.clear()
    if bg is not None: c.put(v.fb,bg)
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,rop); c.w32(v.G+12,xorw); c.w32(v.G+16,andw)
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    bp=c.alloc(16); c.put(bp,struct.pack('>hhhh',*box))
    c.call(fn,[v.D,v.GC,x1,y1,x2,y2,bp,shorten])
    return v.img()
random.seed(12)
for bpp in (8,16,32):
    v=mk(bpp); bs=bpp//8; m=(1<<bpp)-1
    for kind in ('Copy','General','Xor'):
        fn=FN[bpp][kind]; bad=0;n=0
        for it in range(200):
            x1,y1,x2,y2=[random.randint(-10,70) for _ in range(4)]
            box=(random.randint(0,20),random.randint(0,20),random.randint(30,64),random.randint(30,64))
            ox,oy=random.randint(-3,3),random.randint(-3,3)
            shorten=random.choice([0,1]); bz=random.choice([0,0xff,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
            X=random.getrandbits(bpp); A=random.getrandbits(bpp)
            rep=lambda w: int.from_bytes((w.to_bytes(bs,'big')*(4//bs)),'big') if bs<4 else w
            bgb=bytes(random.getrandbits(8) for _ in range(v.pitch*v.H+64))
            try: im=clipped(v,fn,x1,y1,x2,y2,box,shorten,ox,oy,rep(X),rep(A),bgb)
            except Halt as e: print(bpp,kind,'HALT',e); bad=-1; break
            a=(x1+ox,y1+oy);b=(x2+ox,y2+oy)
            px=lp(a,b)
            if shorten and a!=b: px=px[:-1]
            elif shorten and a==b: px=[]
            exp=bytearray(bgb)
            for p in px:
                if box[0]<=p[0]<box[2] and box[1]<=p[1]<box[3]:
                    o=(p[1]*v.W+p[0])*bs
                    old=int.from_bytes(bgb[o:o+bs],'big')
                    new={'Copy':X,'General':(old&A)^X,'Xor':old^X}[kind]&m
                    exp[o:o+bs]=new.to_bytes(bs,'big')
            n+=1
            exp=exp[:len(im)]
            if bytes(exp)!=bytes(im):
                bad+=1
                if bad<3:
                    d=[i for i in range(len(exp)) if exp[i]!=im[i]][:4]; print(bpp,kind,'mismatch',(x1,y1,x2,y2),box,(ox,oy),shorten,d,[ (exp[i],im[i]) for i in d])
        print(bpp,kind,n,'bad',bad)
