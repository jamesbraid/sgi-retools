exec(open("lt2.py").read())
import collections
cfgs=[(8,0x4d32c0,'cfbLineSD',False),(16,0x4cabf0,'cfb16LineSD',False),(32,0x4d71b0,'cfb32LineSD',False),(8,0x4f1ce0,'cfbSegmentSD',True),(16,0x4e8d00,'cfb16SegmentSD',True),(32,0x4ee6a0,'cfb32SegmentSD',True)]
for bpp,fn,name,seg in cfgs:
    v=mk(bpp); random.seed(31); bad=collections.Counter(); tot=0
    FG={8:0x0b,16:0x0b0c,32:0x0b0c0d0e}[bpp]; BG={8:0x0d,16:0x0d0e,32:0x0d0e0f10}[bpp]
    rep={8:lambda x:x*0x01010101,16:lambda x:x*0x00010001,32:lambda x:x}[bpp]
    for it in range(150):
        n=random.randint(2,4) if not seg else random.randint(1,3)
        pts=[]
        if seg:
            for i in range(n): pts+=[(random.randint(-6,70),random.randint(-6,70)),(random.randint(-6,70),random.randint(-6,70))]
        else: pts=[(random.randint(-6,70),random.randint(-6,70)) for _ in range(n)]
        if random.random()<.2 and not seg and n>2: pts[-1]=pts[0]
        clip=[(random.randint(0,20),random.randint(0,20),random.randint(40,64),random.randint(40,64))] if random.random()<.5 else [(5,5,30,20),(40,5,60,20),(10,20,50,40),(5,45,25,60)]
        dl=[random.randint(1,6) for _ in range(random.choice([2,2,4]))]
        off=random.randint(0,20); double=random.random()<.5; cap=random.choice([0,1])
        mode=0
        bz=random.choice([0,0xff,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
        try: got=rund(v,fn,pts,clip,dl,off,double,cap=cap,seg=seg,col=rep(FG),bgp=rep(BG) if bpp<32 else BG)
        except Halt as e: print(name,'HALT',e); break
        exp=dashed(pts,clip,cap,dl,off,double,segments=seg); tot+=1
        want={p:(FG if t=='F' else BG) for p,t in exp.items()}
        if got!=want:
            bad['x']+=1
            if bad['x']<3: print(name,'mismatch',pts,clip,dl,off,double,cap,sorted(set(got.items())^set(want.items()))[:6])
    print(name,tot,dict(bad))
