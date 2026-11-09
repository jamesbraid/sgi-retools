exec(open("lt.py").read())
import collections
cfgs=[(8,0x468cf0,'cfbSegmentSS'),(16,0x4ec3d0,'cfb16SegmentSS'),(32,0x46c220,'cfb32SegmentSS')]
for bpp,fn,name in cfgs:
    v=mk(bpp); random.seed(21); bad=collections.Counter(); tot=0
    col={8:0x0b0b0b0b,16:0x0b0c0b0c,32:0x0b0c0d0e}[bpp]; pv={8:0x0b,16:0x0b0c,32:0x0b0c0d0e}[bpp]
    for it in range(150):
        n=random.randint(1,5)
        pts=[]
        for i in range(n):
            pts+= [(random.randint(-6,70),random.randint(-6,70)),(random.randint(-6,70),random.randint(-6,70))]
        if random.random()<.2: pts[1]=pts[0]
        clip=[(random.randint(0,20),random.randint(0,20),random.randint(40,64),random.randint(40,64))] if random.random()<.5 else [(5,5,30,20),(40,5,60,20),(10,20,50,40),(5,45,25,60)]
        cap=random.choice([0,1]); bz=random.choice([0,0xff,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
        try: got=run(v,fn,pts,clip,cap=cap,col=col,seg=True)
        except Halt as e: print(name,'HALT',e); break
        exp=set()
        for i in range(0,len(pts),2):
            exp|=polyline([pts[i],pts[i+1]],clip,cap,segments=False) if pts[i]!=pts[i+1] else (set([pts[i]]) if (cap and inclip(pts[i],clip)) else set())
        want={p:pv for p in exp}; tot+=1
        if got!=want:
            bad['x']+=1
            if bad['x']<3: print(name,'mismatch',pts,clip,cap,list(set(got.items())^set(want.items()))[:6])
    print(name,tot,dict(bad))
