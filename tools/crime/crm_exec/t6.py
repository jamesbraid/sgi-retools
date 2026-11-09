exec(open("lt.py").read())
import collections
for bpp,fn,name in ((8,0x4668b0,'cfbLineSS'),(16,0x4cea90,'cfb16LineSS'),(32,0x4d0f30,'cfb32LineSS')):
    v=mk(bpp); random.seed(11); bad=collections.Counter(); tot=0
    col={8:0x0b0b0b0b,16:0x0b0c0b0c,32:0x0b0c0d0e}[bpp]
    for it in range(120):
        n=random.randint(2,6)
        pts=[(random.randint(-6,70),random.randint(-6,70)) for _ in range(n)]
        if random.random()<0.25 and n>2: pts[-1]=pts[0]
        clip=[(random.randint(0,20),random.randint(0,20),random.randint(40,64),random.randint(40,64))] if random.random()<.5 else [(5,5,30,20),(40,5,60,20),(10,20,50,40),(5,45,25,60)]
        cap=random.choice([0,1]); mode=random.choice([0,1]); p2=pts
        if mode==1:
            p2=[pts[0]]+[(pts[i][0]-pts[i-1][0],pts[i][1]-pts[i-1][1]) for i in range(1,n)]
        bz=random.choice([0,0xff,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
        try: got=run(v,fn,p2,clip,mode=mode,cap=cap,col=col)
        except Halt as e: print(name,'HALT',e); break
        exp=polyline(pts,clip,cap); tot+=1
        want={p:{8:0x0b,16:0x0b0c,32:0x0b0c0d0e}[bpp] for p in exp}
        if got!=want:
            bad['x']+=1
            if bad['x']<3: print(name,'mismatch',pts,clip,cap,mode,list(set(got.items())^set(want.items()))[:6])
    print(name,tot,dict(bad))
