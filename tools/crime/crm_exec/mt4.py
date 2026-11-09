exec(open("mt3.py").read().split("if __name__")[0])
from ref3 import *
GX=[lambda s,d:0,lambda s,d:s&d,lambda s,d:s&~d,lambda s,d:s,lambda s,d:~s&d,lambda s,d:d,lambda s,d:s^d,lambda s,d:s|d,lambda s,d:~(s|d),lambda s,d:~(s^d),lambda s,d:~d,lambda s,d:s|~d,lambda s,d:~s,lambda s,d:~s|d,lambda s,d:~(s&d),lambda s,d:~0]
random.seed(77)
for name,fn,seg in (('mfbLineSD',0x52c380,0),('mfbSegmentSD',0x53a890,1)):
    bad=0;tot=0;BADS=collections.Counter()
    for it in range(250):
        n=random.randint(1,3)
        if seg:
            pts=[]
            for i in range(n): pts+=[(random.randint(-6,70),random.randint(-6,70)),(random.randint(-6,70),random.randint(-6,70))]
        else:
            pts=[(random.randint(-6,70),random.randint(-6,70)) for _ in range(n+1)]
        clip=[(random.randint(0,20),random.randint(0,20),random.randint(40,64),random.randint(40,64))] if random.random()<.5 else [(5,5,30,20),(40,5,60,20),(10,20,50,40),(5,45,25,60)]
        cap=random.choice([0,1]); rop=random.choice([0,15,10,5]); alu=random.randrange(16); bgp=random.choice([0,1]); pm=random.choice([1,1,1,0,3])
        dl=[random.randint(1,6) for _ in range(random.choice([2,2,4]))]; off=random.randint(0,20); double=random.random()<.5
        bz=random.choice([0,0xff,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
        bg={(random.randint(0,63),random.randint(0,63)) for _ in range(300)}
        v.setclip(clip); setup(v,rop=rop,dash=dl,off=off,double=double,cap=cap,pm=pm,alu=alu,bgp=bgp); put_bg(bg)
        pp=c.alloc(4*len(pts)+8)
        for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
        if seg: c.call(fn,[v.D,v.GC,len(pts)//2,pp])
        else: c.call(fn,[v.D,v.GC,0,len(pts),pp])
        got=bits(v)
        out=set(bg)
        if pm&1:
            for p,t in dashed_list(pts,clip,cap,dl,off,double,segments=bool(seg)):
                d=1 if p in out else 0
                if t=='F':
                    r={0:0,15:1,10:1-d,5:d}[rop]
                else: r=GX[alu](bgp,d)&1
                if r: out.add(p)
                else: out.discard(p)
        tot+=1
        if got!=out:
            bad+=1; BADS[(alu,pm,double)]+=1
            if bad<4: print(name,pts,clip,dl,off,cap,'mismatch rop',rop,'alu',alu,'bgp',bgp,'pm',pm,'dbl',double,'n',len(got^out),sorted(got^out)[:5])
    print(name,tot,'bad',bad,dict(list(BADS.items())[:8]))
