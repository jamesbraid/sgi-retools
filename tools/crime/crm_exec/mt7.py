exec(open("mt4.py").read().split("random.seed(77)")[0])
orig=CPU.exec
INFO=[]
def ex(s,w,pc):
    if (w>>26)==0 and (w&63)==9 and s.r[(w>>21)&31]==0x57a2e0: INFO.append([s.r[i]&0xffffffff for i in range(4,12)])
    return orig(s,w,pc)
CPU.exec=ex
random.seed(5)
found=0
for it in range(400):
    n=random.randint(1,3)
    pts=[(random.randint(-6,70),random.randint(-6,70)) for _ in range(n+1)]
    clip=[(5,5,30,20),(40,5,60,20),(10,20,50,40),(5,45,25,60)] if random.random()<.5 else [(random.randint(0,20),random.randint(0,20),random.randint(40,64),random.randint(40,64))]
    v.setclip(clip); setup(v,rop=15); put_bg(set())
    pp=c.alloc(4*len(pts)+8)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    INFO.clear(); c.call(0x52f320,[v.D,v.GC,0,len(pts),pp])
    if INFO and found<4:
        found+=1; print(pts,clip,[[hex(x) for x in i[:8]] for i in INFO][:1])
# negative index
for name,fn,seg in (('mfbLineSS',0x52f320,0),('mfbSegmentSS',0x53d180,1),('mfbLineSD',0x52c380,0),('mfbSegmentSD',0x53a890,1)):
    out=[]
    for idx in (1,-1):
        c.w32(GP-26136,idx&0xffffffff); v.bias(0)
        v.setclip([(0,0,64,64)]); setup(v,rop=15,dash=[3,2],off=0,double=False); put_bg(set())
        pp=c.alloc(16)
        for i,(x,y) in enumerate([(5,5),(30,12)]): c.put(pp+4*i,struct.pack('>hh',x,y))
        if seg: c.call(fn,[v.D,v.GC,1,pp])
        else: c.call(fn,[v.D,v.GC,0,2,pp])
        out.append(sorted(bits(v)))
    print(name,'negative index same as bias 0:',out[0]==out[1],len(out[1]))
print('--- when is mfbBresS called')
random.seed(9)
stat=collections.Counter()
for it in range(600):
    a=(random.randint(-8,72),random.randint(-8,72)); b=(random.randint(-8,72),random.randint(-8,72))
    clip=[(10,10,50,50)]
    v.setclip(clip); setup(v,rop=15); put_bg(set())
    c.w32(GP-26136,1)
    pts=[a,b]; pp=c.alloc(16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    INFO.clear(); c.call(0x52f320,[v.D,v.GC,0,2,pp])
    inside=all(10<=p[0]<50 and 10<=p[1]<50 for p in pts)
    dx=abs(b[0]-a[0]);dy=abs(b[1]-a[1])
    kind='horiz' if dy==0 else 'vert' if dx==0 else 'diag' if dx==dy else 'slope'
    stat[(kind,'inside' if inside else 'clipped',bool(INFO))]+=1
for k in sorted(stat): print(k,stat[k])
