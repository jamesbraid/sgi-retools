exec(open("lt2.py").read())
def trace_reads(v,fn,call):
    c=v.c; R=collections.defaultdict(set)
    orig=c.rd
    def rd(a,n):
        for nm in ('G','GC','D','P','R','RD'):
            b=getattr(v,nm)
            if b<=a<b+256: R[nm].add((a-b,n))
        return orig(a,n)
    c.rd=rd
    call()
    c.rd=orig
    return {k:sorted(x) for k,x in R.items()}
def setup(v,rop=15,dash=[3,2],off=0,double=True,cap=1,pm=1,alu=3,bgp=0):
    c=v.c
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,rop)
    c.put(v.GC,bytes(80)); c.w32(v.GC+76,v.GCP); c.w8(v.GC+5,alu); c.w16(v.GC+8,off); c.w16(v.GC+10,len(dash))
    dp=c.alloc(len(dash)+8); c.put(dp,bytes(dash)); c.w32(v.GC+12,dp); c.w32(v.GC+16,((2 if double else 1)<<30)|(cap<<28)); c.w32(v.GC+20,pm); c.w32(v.GC+28,bgp)
v=Env(bpp=1,W=64,H=64,pitch=8)
v.setclip([(0,0,64,64)])
setup(v)
c=v.c
pp=c.alloc(16)
for i,(x,y) in enumerate([(5,5),(40,20)]): c.put(pp+4*i,struct.pack('>hh',x,y))
for name,fn,args in (('mfbLineSS',0x52f320,[v.D,v.GC,0,2,pp]),('mfbLineSD',0x52c380,[v.D,v.GC,0,2,pp])):
    for typ in (0,1):
        c.w8(v.D,typ)
        try: print(name,typ,trace_reads(v,fn,lambda:c.call(fn,args)))
        except Halt as e: print(name,typ,'HALT',e)
