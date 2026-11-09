# the three cfb*LineSS1RectPreviousCopy routines: running-position contract
# in:  *x1p,*y1p = current point (drawable coords); pptInit[1..npt-1] = displacements; pptInit[0] unused
# out: on an early exit x1p,y1p = last point inside, x2p,y2p = the point outside, return = its index;
#      when every point fits the routine returns -1 and writes no pointer
exec(open("r6.py").read().split("\nif __name__==")[0])
F={8:0x4990c0,16:0x498ac0,32:0x4984d0}
def runp(fn,start,deltas,box,cap,ox=0,oy=0,col=0x0b0b0b0b,junk0=(0x7777,0x6666)):
    v.clear(); v.setclip([box])
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,3); c.w32(v.G+12,col); c.w32(v.G+16,0); c.w32(v.GC+16,cap<<28)
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    pts=[junk0]+deltas
    pp=c.alloc(4*len(pts)+16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    o=c.alloc(32)
    for i in range(4): c.w32(o+4*i,0xdead0000+i)
    c.w32(o,start[0]&0xffffffff); c.w32(o+4,start[1]&0xffffffff)
    c.put(c.sp0,bytes(32)); c.wr(c.sp0,8,o+8); c.wr(c.sp0+8,8,o+12)
    ret=c.call(fn,[v.D,v.GC,1,len(pts),pp,pp,o,o+4])
    ret=ret&0xffffffff; ret=ret-(1<<32) if ret>=1<<31 else ret
    s=lambda x:x-(1<<32) if x>=1<<31 else x
    return ret,[s(c.r32(o+4*i)) for i in range(4)],px_of(v,v.img())
def refp(start,deltas,box,cap,ox,oy):
    ab=[start]
    for d in deltas: ab.append((ab[-1][0]+d[0],ab[-1][1]+d[1]))
    pa=[(x+ox,y+oy) for x,y in ab]
    ins=lambda p: box[0]<=p[0]<box[2] and box[1]<=p[1]<box[3]
    if not ins(pa[0]): return 1,[start,ab[1]],[]
    out=[]
    for k in range(1,len(pa)):
        if not ins(pa[k]): return k,[ab[k-1],ab[k]],out
        if pa[k-1]!=pa[k]: out+=lp(pa[k-1],pa[k])[:-1]
    if cap and (pa[-1]!=pa[0] or len(pa)==2): out.append(pa[-1])
    return -1,None,out
if __name__=='__main__':
    random.seed(5)
    for bpp in (8,16,32):
        v=mk(bpp); c=v.c; fn=F[bpp]
        pv={8:0x0b,16:0x0b0c,32:0x0b0c0d0e}[bpp]; col={8:0x0b0b0b0b,16:0x0b0c0b0c,32:0x0b0c0d0e}[bpp]
        bad=0; nret=0; N=300; badf=collections.Counter()
        for it in range(N):
            n=random.randint(2,6); cap=random.choice([0,1])
            pts=[(random.randint(-10,74),random.randint(-10,74)) for _ in range(n)]
            if random.random()<.5: pts=[(random.randint(8,56),random.randint(8,56)) for _ in range(n)]
            if random.random()<.2 and n>2: pts[-1]=pts[0]
            ox,oy=random.randint(-3,3),random.randint(-3,3)
            box=(random.randint(0,12),random.randint(0,12),random.randint(52,64),random.randint(52,64))
            bz=random.choice([0,255,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
            deltas=[(pts[i][0]-pts[i-1][0],pts[i][1]-pts[i-1][1]) for i in range(1,n)]
            ret,vals,got=runp(fn,pts[0],deltas,box,cap,ox,oy,col)
            rr,rv,px=refp(pts[0],deltas,box,cap,ox,oy)
            want={p:pv for p in px if 0<=p[0]<64 and 0<=p[1]<64}
            if rr!=-1: nret+=1
            f=[]
            if ret!=rr: f.append('ret')
            if got!=want: f.append('pix')
            want_ptrs=[pts[0][0],pts[0][1],0xdead0002-(1<<32),0xdead0003-(1<<32)] if rv is None else [rv[0][0],rv[0][1],rv[1][0],rv[1][1]]
            if vals!=want_ptrs: f.append('ptrs')
            if f:
                bad+=1; badf[tuple(f)]+=1
                if bad<4: print(bpp,'mismatch',f,pts,cap,box,(ox,oy),'ret',ret,'ref',rr,vals,rv)
        print(bpp,N,'bad',bad,dict(badf),'early-exits',nret)
