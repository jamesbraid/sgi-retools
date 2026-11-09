exec(open("r1.py").read().split("if __name__")[0])
from ref2 import *
def ref1rect(pts_abs,box,cap):
    """pts_abs: absolute drawable-coord points; box in same coords (x1,y1,x2,y2). returns (ret,pixels)"""
    def ins(p): return box[0]<=p[0]<box[2] and box[1]<=p[1]<box[3]
    n=len(pts_abs)
    if not ins(pts_abs[0]): return 1,[]
    out=[]
    for k in range(1,n):
        if not ins(pts_abs[k]): return k,out
        out+=lp(pts_abs[k-1],pts_abs[k])[:-1] if pts_abs[k-1]!=pts_abs[k] else []
    last=pts_abs[-1]
    if cap and (last!=pts_abs[0] or n==2): out.append(last)
    return -1,out
def runit2(fn,pts,box,mode,cap,rop=3,ox=0,oy=0,acc=(1000,2000),col=0x0b0b0b0b):
    v.clear(); v.setclip([box])
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,rop); c.w32(v.G+12,col); c.w32(v.G+16,0); c.w32(v.GC+16,cap<<28)
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    pp=c.alloc(4*len(pts)+16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    o=c.alloc(32)
    for i in range(4): c.w32(o+4*i,0xdead0000+i)
    c.w32(o+8,acc[0]); c.w32(o+12,acc[1])
    c.put(c.sp0,bytes(32)); c.wr(c.sp0,8,o+8); c.wr(c.sp0+8,8,o+12)
    ret=c.call(fn,[v.D,v.GC,mode,len(pts),pp,pp,o,o+4])
    ret=ret&0xffffffff; ret=ret-(1<<32) if ret>=1<<31 else ret
    return ret,[c.r32(o+4*i) for i in range(4)],px_of(v,v.img())
if __name__=='__main__':
    random.seed(7); bad=0
    for it in range(300):
        n=random.randint(2,5); mode=random.choice([0,1]); cap=random.choice([0,1])
        pts=[(random.randint(-10,74),random.randint(-10,74)) for _ in range(n)]
        if random.random()<.5: pts=[(random.randint(8,56),random.randint(8,56)) for _ in range(n)]
        if random.random()<.2 and n>2: pts[-1]=pts[0]
        ox,oy=random.randint(-3,3),random.randint(-3,3)
        box=(random.randint(0,12),random.randint(0,12),random.randint(52,64),random.randint(52,64))
        v.bias(0); BIAS[0]=0; bz=random.choice([0,255,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
        p2=pts if mode==0 else [pts[0]]+[(pts[i][0]-pts[i-1][0],pts[i][1]-pts[i-1][1]) for i in range(1,n)]
        ret,vals,got=runit2(0x49a460,p2,box,mode,cap,ox=ox,oy=oy)
        pa=[(x+ox,y+oy) for x,y in pts]
        rr,px=ref1rect(pa,(box[0],box[1],box[2],box[3]),cap)
        want={p:0x0b for p in px if 0<=p[0]<64 and 0<=p[1]<64}
        # accumulators in mode 1: x2p += relative dx of stopping point?
        if ret!=rr or got!=want:
            bad+=1
            if bad<5: print('mismatch',pts,mode,cap,box,(ox,oy),'ret',ret,'ref',rr,len(set(got.items())^set(want.items())),vals)
    print('bad',bad)
