# the six cfb*FillPoly1Rect{Copy,General} routines: shape/mode/clip tests, tail call to the generic filler, exact pixels
exec(open("lt.py").read())
from fractions import Fraction as Fr
import math, os
class Tail(Halt): pass
FN={('Copy',8):0x44cb60,('Copy',16):0x4ddb90,('Copy',32):0x4dcc50,('General',8):0x4dfaf0,('General',16):0x4e1260,('General',32):0x4dec00}
MIFILL=0x4472f0
def hull(pts):
    pts=sorted(set(pts))
    if len(pts)<3: return pts
    def cr(o,a,b): return (a[0]-o[0])*(b[1]-o[1])-(a[1]-o[1])*(b[0]-o[0])
    lo=[]
    for p in pts:
        while len(lo)>=2 and cr(lo[-2],lo[-1],p)<=0: lo.pop()
        lo.append(p)
    up=[]
    for p in reversed(pts):
        while len(up)>=2 and cr(up[-2],up[-1],p)<=0: up.pop()
        up.append(p)
    return lo[:-1]+up[:-1]
def ceilfr(f): return -((-f.numerator)//f.denominator)
def raster(pts):
    """sample point of pixel (x,y) is the integer point (x,y); rows y in [top,bottom), spans [ceil(xl),ceil(xr)). <=2 crossings per row assumed."""
    out=set(); n=len(pts)
    if n<3: return out
    ys=[p[1] for p in pts]
    for y in range(min(ys),max(ys)):
        yc=Fr(y); xs=[]
        for i in range(n):
            a,b=pts[i],pts[(i+1)%n]
            if a[1]==b[1]: continue
            lo,hi=(a,b) if a[1]<b[1] else (b,a)
            if lo[1]<=yc<hi[1]:
                xs.append(lo[0]+Fr(hi[0]-lo[0])*(yc-lo[1])/(hi[1]-lo[1]))
        if len(xs)<2: continue
        assert len(xs)==2,xs
        xl,xr=min(xs),max(xs)
        for x in range(ceilfr(xl),ceilfr(xr)): out.add((x,y))
    return out
def dirchanges(pts):
    """reversal count the routine uses for a non-convex shape: y-direction changes between successive
    non-horizontal edges, plus the wrap edge (last to first vertex) which counts as 'up' when the first
    vertex is higher than the last and as 'down' otherwise, even when the two rows are equal"""
    n=len(pts); d=[]
    for i in range(n-1):
        a,b=pts[i],pts[i+1]
        if a[1]!=b[1]: d.append(-1 if b[1]<a[1] else 0)
    if not d: return None
    w=-1 if pts[0][1]<pts[-1][1] else 0
    seq=d+[w]
    return sum(1 for i in range(len(seq)) if seq[i]!=seq[i-1])
def run1(kind,bpp,shape,mode,pts,box,ox,oy,xorw,andw,pixmap=False):
    v=mk(bpp); c=v.c; fn=FN[(kind,bpp)]
    bs=bpp//8
    rnd=random.Random(1); base=bytes(rnd.getrandbits(8) for _ in range(v.pitch*v.H+64)); c.put(v.fb,base)
    v.setclip([box])
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,3 if kind=='Copy' else 6); c.w32(v.G+12,xorw); c.w32(v.G+16,andw)
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    if pixmap:
        c.w8(v.D,1); c.w32(v.D+28,v.pitch); c.w32(v.D+32,v.fb); c.put(v.D+12,struct.pack('>HH',v.W,v.H))
    pp=c.alloc(4*len(pts)+16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    def tail(s): raise Tail(('tail',s.r[25],[s.r[4+i] for i in range(6)]))
    c.hooks[MIFILL]=tail
    try:
        c.call(fn,[v.D,v.GC,shape,mode,len(pts),pp]); res=('fill',)
    except Tail as e: res=e.args[0]
    except Halt as e: res=('halt',str(e))
    return res,v.img(),base[:v.pitch*v.H],(v.D,v.GC,pp)
def rep(val,bpp): return {8:val*0x01010101,16:val*0x00010001,32:val}[bpp]&0xffffffff
def expect(kind,bpp,img,pix,xorw,andw,W):
    bs=bpp//8; b=bytearray(img); m=(1<<bpp)-1
    for (x,y) in pix:
        o=(y*W+x)*bs; old=int.from_bytes(b[o:o+bs],'big')
        new=(xorw&m) if kind=='Copy' else ((old&andw)^xorw)&m
        b[o:o+bs]=new.to_bytes(bs,'big')
    return bytes(b)
if __name__=='__main__':
    random.seed(11); NIT=int(os.environ.get('NIT','400'))
    for (kind,bpp) in sorted(FN):
        stats=collections.Counter(); bad=0
        for it in range(NIT):
            shape=random.choice([2,2,1,1,0,0]); mode=random.choice([0,0,0,1])
            k=random.choice([3,4,5,8,12])
            lo,hi=(-12,76) if random.random()<.25 else (10,50)
            pts=hull([(random.randint(lo,hi),random.randint(lo,hi)) for _ in range(k)])
            if shape!=2 and random.random()<.6: pts=[(random.randint(lo,hi),random.randint(lo,hi)) for _ in range(random.choice([3,4,5,6,7]))]
            if random.random()<.3 and len(pts)>=3: pts=pts[::-1]
            if pts and random.random()<.5: r=random.randrange(len(pts)); pts=pts[r:]+pts[:r]
            if pts and random.random()<.15: pts=pts+[pts[0]]   # closing point repeated
            if random.random()<.1: pts=pts[:random.randint(0,2)]
            ox,oy=random.randint(-3,3),random.randint(-3,3)
            box=(random.randint(0,12),random.randint(0,12),random.randint(52,64),random.randint(52,64))
            if random.random()<.3 and pts:
                # shrink the box around the polygon so the edge cases at the clip border show
                xs=[p[0]+ox for p in pts]; ys=[p[1]+oy for p in pts]
                box=(min(xs)-random.randint(0,1),min(ys)-random.randint(0,1),max(xs)+1+random.randint(-1,1),max(ys)+1+random.randint(-1,1))
                box=(max(box[0],0),max(box[1],0),min(box[2],64),min(box[3],64))
            xorw=rep(random.randint(1,255) if bpp==8 else random.getrandbits(bpp),bpp); andw=rep(random.getrandbits(bpp),bpp)
            pixmap=random.random()<.2
            res,img,base,_=run1(kind,bpp,shape,mode,pts,box,ox,oy,xorw,andw,pixmap)
            inbox=all(box[0]<=x+ox<box[2] and box[1]<=y+oy<box[3] for x,y in pts)
            nd=dirchanges(pts)
            # prediction
            if mode==1 or not inbox or (shape!=2 and nd!=2): want='tail'   # nd None: all rows equal
            else: want='fill'
            if len(pts)<3: stats[('n<3',got_ := res[0])]+=1; continue
            got=res[0]
            stats[(want,got)]+=1
            if got=='tail':
                if res[1]!=MIFILL or res[2][2:5]!=[shape,mode,len(pts)] or res[2][0]!=_[0] or res[2][1]!=_[1] or res[2][5]!=_[2]: bad+=1; print('tail target/args differ',res)
                if img!=base: bad+=1; print('tail but pixels changed')
            if got!=want:
                bad+=1
                if bad<6: print(kind,bpp,'predict',want,'got',got,'shape',shape,'mode',mode,'nd',nd,'inbox',inbox,pts,box,(ox,oy))
                continue
            if got=='fill':
                try: pix={(x+ox,y+oy) for x,y in raster(pts)}
                except AssertionError: bad+=1; print('filled a row with >2 crossings',pts); continue
                if img!=expect(kind,bpp,base,pix,xorw,andw,64):
                    bad+=1
                    if bad<6:
                        e=expect(kind,bpp,base,pix,xorw,andw,64); bs=bpp//8
                        dif=[((i//bs)%64,(i//bs)//64) for i in range(0,len(e),bs) if e[i:i+bs]!=img[i:i+bs]]
                        print(kind,bpp,'PIXELS differ',shape,pts,box,(ox,oy),'pixmap',pixmap,len(dif),dif[:8])
        print(kind,bpp,'bad',bad,dict(stats))
