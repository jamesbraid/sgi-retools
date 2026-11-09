exec(open("lt2.py").read())
for bpp,fn,name,seg in [(8,0x4d32c0,'cfbLineSD',0),(8,0x4f1ce0,'cfbSegmentSD',1)]:
    v=mk(bpp); v.bias(0); BIAS[0]=0
    pts=[(2,5),(30,5)]
    for dl in ([3,2,1],[2],[5,1,1,1,1]):
        got=rund(v,fn,pts,[(0,0,64,64)],dl,0,True,col=0x0b0b0b0b,bgp=0x0d0d0d0d,seg=bool(seg))
        row=''.join({0x0b:'F',0x0d:'B'}.get(got.get((x,5)),'.') for x in range(2,31))
        print(name,dl,row)
# mode previous for LineSD
import random
random.seed(9); bad=0
for bpp,fn,name in [(8,0x4d32c0,'cfbLineSD'),(16,0x4cabf0,'cfb16LineSD'),(32,0x4d71b0,'cfb32LineSD')]:
    v=mk(bpp); FG={8:0x0b,16:0x0b0c,32:0x0b0c0d0e}[bpp]; BG={8:0x0d,16:0x0d0e,32:0x0d0e0f10}[bpp]
    rep={8:lambda x:x*0x01010101,16:lambda x:x*0x00010001,32:lambda x:x}[bpp]
    bad=0
    for it in range(60):
        pts=[(random.randint(-6,70),random.randint(-6,70)) for _ in range(random.randint(2,5))]
        p2=[pts[0]]+[(pts[i][0]-pts[i-1][0],pts[i][1]-pts[i-1][1]) for i in range(1,len(pts))]
        dl=[random.randint(1,5) for _ in range(2)]; off=random.randint(0,9); clip=[(3,3,60,50)]
        got=rund(v,fn,p2,clip,dl,off,True,mode=1,cap=1,col=rep(FG),bgp=rep(BG) if bpp<32 else BG)
        exp=dashed(pts,clip,1,dl,off,True)
        want={p:(FG if t=='F' else BG) for p,t in exp.items()}
        bad+= got!=want
    print(name,'mode1 bad',bad,'of 60')
