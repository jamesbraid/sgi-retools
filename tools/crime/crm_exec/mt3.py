exec(open("mt2.py").read().split("for rop in (0,15")[0])
import random
random.seed(41)
def put_bg(bg):
    v.clear(); im=bytearray(v.pitch*v.H+64)
    for (x,y) in bg:
        o=y*8+(x>>5)*4; w=int.from_bytes(im[o:o+4],'big')|(1<<(31-(x&31))); im[o:o+4]=w.to_bytes(4,'big')
    c.put(v.fb,bytes(im))
def runm2(fn,pts,clip,rop,bg,seg=False,mode=0,cap=1,**kw):
    v.setclip(clip); setup(v,rop=rop,cap=cap,**kw); put_bg(bg)
    pp=c.alloc(4*len(pts)+8)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    if seg: c.call(fn,[v.D,v.GC,len(pts)//2,pp])
    else: c.call(fn,[v.D,v.GC,mode,len(pts),pp])
    return bits(v)
def apply_rop(rop,bgset,px,allpix):
    out=set(bgset)
    for p in (px if rop==10 else set(px)):
        if rop==0: out.discard(p)
        elif rop==15: out.add(p)
        elif rop==10:
            if p in out: out.discard(p)
            else: out.add(p)
    return out
if __name__=='__main__' or True:
  for name,fn,seg in (('mfbLineSS',0x52f320,0),('mfbSegmentSS',0x53d180,1)):
    bad=0;tot=0
    for it in range(150):
        n=random.randint(1,4)
        pts=[]
        if seg:
            for i in range(n): pts+=[(random.randint(-6,70),random.randint(-6,70)),(random.randint(-6,70),random.randint(-6,70))]
        else:
            pts=[(random.randint(-6,70),random.randint(-6,70)) for _ in range(n+1)]
            if random.random()<.25 and n>1: pts[-1]=pts[0]
        clip=[(random.randint(0,20),random.randint(0,20),random.randint(40,64),random.randint(40,64))] if random.random()<.5 else [(5,5,30,20),(40,5,60,20),(10,20,50,40),(5,45,25,60)]
        cap=random.choice([0,1]); rop=random.choice([0,15,10,5]); bz=random.choice([0,0xff,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
        bg={(random.randint(0,63),random.randint(0,63)) for _ in range(300)}
        got=runm2(fn,pts,clip,rop,bg,seg=bool(seg),cap=cap)
        px=polyline_list(pts,clip,cap,segments=bool(seg))
        exp=apply_rop(rop,bg,px,None); tot+=1
        if got!=exp:
            bad+=1
            if bad<3: print(name,'mismatch',pts,clip,cap,rop,len(got^exp),sorted(got^exp)[:6])
    print(name,tot,'bad',bad)
