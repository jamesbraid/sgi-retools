# generic line/segment tester
from h2 import *
from ref2 import *
import random
def mk(bpp,W=64,H=64):
    v=Env(bpp=bpp,W=W,H=H); return v
def px_of(v,im):
    bs=v.bpp//8; W=v.W
    out={}
    for i in range(0,len(im),bs):
        val=int.from_bytes(im[i:i+bs],'big')
        if val: out[((i//bs)%W,(i//bs)//W)]=val
    return out
def run(v,fn,pts,clip,mode=0,cap=1,rop=3,seg=False,col=0x0b0b0b0b,andv=0,dashes=None,dashoff=0,linestyle=0,bgcol=None,planemask=None):
    c=v.c; v.clear(); v.setclip(clip)
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R)
    c.w8(v.G,rop); c.w32(v.G+12,col); c.w32(v.G+16,andv)
    c.w32(v.GC+16,cap<<28)
    pp=c.alloc(4*len(pts)+16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    c.call(fn,[v.D,v.GC,mode,len(pts)//(2 if seg else 1),pp] if not seg else [v.D,v.GC,len(pts)//2,pp])
    return px_of(v,v.img())
