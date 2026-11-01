exec(open("lt.py").read())
v=mk(8); c=v.c
def call1rect(fn,pts,clip,rop=3,mode=0,cap=1,col=0x0b0b0b0b,andv=0,orig=None):
    v.clear(); v.setclip([clip])
    c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,rop); c.w32(v.G+12,col); c.w32(v.G+16,andv); c.w32(v.GC+16,cap<<28)
    pp=c.alloc(4*len(pts)+16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    o=c.alloc(32)
    for i in range(4): c.w32(o+4*i,0xdead0000+i)
    # stack args at sp0 (x2p,y2p)
    sp=c.sp0
    c.w32(sp+0-0,0);  # placeholders (call sets sp = sp0) ; stack args are at sp+0 and sp+8 relative to caller sp
    return pp,o
def runit(fn,pts,clip,**kw):
    pp,o=call1rect(fn,pts,clip,**kw)
    c.put(c.sp0,bytes(32))
    # n32 stack args: 9th arg at sp+0, 10th at sp+8 (8-byte slots)
    c.wr(c.sp0,8,o+8); c.wr(c.sp0+8,8,o+12)
    ret=c.call(fn,[v.D,v.GC,kw.get('mode',0),len(pts),pp,pp,o,o+4])
    vals=[c.r32(o+4*i) for i in range(4)]
    return ret&0xffffffff,vals,px_of(v,v.img())
if __name__=='__main__':
    for pts in ([(10,10),(30,20),(40,5)],[(10,10),(100,20),(40,5)],[(10,10),(20,20),(100,30),(5,5)]):
        r=runit(0x49a460,pts,(0,0,64,64))
        print(pts,'ret',r[0],[hex(x) if x>1000 else x for x in r[1]],len(r[2]))
