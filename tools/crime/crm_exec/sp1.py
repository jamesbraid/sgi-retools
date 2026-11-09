# FillSpans-style stipple routines: spans clipped to the composite clip, rotated 32-bit-wide stipple, fg/bg/alu/planemask
exec(open("lt.py").read())
import os
def setup(bpp,clip,ox,oy,H,words,fg,bg,alu,pm,xorw=None,andw=None):
    v=mk(bpp); c=v.c
    v.setclip(clip); c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    ST=c.alloc(64); SD=c.alloc(4*H+16)
    c.w32(v.G+4,ST); c.put(ST+12,struct.pack('>HH',32,H)); c.w32(ST+28,4); c.w32(ST+32,SD); c.w8(ST,1)
    for i,w in enumerate(words): c.w32(SD+4*i,w)
    c.w8(v.GC+5,alu); c.w32(v.GC+20,pm); c.w32(v.GC+24,fg); c.w32(v.GC+28,bg)
    if xorw is not None: c.w32(v.G+12,xorw); c.w32(v.G+16,andw)
    return v
def run(v,fn,spans,fs=1):
    c=v.c; n=len(spans)
    pts=c.alloc(4*n+8); wd=c.alloc(4*n+8)
    for i,(x,y,w) in enumerate(spans): c.put(pts+4*i,struct.pack('>hh',x,y)); c.w32(wd+4*i,w)
    c.call(fn,[v.D,v.GC,n,pts,wd,fs])
    return v.img()
if __name__=='__main__':
    FN=int(os.environ.get('FN','0x4c2590'),0)
    rng=random.Random(2)
    words=[rng.getrandbits(32) for _ in range(4)]
    for (ox,oy) in [(0,0),(3,5)]:
        v=setup(8,[(0,0,64,64)],ox,oy,4,words,0x0b,0x0d,3,0xffffffff)
        img=run(v,FN,[(3,5,32)])
        # print the pixels row
        row=[(x,y,img[y*64+x]) for y in range(64) for x in range(64) if img[y*64+x]]
        ys=sorted({r[1] for r in row}); print('origin',(ox,oy),'rows',ys,'n',len(row))
        for y in ys:
            bits=''.join('1' if img[y*64+x]==0x0b else ('b' if img[y*64+x]==0x0d else '.') for x in range(3,3+32))
            print(y,bits)
        for i,w in enumerate(words): print('word',i,format(w,'032b'))
    v=setup(8,[(0,0,64,64)],0,0,4,words,0x0b,0x0d,3,0xffffffff)
    img=run(v,FN,[(3,5,32)])
    print([(x,hex(img[5*64+x])) for x in range(64) if img[5*64+x]])
    print(format(words[1],'032b'),format(words[5%4],'032b'))
