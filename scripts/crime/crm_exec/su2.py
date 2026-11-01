exec(open("su1.py").read().split("\nif __name__")[0])
for W,rows in ((1,[[1]]),(1,[[0]]),(2,[[1,0]]),(1,[[1],[0]])):
  for opaque in (False,True):
    v=mk(8); c=v.c; Hh=len(rows); pitch=4
    v.setclip([(0,0,64,64)])
    ST=c.alloc(64); SD=c.alloc(64); c.w8(ST,1); c.put(ST+12,struct.pack('>HH',W,Hh)); c.w32(ST+28,pitch); c.w32(ST+32,SD)
    for r in range(Hh):
        for xx in range(W):
            if rows[r][xx]: o=SD+r*pitch; c.w32(o,c.r32(o)|(1<<(31-xx)))
    c.w8(v.GC+5,3); c.w32(v.GC+20,0xffffffff); c.w32(v.GC+24,0x0b); c.w32(v.GC+28,0x0d); c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack('>hh',0,0)); c.w32(v.GC+16,(3 if opaque else 2)<<24)
    bx=c.alloc(16); c.put(bx,struct.pack('>hhhh',2,2,10,4))
    c.call(0x4e7e20,[v.D,v.GC,1,bx]); img=v.img()
    print(W,rows,opaque,[hex(img[2*64+x]) for x in range(1,12)],[hex(img[3*64+x]) for x in range(1,12)])
