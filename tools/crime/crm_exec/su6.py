exec(open("su1.py").read().split("\nif __name__")[0])
FN=0x4c5c10; bpp=8; m=255
def chk(rows,off_y,y,off_x=0,x0=0):
    W=2; Hh=len(rows)
    v=mk(bpp); c=v.c; v.setclip([(0,0,64,64)])
    ST=c.alloc(64); SD=c.alloc(128); c.w8(ST,1); c.put(ST+12,struct.pack('>HH',W,Hh)); c.w32(ST+28,4); c.w32(ST+32,SD)
    for r in range(Hh):
        o=SD+r*4; c.w32(o,sum(1<<(31-x) for x in range(W) if rows[r][x]))
    c.w8(v.GC+5,3); c.w32(v.GC+20,0xffffffff); c.w32(v.GC+24,0x3a); c.w32(v.GC+28,0x45); c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack('>hh',off_x,off_y)); c.w32(v.GC+16,3<<24)
    img=run(v,FN,[(x0,y,30)],1)
    exp=[0x3a if rows[(y-off_y)%Hh][(x-off_x)%W] else 0x45 for x in range(x0,x0+30)]
    return list(img[y*64+x0:y*64+x0+30])==exp
rng=random.Random(8); fails=[]
for t in range(120):
    Hh=7; rows=[[rng.getrandbits(1) for _ in range(2)] for _ in range(Hh)]
    for y in range(0,12):
        if not chk(rows,13,y,off_x=int(os.environ.get('PX','0')),x0=int(os.environ.get('X0','0'))): fails.append((rows,y,(y-13)%7)); break
print(len(fails),'of 120 patterns fail; sample',[(f[1],f[2],f[0]) for f in fails[:4]])
