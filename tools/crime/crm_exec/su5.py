exec(open("su1.py").read().split("\nif __name__")[0])
FN=int(os.environ['FN'],0); bpp=int(os.environ.get('BPP','8')); m=(1<<bpp)-1
def row_ok(W,Hh,off_y,off_x,y=5):
    rng=random.Random(W*100+Hh)
    rows=[[rng.getrandbits(1) for _ in range(W)] for _ in range(Hh)]
    v=mk(bpp); c=v.c; v.setclip([(0,0,64,64)])
    ST=c.alloc(64); SD=c.alloc(128); c.w8(ST,1); c.put(ST+12,struct.pack('>HH',W,Hh)); pitch=((W+31)//32)*4; c.w32(ST+28,pitch); c.w32(ST+32,SD)
    for r in range(Hh):
        for xx in range(W):
            if rows[r][xx]:
                o=SD+r*pitch+(xx//32)*4; c.w32(o,c.r32(o)|(1<<(31-xx%32)))
    c.w8(v.GC+5,3); c.w32(v.GC+20,0xffffffff); c.w32(v.GC+24,0x3a&m); c.w32(v.GC+28,0x45&m); c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack('>hh',off_x,off_y)); c.w32(v.GC+16,3<<24)
    img=run(v,FN,[(0,y,40)],1); bs=bpp//8
    exp=[ (0x3a if rows[(y-off_y)%Hh][(x-off_x)%W] else 0x45)&m for x in range(40)]
    got=[int.from_bytes(img[(y*64+x)*bs:(y*64+x)*bs+bs],'big') for x in range(40)]
    return got==exp
bad=collections.defaultdict(list)
for Hh in range(1,10):
    for off in range(-45,46):
        if not row_ok(int(os.environ.get('W','3')),Hh,off,int(os.environ.get('OX','0'))): bad[Hh].append(off)
for Hh,l in bad.items(): print('H',Hh,'bad y-offsets',l[:12],'..',len(l))
print('y-offset sweep done; bad heights:',sorted(bad))
