exec(open("pp1.py").read().split("\nif __name__")[0])
for bpp in (8,16,32):
    rng=random.Random(2); args=collections.Counter()
    for it in range(80):
        W=64; v=Env(bpp=bpp,W=W,H=64); c=v.c; ffs=install_ffs(c); v.setclip([(0,0,64,64)])
        c.put(v.G,bytes(256)); c.w32(v.G+8,v.R); c.w8(v.G,rng.choice([3,6])); pp=c.alloc(16); c.put(pp,struct.pack('>hhhh',3,4,5,6))
        c.call(FN[bpp],[v.D,v.GC,0,2,pp]); args.update(ffs.args)
    print(bpp,dict(args),'pitch',v.pitch)
