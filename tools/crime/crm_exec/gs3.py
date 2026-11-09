exec(open("gs1.py").read().split("\nif __name__")[0])
for bpp in (8,16,32):
    rng=random.Random(4); pads=set()
    for it in range(60):
        r=trial(bpp,rng,'pixmap'); pads|=r[1][2]
    print(bpp,pads)
