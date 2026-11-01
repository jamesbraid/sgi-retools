exec(open("sp3.py").read().split("\nif __name__")[0])
FN=0x4c2590
for alu in (12,15,10,3):
    rng=random.Random(9); H=2; words=[0xaaaaaaaa,0x55555555]
    clip=[(0,0,64,64)]; fg,bg=0x0b,0x0d
    v=setup(8,clip,0,0,H,words,fg,bg,alu,0xffffffff,0x0b0b0b0b,0)
    base=bytes([0x21])*(64*64); v.c.put(v.fb,base)
    img=run(v,FN,[(0,0,12),(0,1,12)])
    want=model(8,base,[(0,0,12),(0,1,12)],clip,words,H,fg,bg,alu,0xffffffff,False)
    print(alu,[hex(x) for x in img[0:12]],[hex(x) for x in want[0:12]])
    print('  ',[hex(x) for x in img[64:76]],[hex(x) for x in want[64:76]])
