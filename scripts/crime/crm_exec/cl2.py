exec(open("cl1.py").read().split("random.seed(12)")[0])
random.seed(2)
for bpp in (8,16,32):
    v=mk(bpp); bs=bpp//8; c=v.c
    for kind in ('Copy','General','Xor'):
        fn=FN[bpp][kind]
        # negative index
        v.bias(0)
        c.w32(GP-26136,0xffffffff)
        a=clipped(v,fn,5,5,40,20,(0,0,64,64),0,xorw=0x0b0b0b0b)
        c.w32(GP-26136,1)
        b=clipped(v,fn,5,5,40,20,(0,0,64,64),0,xorw=0x0b0b0b0b)
        # pixmap drawable
        c.w8(v.D,1); c.w32(v.D+28,v.pitch); c.w32(v.D+32,v.fb)
        d=clipped(v,fn,5,5,40,20,(0,0,64,64),0,xorw=0x0b0b0b0b)
        c.w8(v.D,0)
        print(bpp,kind,'negative index same as bias 0:',a==b,'pixels',sum(1 for x in a if x),'| pixmap-type same:',d==b)
