exec(open("sp1.py").read().split("\nif __name__")[0])
FN=int(os.environ.get('FN','0x4c2590'),0)
words=[0xf0f0f0f0]*4
for (fg,bg,xw) in ((0x0b,0x0d,None),(0x0b,0x0d,0x0b0b0b0b),(0x55,0x66,0x55555555)):
    v=setup(8,[(0,0,64,64)],0,0,4,words,fg,bg,3,0xffffffff,xw,0)
    img=run(v,FN,[(3,5,10)])
    print(hex(fg),hex(bg),[hex(img[5*64+x]) for x in range(2,14)])
