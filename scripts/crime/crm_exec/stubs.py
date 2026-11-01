# stand-ins for imported library routines, which the file leaves unrelocated
def install_ffs(c,gotoff=-0x6f3c):
    """C library ffs(): index of the lowest set bit counting from 1, 0 for zero. Stored in the import slot gp+gotoff."""
    a=c.alloc(16); c.w32(a,0x03e00008); c.w32(a+4,0)
    def ffs(s):
        x=s.r[4]&0xffffffff; s.r[2]=(x&-x).bit_length() if x else 0
        ffs.args.append(x)
    ffs.args=[]
    c.hooks[a]=ffs; c.w32(0x5b0ea0+gotoff,a); return ffs
def install_pad(c,gotoff=-0x717c):
    """the width-padding table (one 12-byte record per depth: pixels per 32-bit pad unit minus one, log2 of pixels per pad unit, log2 of bytes per pad unit), an import the file leaves unrelocated"""
    t=c.alloc(12*40)
    for d in range(40):
        bpp=8 if d<=8 else 16 if d<=16 else 32
        pu=32//bpp; lg={1:0,2:1,4:2}[pu]
        c.w32(t+12*d,pu-1); c.w32(t+12*d+4,lg); c.w32(t+12*d+8,2)
    c.w32(0x5b0ea0+gotoff,t); return t
