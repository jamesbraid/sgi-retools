# cfb{,16,32}DoBitblt{Copy,General,Or,Xor}: region copy between pixmaps or windows, same-drawable overlap order, merge rops
exec(open("h2.py").read())
import os
A={('Copy',8):0x45e7f0,('Copy',16):0x4ac3a0,('Copy',32):0x4326e0,
   ('General',8):0x4afba0,('General',16):0x4ae330,('General',32):0x4ad5d0,
   ('Or',8):0x4b1df0,('Or',16):0x4b2fb0,('Or',32):0x4b1400,
   ('Xor',8):0x4b5340,('Xor',16):0x4b4180,('Xor',32):0x4b64f0}
def rop(alu,s,d):
    return [0,s&d,s&~d,s,~s&d,d,s^d,s|d,~(s|d),~(s^d),~d,s|~d,~s,~s|d,~(s&d),-1][alu]
def mkdraw(c,kind,pitch,data,bpp=8):
    D=c.alloc(64); c.put(D,bytes(64))
    if kind=='pixmap':
        c.w8(D,1); c.w32(D+28,pitch); c.w32(D+32,data)
    else:
        S=c.alloc(512); P=c.alloc(64); c.w8(D,0); c.w32(D+16,S); c.w32(S+116,P)
        if bpp>8:
            ARR=c.alloc(64); c.w32(S+436,ARR); c.w32(ARR+4*3,P)
        c.w32(P+28,pitch); c.w32(P+32,data)
    return D
def mkregion(c,boxes,use_data=True):
    R=c.alloc(32); c.put(R,bytes(32))
    xs1=min(b[0] for b in boxes);ys1=min(b[1] for b in boxes);xs2=max(b[2] for b in boxes);ys2=max(b[3] for b in boxes)
    c.put(R,struct.pack('>hhhh',xs1,ys1,xs2,ys2))
    if len(boxes)==1 and not use_data: c.w32(R+8,0); return R
    d=c.alloc(8+8*len(boxes)); c.w32(d,len(boxes)); c.w32(d+4,len(boxes))
    for i,b in enumerate(boxes): c.put(d+8+8*i,struct.pack('>hhhh',*b))
    c.w32(R+8,d); return R
def bands(rng,W,H):
    boxes=[]; y=rng.randint(0,6)
    while y<H-2 and len(boxes)<8:
        h=rng.randint(1,12); y2=min(H,y+h); x=rng.randint(0,8)
        while x<W-1 and rng.random()<.8:
            w=rng.randint(1,24); x2=min(W,x+w); boxes.append((x,y,x2,y2)); x=x2+rng.randint(1,8)
        y=y2+rng.randint(0,5)
    return boxes
def one(kind,bpp,rng,W=64,H=40):
    c=CPU(); bs=bpp//8; pitch=W*bs; c.w32(0x5b0ea0-25904,3); c.w32(0x5b0ea0-25916,3)
    srcimg=bytearray(rng.getrandbits(8) for _ in range(pitch*H)); dstimg=bytearray(rng.getrandbits(8) for _ in range(pitch*H))
    same=rng.random()<.4
    sa=c.alloc(pitch*H+128)+64; c.put(sa,bytes(srcimg)); da=sa if same else c.alloc(pitch*H+128)+64   # pad: the shifted-word loops read a word before and after
    if not same: c.put(da,bytes(dstimg))
    sk=rng.choice(['pixmap','window']); dk=sk if same else rng.choice(['pixmap','window'])
    Ds=mkdraw(c,sk,pitch,sa,bpp); Dd=Ds if same else mkdraw(c,dk,pitch,da,bpp)
    boxes=bands(rng,W,H)
    if not boxes: return None
    use_data=rng.random()<.8 or len(boxes)>1
    if len(boxes)==1 and not use_data: pass
    if same:
        dx,dy=rng.randint(-10,10),rng.randint(-8,8)
        boxes=[b for b in boxes if 0<=b[0]-dx and b[2]-dx<=W and 0<=b[1]-dy and b[3]-dy<=H]
        if not boxes: return None
        ppts=[(b[0]-dx,b[1]-dy) for b in boxes]
    else:
        ppts=[]
        for b in boxes:
            ppts.append((rng.randint(0,W-(b[2]-b[0])),rng.randint(0,H-(b[3]-b[1]))))
    R=mkregion(c,boxes,use_data or len(boxes)>1)
    pp=c.alloc(4*len(ppts)+8)
    for i,(x,y) in enumerate(ppts): c.put(pp+4*i,struct.pack('>hh',x,y))
    alu=rng.randrange(16) if kind=='General' else 3
    pm=rng.choice([0xffffffff,rng.getrandbits(32),0x0f0f0f0f&0xffffffff]) if kind!='Copy' else 0xffffffff
    # reference
    snap=bytes(srcimg); out=bytearray(snap if same else dstimg); m=(1<<bpp)-1
    pmm=pm&m if bpp<32 else pm
    if bpp==8: pmm=pm&0xff
    for b,(sx,sy) in zip(boxes,ppts):
        for yy in range(b[3]-b[1]):
            for xx in range(b[2]-b[0]):
                so=((sy+yy)*W+sx+xx)*bs; do=((b[1]+yy)*W+b[0]+xx)*bs
                s=int.from_bytes(snap[so:so+bs],'big'); d=int.from_bytes(out[do:do+bs],'big')
                if kind=='Copy': n=s
                elif kind=='Or': n=(d|s)
                elif kind=='Xor': n=(d^s)
                else: n=(d&~pmm)|(rop(alu,s,d)&pmm&m)
                out[do:do+bs]=(n&m).to_bytes(bs,'big') if n is not None else b'\0'*bs
    try:
        c.call(A[(kind,bpp)],[Ds,Dd,alu,R,pp,pm])
    except Halt as e: return ('halt',str(e),sk,dk,alu,hex(pm),boxes,ppts,same)
    got=c.bytes(da,pitch*H)
    ok=(got==bytes(out))
    return ('ok' if ok else 'BAD',len(boxes),same,sk,dk,alu,hex(pm),boxes[:3],ppts[:3])
if __name__=='__main__':
    NIT=int(os.environ.get('NIT','150'))
    for key in sorted(A):
        rng=random.Random(3); cnt=collections.Counter(); ex=[]
        for it in range(NIT):
            r=one(key[0],key[1],rng)
            if r is None: continue
            cnt[(r[0],r[2] if r[0]!='halt' else None)]+=1
            if r[0]!='ok' and len(ex)<2: ex.append(r)
        print(key,dict(cnt)); [print('   ',e) for e in ex]
