exec(open("bb1.py").read().split("\nif __name__")[0])
def order(kind,bpp,dx,dy,boxes,same=True,sk='pixmap'):
    c=CPU(); c.w32(0x5b0ea0-25904,3); c.w32(0x5b0ea0-25916,3)
    W,H=64,40; bs=bpp//8; pitch=W*bs
    sa=c.alloc(pitch*H+128)+64; rng=random.Random(1); c.put(sa,bytes(rng.getrandbits(8) for _ in range(pitch*H)))
    Ds=mkdraw(c,sk,pitch,sa,bpp)
    ppts=[(b[0]-dx,b[1]-dy) for b in boxes]
    R=mkregion(c,boxes); pp=c.alloc(64)
    for i,(x,y) in enumerate(ppts): c.put(pp+4*i,struct.pack('>hh',x,y))
    log=[]
    def w(a,n,v):
        if sa<=a<sa+pitch*H: log.append(((a-sa)//pitch,((a-sa)%pitch)//bs,n))
    c.watch=w
    c.call(A[(kind,bpp)],[Ds,Ds,3,R,pp,0xffffffff])
    rows=[]
    for r,x,n in log:
        if not rows or rows[-1]!=r: rows.append(r)
    # x order inside the first written row
    first=[x for r,x,n in log if r==rows[0]]
    return rows[:3],rows[-1],'x ascending' if first[0]<=first[-1] else 'x descending', len(rows)
for bpp in (8,16,32):
  for kind in ('Copy','General','Or'):
    print(bpp,kind,end=' ')
    for (dx,dy) in [(5,0),(-5,0),(0,5),(0,-5),(4,4),(-4,4)]:
        r=order(kind,bpp,dx,dy,[(10,8,40,24)])
        print((dx,dy),r[0][0],'->',r[1],r[2][:6],end=' | ')
    print()
