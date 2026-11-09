# reference thin-line pixel generator with tie rule per octant (derived empirically)
def line_pixels(x1,y1,x2,y2,tie):
    """returns list of (x,y) from start to end inclusive. tie: dict octant-> 0/1 meaning on exact tie
    choose +? ; octant key=(ymajor,xdec,ydec)"""
    dx=x2-x1; dy=y2-y1
    adx=abs(dx); ady=abs(dy); sx=-1 if dx<0 else 1; sy=-1 if dy<0 else 1
    ymaj = ady>adx
    key=(ymaj,dx<0,dy<0)
    out=[]
    if not ymaj:
        n=adx
        for i in range(n+1):
            # exact minor = y1 + dy*i/adx *... (i steps along x)
            num=ady*i*2   # 2*ady*i / (adx) compare to odd multiples
            # minor offset m = ady*i/adx, round with tie
            if adx==0: m=0
            else:
                q,r=divmod(2*ady*i,2*adx)  # m = q + r/(2adx)
                # r/(2adx) vs 1/2: r*2 vs 2adx
                if r*2>2*adx or (r*2==2*adx and tie.get(key,0)): q+=1
                m=q
            out.append((x1+sx*i,y1+sy*m))
    else:
        n=ady
        for i in range(n+1):
            q,r=divmod(2*adx*i,2*ady)
            if r*2>2*ady or (r*2==2*ady and tie.get(key,0)): q+=1
            out.append((x1+sx*q,y1+sy*i))
    return out
