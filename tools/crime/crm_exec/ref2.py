from ref import line_pixels
TIE={(False,False,False):1,(False,False,True):1,(False,True,False):1,(False,True,True):0,(True,False,False):1,(True,False,True):1,(True,True,False):1,(True,True,True):0}
BIAS=[0]
def tiefor(b): return {(ym,xd,yd):(0 if (b>>(int(ym)|int(yd)<<1|int(xd)<<2))&1 else 1) for ym in (False,True) for xd in (False,True) for yd in (False,True)}
def lp(a,b):
    return line_pixels(a[0],a[1],b[0],b[1],tiefor(BIAS[0])) if a!=b else [a]
def inclip(p,clip): return any(b[0]<=p[0]<b[2] and b[1]<=p[1]<b[3] for b in clip)
def polyline(pts,clip,cap,rule='A',segments=False):
    out=set()
    if segments:
        for i in range(0,len(pts)-1,2):
            a,b=pts[i],pts[i+1]
            px=lp(a,b)
            if a!=b: px=px if cap else px[:-1]
            elif not cap: px=[]   # guess
            out.update(p for p in px if inclip(p,clip))
        return out
    for i in range(len(pts)-1):
        px=lp(pts[i],pts[i+1])[:-1] if pts[i]!=pts[i+1] else []
        out.update(p for p in px if inclip(p,clip))
    last=pts[-1]
    if cap:
        if rule=='A': ok=(last!=pts[0] or len(pts)==2)
        else: ok=True
        if ok and inclip(last,clip): out.add(last)
    return out

def polyline_list(pts,clip,cap,segments=False):
    out=[]
    if segments:
        for i in range(0,len(pts)-1,2):
            a,b=pts[i],pts[i+1]
            px=lp(a,b)
            if a!=b: px=px if cap else px[:-1]
            elif not cap: px=[]
            out+=[p for p in px if inclip(p,clip)]
        return out
    for i in range(len(pts)-1):
        px=lp(pts[i],pts[i+1])[:-1] if pts[i]!=pts[i+1] else []
        out+=[p for p in px if inclip(p,clip)]
    last=pts[-1]
    if cap and (last!=pts[0] or len(pts)==2) and inclip(last,clip): out.append(last)
    return out
