from ref2 import *
def dash_at(dl,pos):
    tot=sum(dl); p=pos%tot; i=0
    while p>=dl[i]: p-=dl[i]; i+=1
    return i  # index
def dashed(pts,clip,cap,dl,off,double,segments=False):
    """returns dict pixel->'F' or 'B'"""
    out={}
    def put(p,pos):
        if not inclip(p,clip): return
        i=dash_at(dl,pos)
        if i%2==0: out[p]='F'
        elif double: out[p]='B'
    if segments:
        for k in range(0,len(pts)-1,2):
            a,b=pts[k],pts[k+1]
            px=lp(a,b); pos=off
            n=len(px)-1
            for j,p in enumerate(px):
                if j==n and (a!=b and not cap): continue
                if a==b and not cap: continue
                put(p,pos+j)
        return out
    pos=off
    for k in range(len(pts)-1):
        a,b=pts[k],pts[k+1]
        if a==b: continue
        px=lp(a,b); n=len(px)-1
        for j,p in enumerate(px[:-1]): put(p,pos+j)
        pos+=n
    last=pts[-1]
    if cap and (last!=pts[0] or len(pts)==2): put(last,pos)
    return out

def dashed_list(pts,clip,cap,dl,off,double,segments=False):
    out=[]
    def put(p,pos):
        if not inclip(p,clip): return
        i=dash_at(dl,pos)
        if i%2==0: out.append((p,'F'))
        elif double: out.append((p,'B'))
    if segments:
        for k in range(0,len(pts)-1,2):
            a,b=pts[k],pts[k+1]
            px=lp(a,b); pos=off; n=len(px)-1
            for j,p in enumerate(px):
                if j==n and (a!=b and not cap): continue
                if a==b and not cap: continue
                put(p,pos+j)
        return out
    pos=off
    for k in range(len(pts)-1):
        a,b=pts[k],pts[k+1]
        if a==b: continue
        px=lp(a,b); n=len(px)-1
        for j,p in enumerate(px[:-1]): put(p,pos+j)
        pos+=n
    last=pts[-1]
    if cap and (last!=pts[0] or len(pts)==2): put(last,pos)
    return out
