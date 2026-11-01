exec(open("su1.py").read().split("\nif __name__")[0])
FN=0x4c5c10
def rowsel(Hh,oy,py,ox=0,px=0):
    # stipple W=20, row r has only bit r set -> the painted x tells which row was used for each y
    W=20; v=mk(8); c=v.c; v.setclip([(0,0,64,64)])
    c.w16(v.D+8,ox); c.w16(v.D+10,oy)
    ST=c.alloc(64); SD=c.alloc(128); c.w8(ST,1); c.put(ST+12,struct.pack('>HH',W,Hh)); c.w32(ST+28,4); c.w32(ST+32,SD)
    for r in range(Hh): c.w32(SD+4*r,1<<(31-r))
    c.w8(v.GC+5,3); c.w32(v.GC+20,0xffffffff); c.w32(v.GC+24,0x3a); c.w32(v.GC+28,0x45); c.w32(v.GC+36,ST); c.put(v.GC+40,struct.pack('>hh',px,py)); c.w32(v.GC+16,2<<24)
    out=[]
    for y in range(0,24):
        v.clear(); img=run(v,FN,[(0,y,20)],1)
        xs=[x for x in range(20) if img[y*64+x]==0x3a]; out.append(xs[0] if len(xs)==1 else xs)
    exp=[(y-oy-py)%Hh for y in range(24)]
    return out,exp
for (Hh,oy,py) in [(7,3,13),(7,0,16),(7,3,-3),(5,3,13),(7,-3,13),(7,3,30)]:
    got,exp=rowsel(Hh,oy,py); print(Hh,oy,py,'ok' if got==exp else ('MISMATCH',got,exp))
