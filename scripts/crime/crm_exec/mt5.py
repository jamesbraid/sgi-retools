exec(open("mt4.py").read().split("random.seed(77)")[0])
fn=0x52c380
def endtest(off,dl,double,pts=[(10,10),(30,10)],rop=0,alu=15,bgp=1):
    v.setclip([(0,0,64,64)]); setup(v,rop=rop,dash=dl,off=off,double=double,cap=1,pm=1,alu=alu,bgp=bgp)
    # background: half set pattern: all zero so clear invisible; use rop=15 (set) fg and alu 0 (clear) bg instead
    put_bg(set())
    pp=c.alloc(16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    c.call(fn,[v.D,v.GC,0,len(pts),pp]); return bits(v)
# fg=set (rop 15), bg=clear (alu 0): bg pixels leave 0. Show line pixels in order
for off in range(0,6):
    g=endtest(off,[1,4],False,rop=15,alu=0,bgp=0)
    row=''.join('#' if (x,10) in g else '.' for x in range(10,31))
    print('off',off,row,'end drawn' if (30,10) in g else 'end not drawn', 'dash state at end idx', dash_at([1,4],off+20))
print('--- bg op set (alu 15, bg 1), fg noop, single dash')
for off in (0,1,3,5):
    g=endtest(off,[1,4],False,rop=5,alu=15,bgp=1)
    row=''.join('#' if (x,10) in g else '.' for x in range(8,33))
    print('off',off,row)
print('--- clipped start')
for pts in ([(-6,51),(37,40)],[(10,51),(37,40)]):
    for off in (0,2):
        g=endtest(off,[1,4],False,pts=pts,rop=5,alu=15,bgp=1)
        print(pts,off,sorted(g))
print('--- endpoint op identification (bg all ones; fg rop clear; bg alu clear(0)? )')
allp={(x,y) for x in range(64) for y in range(64)}
def endtest2(off,dl,double,rop,alu,bgp,pts=[(10,10),(30,10)],pre=allp):
    v.setclip([(0,0,64,64)]); setup(v,rop=rop,dash=dl,off=off,double=double,cap=1,pm=1,alu=alu,bgp=bgp); put_bg(pre)
    pp=c.alloc(16)
    for i,(x,y) in enumerate(pts): c.put(pp+4*i,struct.pack('>hh',x,y))
    c.call(fn,[v.D,v.GC,0,len(pts),pp]); return bits(v)
# fg clears, bg (alu=3 copy of bg pixel 1) sets => on dash pixels cleared, off dash pixels set (stay set)
for off in (0,1,2):
    for dbl in (False,True):
        g=endtest2(off,[1,4],dbl,rop=0,alu=3,bgp=1)
        row=''.join('#' if (x,10) in g else '.' for x in range(8,33))
        print('off',off,'dbl',dbl,row)
print('--- noop fg, set bg')
for off in (0,1):
    for dbl in (False,True):
        g=endtest2(off,[1,4],dbl,rop=5,alu=15,bgp=1,pre=set())
        row=''.join('#' if (x,10) in g else '.' for x in range(8,33))
        print('off',off,'dbl',dbl,row)
print('--- fg set, bg none (alu 5 noop)')
for off in (0,1):
    for dbl in (False,True):
        g=endtest2(off,[1,4],dbl,rop=15,alu=5,bgp=1,pre=set())
        row=''.join('#' if (x,10) in g else '.' for x in range(8,33))
        print('off',off,'dbl',dbl,row)
print('=== endpoint truth table')
ops={'clr':(0,0),'set':(15,15),'noop':(5,5),'inv':(10,10)}   # (fg rop, bg alu)
# bg alu with bgp=1: set=alu 15 (all ones), clear=alu 0, noop=alu 5 (dest), inv=alu 10 (~d)
rows=[]
for off,state in ((0,'F'),(1,'B')):
  for dbl in (False,True):
    for fg in ('clr','set','noop','inv'):
      for bg in ('clr','set','noop','inv'):
        res=[]
        for pre in (0,1):
            g=endtest2(off,[1,4],dbl,rop=ops[fg][0],alu=ops[bg][1],bgp=1,pre=(allp if pre else set()))
            res.append(int((30,10) in g))
        # expected by reference: state F -> fg op; B -> bg op if dbl else nothing
        def ap(op,d): return {'clr':0,'set':1,'noop':d,'inv':1-d}[op]
        exp=[ (ap(fg,d) if state=='F' else (ap(bg,d) if dbl else d)) for d in (0,1)]
        if res!=exp: rows.append((state,dbl,fg,bg,res,exp))
for r in rows: print(r)
print(len(rows),'differences of 64')
