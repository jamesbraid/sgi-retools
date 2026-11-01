exec(open("fp1.py").read().split("\nif __name__")[0])
def tails(pts,shape=1,kind='Copy',bpp=8):
    r=run1(kind,bpp,shape,0,pts,(0,0,64,64),0,0,0x0b0b0b0b,0xffffffff)[0]
    return r[0]
P=[(17,33),(30,15),(47,27),(44,40),(17,42)]
print('no dup',tails(P),'closing dup',tails(P+[P[0]]),'dup mid',tails(P[:2]+[P[1]]+P[2:]),'dup first',tails([P[0]]+P))
# y-monotone shapes with horizontal edges, plateaus
Q=[(10,10),(30,10),(30,20),(20,30),(10,20)]
print('plateau top',tails(Q),'rot',[tails(Q[i:]+Q[:i]) for i in range(5)])
# zig-zag with 4 reversals
Z=[(10,10),(40,20),(10,30),(40,40),(10,50)]
print('zigzag',tails(Z))
Z2=[(10,10),(40,10),(40,50),(25,30),(10,50)]
print('notch',tails(Z2),tails([(10,10),(40,10),(25,30)]))
print('--- small counts')
for pts in ([],[(5,5)],[(5,5),(9,9)],[(5,5),(9,5)],[(5,5),(5,5),(5,5)],[(5,5),(9,5),(5,5)]):
    for shape in (2,0):
        r=run1('Copy',8,shape,0,pts,(0,0,64,64),0,0,0x0b0b0b0b,0xffffffff)
        print(len(pts),pts,shape,r[0][0],'changed' if r[1]!=r[2] else 'pixels untouched')
r=run1('Copy',8,2,0,[(10,10),(30,12),(20,30)],(0,0,64,64),0,0,0x0b0b0b0b,0xffffffff)
print(r[0])
r=run1('Copy',8,2,0,[(10,10),(30,12),(20,30)],(0,0,64,64),0,0,0x0b0b0b0b,0xffffffff)
for m in (1,):
    r=run1('General',16,2,m,[(10,10),(30,12),(20,30)],(0,0,64,64),0,0,0x0b0b0b0b,0xffffffff); print('prev',[hex(x) for x in [r[0][1]]+r[0][2]],[hex(x) for x in r[3]])
r=run1('General',16,2,0,[(10,10),(30,12),(40,70)],(0,0,64,64),0,0,0x0b0b0b0b,0xffffffff); print('out',[hex(x) for x in [r[0][1]]+r[0][2]],[hex(x) for x in r[3]])
print('--- convex shape given a non-monotone outline')
W=[(10,10),(40,30),(10,50),(40,10),(40,50)]   # 4 reversals
for sh in (2,1):
    r=run1('Copy',8,sh,0,W,(0,0,64,64),0,0,0x0b0b0b0b,0xffffffff); print(sh,r[0][0],'changed' if r[1]!=r[2] else 'untouched', sum(1 for a,b in zip(r[1],r[2]) if a!=b))
