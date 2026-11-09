exec(open("r6.py").read().split("\nif __name__==")[0])
F={8:{'Copy':0x429580,'General':0x49a460,'Xor':0x4a1f90,'PreviousCopy':0x4990c0},16:{'Copy':0x4944f0,'General':0x499680,'Xor':0x4a40b0,'PreviousCopy':0x498ac0},32:{'Copy':0x4954b0,'General':0x49f0b0,'Xor':0x49fe80,'PreviousCopy':0x4984d0}}
random.seed(17)
for bpp in (8,16,32):
    v=mk(bpp); c=v.c; bs=bpp//8
    for kind in ('Copy','General','Xor'):
        fn=F[bpp][kind]; bad=0; n=0; acc_ok=True
        for it in range(250):
            nn=random.randint(2,5); cap=random.choice([0,1])
            pts=[(random.randint(-10,74),random.randint(-10,74)) for _ in range(nn)]
            if random.random()<.5: pts=[(random.randint(8,56),random.randint(8,56)) for _ in range(nn)]
            if random.random()<.2 and nn>2: pts[-1]=pts[0]
            ox,oy=random.randint(-3,3),random.randint(-3,3)
            box=(random.randint(0,12),random.randint(0,12),random.randint(52,64),random.randint(52,64))
            bz=random.choice([0,255,random.getrandbits(8)]); v.bias(bz); BIAS[0]=bz
            mode=1 if kind=='PreviousCopy' else 0
            p2=pts if mode==0 else [pts[0]]+[(pts[i][0]-pts[i-1][0],pts[i][1]-pts[i-1][1]) for i in range(1,nn)]
            col={8:0x0b0b0b0b,16:0x0b0c0b0c,32:0x0b0c0d0e}[bpp]; pv={8:0x0b,16:0x0b0c,32:0x0b0c0d0e}[bpp]
            rop=3; andv=0
            if kind=='General': rop=6; andv=0   # general: (old&and)^xor, old=0 -> xor
            if kind=='Xor': rop=6
            try: ret,vals,got=runit2(fn,p2,box,mode,cap,rop=rop,ox=ox,oy=oy,col=col)
            except Halt as e: print(bpp,kind,'HALT',e); bad=-1; break
            pa=[(x+ox,y+oy) for x,y in pts]
            rr,px=ref1rect(pa,box,cap)
            if kind=='Xor':
                cc=collections.Counter(p for p in px if 0<=p[0]<64 and 0<=p[1]<64); want={p:pv for p,k in cc.items() if k%2}
            else: want={p:pv for p in px if 0<=p[0]<64 and 0<=p[1]<64}
            n+=1
            if ret!=rr or got!=want:
                bad+=1
                if bad<3: print(bpp,kind,'mismatch',pts,mode,cap,box,(ox,oy),'ret',ret,'ref',rr,len(set(got.items())^set(want.items())),[hex(x) for x in vals])
        print(bpp,kind,n,'bad',bad)
