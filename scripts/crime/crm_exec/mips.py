"""Tiny MIPS IV (n32, big-endian) interpreter for crm.so functions. Integer + double FP subset."""
import struct, math, os
from elftools.elf.elffile import ELFFile
M64=(1<<64)-1
def s32(x): x&=0xffffffff; return x-(1<<32) if x&0x80000000 else x
def s64(x): x&=M64; return x-(1<<64) if x>>63 else x
def sx32(x): return s32(x)&M64
NAMES=['zero','at','v0','v1','a0','a1','a2','a3','a4','a5','a6','a7','t0','t1','t2','t3','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','s8','ra']
RI={n:i for i,n in enumerate(NAMES)}
class Halt(Exception): pass
class CPU:
    def __init__(s,binpath=os.environ.get('CRM_SO',os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','ddx','crm.so'))):
        s.segs=[]  # (base, bytearray)
        e=ELFFile(open(binpath,'rb'))
        for seg in e.iter_segments():
            if seg['p_type']!='PT_LOAD':continue
            b=bytearray(seg['p_memsz']); d=seg.data(); b[:len(d)]=d
            s.segs.append([seg['p_vaddr'],b])
        s.text=s.segs[0]
        s.heap=0x10000000; s.hb=bytearray(0x1000000); s.segs.append([0x10000000,s.hb])
        s.sb=bytearray(0x100000); s.segs.append([0x7f700000,s.sb]); s.sp0=0x7f7ff000
        s.r=[0]*32; s.hi=0; s.lo=0; s.f=[0]*32; s.fcc=0
        s.dec={}; s.hooks={}; s.ninsn=0; s.trace=None
        s.watch=None; s.rwatch=None
    def alloc(s,n,al=16):
        s.heap=(s.heap+al-1)&~(al-1); a=s.heap; s.heap+=n; assert s.heap-0x10000000<len(s.hb); return a
    def seg(s,a):
        for b,m in s.segs:
            if b<=a<b+len(m): return b,m
        raise Halt('unmapped %x pc=%x'%(a,s.pc))
    def rd(s,a,n):
        if s.rwatch: s.rwatch(a,n)
        b,m=s.seg(a); o=a-b
        if o+n>len(m): raise Halt('rd overrun %x'%a)
        return int.from_bytes(m[o:o+n],'big')
    def wr(s,a,n,v):
        b,m=s.seg(a); o=a-b
        if b<0x10000000 and not (b==s.segs[1][0]): pass
        m[o:o+n]=(v&((1<<(8*n))-1)).to_bytes(n,'big')
        if s.watch: s.watch(a,n,v)
    def bytes(s,a,n): b,m=s.seg(a); return bytes(m[a-b:a-b+n])
    def put(s,a,data): b,m=s.seg(a); m[a-b:a-b+len(data)]=data
    def w32(s,a,v): s.wr(a,4,v)
    def w16(s,a,v): s.wr(a,2,v)
    def w8(s,a,v): s.wr(a,1,v)
    def r32(s,a): return s.rd(a,4)
    def R(s,n): return s.r[RI[n]]
    def call(s,fn,args=(),maxins=20000000,stubs=None):
        SENT=0x7ff00000
        s.r=[0]*32
        for i,a in enumerate(args): s.r[4+i]=a&M64
        s.r[25]=fn; s.r[28]=0x5b0ea0; s.r[31]=SENT; s.r[29]=s.sp0
        s.pc=fn; s.ninsn=0; s.calls=[]
        while s.pc!=SENT:
            if s.ninsn>maxins: raise Halt('insn limit')
            s.step()
        return s.r[2]
    def fetch(s,pc):
        d=s.dec.get(pc)
        if d is None:
            d=s.dec[pc]=s.rd(pc,4)
        return d
    def step(s):
        pc=s.pc; w=s.fetch(pc)
        s.ninsn+=1
        if pc in s.hooks:
            s.hooks[pc](s)
        nxt=pc+4
        br=s.exec(w,pc)   # returns None or ('b',target,likely_taken_flag) etc.
        if br is None:
            s.pc=nxt
        else:
            kind,tgt,cond,likely=br
            if cond:
                s.pc=pc+4; s.delay(); s.pc=tgt
            else:
                if likely: s.pc=pc+8
                else:
                    s.pc=pc+4; s.delay(); s.pc=pc+8
    def delay(s):
        pc=s.pc; w=s.fetch(pc); s.ninsn+=1
        if pc in s.hooks: s.hooks[pc](s)
        br=s.exec(w,pc); assert br is None,'branch in delay slot %x'%pc
    def exec(s,w,pc):
        r=s.r; op=w>>26; rs=(w>>21)&31; rt=(w>>16)&31; rd=(w>>11)&31; sa=(w>>6)&31; fn=w&63
        imm=w&0xffff; simm=imm-0x10000 if imm&0x8000 else imm
        def W(i,v):
            if i: r[i]=v&M64
        if op==0:
            if fn==0: W(rd,sx32(r[rt]<<sa))
            elif fn==2: W(rd,sx32((r[rt]&0xffffffff)>>sa))
            elif fn==3: W(rd,sx32(s32(r[rt])>>sa))
            elif fn==4: W(rd,sx32(r[rt]<<(r[rs]&31)))
            elif fn==6: W(rd,sx32((r[rt]&0xffffffff)>>(r[rs]&31)))
            elif fn==7: W(rd,sx32(s32(r[rt])>>(r[rs]&31)))
            elif fn==8: return ('b',r[rs],True,False)
            elif fn==9: t=r[rs]; W(rd,pc+8); return ('b',t,True,False)
            elif fn==10:
                if r[rt]==0: W(rd,r[rs])
            elif fn==11:
                if r[rt]!=0: W(rd,r[rs])
            elif fn==1:
                cc=(rt>>2)&7; tf=rt&1
                if (((s.fcc>>cc)&1)==tf): W(rd,r[rs])
            elif fn==16: W(rd,s.hi)
            elif fn==18: W(rd,s.lo)
            elif fn==17: s.hi=r[rs]
            elif fn==19: s.lo=r[rt] if False else r[rs]
            elif fn==20: W(rd,r[rt]<<(r[rs]&63))
            elif fn==22: W(rd,r[rt]>>(r[rs]&63))
            elif fn==23: W(rd,s64(r[rt])>>(r[rs]&63))
            elif fn==24: p=s32(r[rs])*s32(r[rt]); s.lo=sx32(p); s.hi=sx32(p>>32)
            elif fn==25: p=(r[rs]&0xffffffff)*(r[rt]&0xffffffff); s.lo=sx32(p); s.hi=sx32(p>>32)
            elif fn==26:
                a,b=s32(r[rs]),s32(r[rt])
                if b:
                    q=abs(a)//abs(b)
                    if (a<0)!=(b<0): q=-q
                    s.lo=sx32(q); s.hi=sx32(a-q*b)
            elif fn==27:
                a,b=r[rs]&0xffffffff,r[rt]&0xffffffff
                if b: s.lo=sx32(a//b); s.hi=sx32(a%b)
            elif fn==28: p=s64(r[rs])*s64(r[rt]); s.lo=p&M64; s.hi=(p>>64)&M64
            elif fn==29: p=r[rs]*r[rt]; s.lo=p&M64; s.hi=(p>>64)&M64
            elif fn in(32,33): W(rd,sx32(r[rs]+r[rt]))
            elif fn in(34,35): W(rd,sx32(r[rs]-r[rt]))
            elif fn==36: W(rd,r[rs]&r[rt])
            elif fn==37: W(rd,r[rs]|r[rt])
            elif fn==38: W(rd,r[rs]^r[rt])
            elif fn==39: W(rd,~(r[rs]|r[rt]))
            elif fn==42: W(rd,1 if s64(r[rs])<s64(r[rt]) else 0)
            elif fn==43: W(rd,1 if r[rs]<r[rt] else 0)
            elif fn in(44,45): W(rd,r[rs]+r[rt])
            elif fn in(46,47): W(rd,r[rs]-r[rt])
            elif fn==52:
                if r[rs]==r[rt]: raise Halt('trap teq pc=%x'%pc)
            elif fn==56: W(rd,r[rt]<<sa)
            elif fn==58: W(rd,r[rt]>>sa)
            elif fn==59: W(rd,s64(r[rt])>>sa)
            elif fn==60: W(rd,r[rt]<<(sa+32))
            elif fn==62: W(rd,r[rt]>>(sa+32))
            elif fn==63: W(rd,s64(r[rt])>>(sa+32))
            elif fn==0 and w==0: pass
            else: raise Halt('special %d pc=%x'%(fn,pc))
        elif op==1:
            v=s64(r[rs])
            if rt==0: return ('b',pc+4+(simm<<2),v<0,False)
            if rt==1: return ('b',pc+4+(simm<<2),v>=0,False)
            if rt==2: return ('b',pc+4+(simm<<2),v<0,True)
            if rt==3: return ('b',pc+4+(simm<<2),v>=0,True)
            if rt in(17,19):
                W(31,pc+8); return ('b',pc+4+(simm<<2),v>=0,rt==19)
            raise Halt('regimm %d'%rt)
        elif op==2: return ('b',(pc&0xf0000000)|((w&0x3ffffff)<<2),True,False)
        elif op==3: W(31,pc+8); return ('b',(pc&0xf0000000)|((w&0x3ffffff)<<2),True,False)
        elif op in(4,20): return ('b',pc+4+(simm<<2),r[rs]==r[rt],op==20)
        elif op in(5,21): return ('b',pc+4+(simm<<2),r[rs]!=r[rt],op==21)
        elif op in(6,22): return ('b',pc+4+(simm<<2),s64(r[rs])<=0,op==22)
        elif op in(7,23): return ('b',pc+4+(simm<<2),s64(r[rs])>0,op==23)
        elif op in(8,9): W(rt,sx32(r[rs]+simm))
        elif op==10: W(rt,1 if s64(r[rs])<simm else 0)
        elif op==11: W(rt,1 if r[rs]<(simm&M64) else 0)
        elif op==12: W(rt,r[rs]&imm)
        elif op==13: W(rt,r[rs]|imm)
        elif op==14: W(rt,r[rs]^imm)
        elif op==15: W(rt,sx32(imm<<16))
        elif op in(24,25): W(rt,r[rs]+simm)
        elif op==32: v=s.rd(r[rs]+simm,1); W(rt,v-256 if v&128 else v)
        elif op==33: v=s.rd(r[rs]+simm,2); W(rt,v-65536 if v&0x8000 else v)
        elif op==35: W(rt,sx32(s.rd(r[rs]+simm,4)))
        elif op==36: W(rt,s.rd(r[rs]+simm,1))
        elif op==37: W(rt,s.rd(r[rs]+simm,2))
        elif op==39: W(rt,s.rd(r[rs]+simm,4))
        elif op==55: W(rt,s.rd(r[rs]+simm,8))
        elif op==40: s.wr(r[rs]+simm,1,r[rt])
        elif op==41: s.wr(r[rs]+simm,2,r[rt])
        elif op==43: s.wr(r[rs]+simm,4,r[rt])
        elif op==63: s.wr(r[rs]+simm,8,r[rt])
        elif op==51: pass
        elif op==53: s.f[rt]=s.rd(r[rs]+simm,8)
        elif op==61: s.wr(r[rs]+simm,8,s.f[rt])
        elif op==49: s.f[rt]=s.rd(r[rs]+simm,4)
        elif op==57: s.wr(r[rs]+simm,4,s.f[rt])
        elif op in(26,27,34,38,44,45,42,46): s.unaligned(op,rs,rt,simm)
        elif op==17: return s.cop1(w,pc,rs,rt,rd,sa,fn,simm)
        else: raise Halt('op %d pc=%x'%(op,pc))
        return None
    def unaligned(s,op,rs,rt,simm):
        r=s.r; a=r[rs]+simm
        if op in(34,38,42,46): n=4
        else: n=8
        al=a&~(n-1); k=a&(n-1)
        if op==34:  # lwl: big endian: loads bytes from a..end of word into high bytes
            m=n-k; v=s.rd(a,m); old=r[rt]&0xffffffff; sh=8*(n-m)
            nv=(old&((1<<sh)-1))|(v<<sh) ; r[rt]=sx32(nv) if rt else 0
        elif op==38:  # lwr: loads bytes from word start to a into low bytes
            m=k+1; v=s.rd(al,m); old=r[rt]&0xffffffff
            nv=(old&~((1<<(8*m))-1)&0xffffffff)|v; r[rt]=sx32(nv) if rt else 0
        elif op==42:  # swl
            m=n-k; v=(r[rt]&0xffffffff)>>(8*(n-m)) ; s.wr(a,m,v)
        elif op==46:  # swr
            m=k+1; v=r[rt]&((1<<(8*m))-1); s.wr(al,m,v)
        elif op==26:  # ldl
            m=n-k; v=s.rd(a,m); sh=8*(n-m); old=r[rt]; r[rt]=((old&((1<<sh)-1))|(v<<sh))&M64
        elif op==27:  # ldr
            m=k+1; v=s.rd(al,m); old=r[rt]; r[rt]=((old&~((1<<(8*m))-1))|v)&M64
        elif op==44: m=n-k; s.wr(a,m,r[rt]>>(8*(n-m)))
        elif op==45: m=k+1; s.wr(al,m,r[rt]&((1<<(8*m))-1))
    def fd(s,i): return struct.unpack('>d',s.f[i].to_bytes(8,'big'))[0]
    def sfd(s,i,v): s.f[i]=int.from_bytes(struct.pack('>d',v),'big')
    def cop1(s,w,pc,rs,rt,rd,sa,fn,simm):
        r=s.r
        fmt=rs; ft=rt; fs=rd; fd=sa
        if rs==0: 
            if rt: r[rt]=sx32(s.f[fs]&0xffffffff)
        elif rs==4:
            s.f[fs]=r[rt]&0xffffffff if True else 0
        elif rs==5:
            s.f[fs]=r[rt]
        elif rs==1:
            if rt: r[rt]=s.f[fs]
        elif rs==8:
            cc=(rt>>2)&7; tf=rt&1; likely=(rt>>1)&1
            return ('b',pc+4+(simm<<2),((s.fcc>>cc)&1)==tf,bool(likely))
        elif fmt==17:  # double
            a=s.fd(fs); b=s.fd(ft)
            if fn==0: s.sfd(fd,a+b)
            elif fn==1: s.sfd(fd,a-b)
            elif fn==2: s.sfd(fd,a*b)
            elif fn==3: s.sfd(fd,a/b if b else math.copysign(math.inf,a))
            elif fn==5: s.sfd(fd,abs(a))
            elif fn==6: s.f[fd]=s.f[fs]
            elif fn==7: s.sfd(fd,-a)
            elif fn==13: s.f[fd]=(int(a) if math.isfinite(a) and abs(a)<2**31 else 0x7fffffff)&0xffffffff
            elif fn==33: pass
            elif fn==17:  # movf/movt.d
                cc=(rt>>2)&7; tf=rt&1
                if ((s.fcc>>cc)&1)==tf: s.f[fd]=s.f[fs]
            elif fn==18:
                if r[rt]==0: s.f[fd]=s.f[fs]
            elif fn==19:
                if r[rt]!=0: s.f[fd]=s.f[fs]
            elif fn>=48:
                cc=(sa>>2)&7
                c=fn&15
                if c==2: res=a==b
                elif c==12: res=a<b
                elif c==14: res=a<=b
                else: raise Halt('c.cond %d pc=%x'%(c,pc))
                s.fcc=(s.fcc&~(1<<cc))|(int(res)<<cc)
            else: raise Halt('cop1.d fn %d pc=%x'%(fn,pc))
        elif fmt==20:  # word
            v=s32(s.f[fs])
            if fn==33: s.sfd(fd,float(v))
            elif fn==32: s.f[fd]=int.from_bytes(struct.pack('>f',float(v)),'big')
            else: raise Halt('cop1.w fn %d'%fn)
        else: raise Halt('cop1 rs %d fn %d pc=%x'%(rs,fn,pc))
        return None
