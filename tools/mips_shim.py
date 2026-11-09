"""Stand-ins for the MIPS IV instructions the Unicorn MIPS core does not run.

The IRIX N32 libraries use the multiply-add family (`madd.s` and the others of the same
opcode), the conditional moves `movz`, `movn`, `movf` and `movt`, and floating-point
condition codes other than 0. The emulator stops silently at the first of them. `install`
rewrites each such instruction in the emulated copy of a routine to a no-op and registers
a code hook that performs it on the registers instead; the condition codes of compares and
branches are folded onto code 0 after checking that no compare is still waiting for its
branch when the next one runs. The loaded image on disk is not touched, and the routine's
control flow is the shipped one.
"""
import struct

import numpy as np
import unicorn.mips_const as mc
from unicorn import UC_HOOK_CODE


def decode(w):
    op=w>>26
    if op==0x11:
        rs=(w>>21)&0x1f
        if rs==8: return ('bc1',(w>>18)&7)
        if rs in (0x10,0x11) and (w&0x3f)>=0x30: return ('cmp',(w>>8)&7)
        if rs in (0x10,0x11) and (w&0x3f) in (0x11,0x12): return ('movcf',(w>>18)&7)
    if op==0 and (w&0x3f)==1: return ('movci',(w>>18)&7)
    return None
def patch(mu,start,end,seen=None):
    """Fold every condition code onto code 0. `seen` collects, by address, each compare's
    operands and condition and each conditional move's original code, for the stand-ins."""
    n=0; live=None; conflicts=[]; cmps=0
    last_cmp=None; consumed=True
    for a in range(start,end,4):
        w=struct.unpack('>I',bytes(mu.mem_read(a,4)))[0]
        d=decode(w)
        if not d: continue
        k,cc=d
        if seen is not None:
            if k=='cmp': seen[a]=('cmp',(w>>21)&31,(w>>11)&31,(w>>16)&31,w&0xf,cc)
            elif k in('movcf','movci'): seen[a]=('ccmove',cc)
        if k=='cmp':
            cmps+=1
            if last_cmp is not None and not consumed and last_cmp[1]!=cc: conflicts.append((hex(last_cmp[0]),hex(a)))
            last_cmp=(a,cc); consumed=False
        elif k in('bc1','movcf','movci'): consumed=True
        if cc:
            if k=='cmp': nw=w&~(7<<8)
            else: nw=w&~(7<<18)
            mu.mem_write(a,struct.pack('>I',nw)); n+=1
    return n,cmps,conflicts

def F(n): return getattr(mc,'UC_MIPS_REG_F%d'%n)
def f32(bits): return np.frombuffer(struct.pack('>I',bits&0xffffffff),dtype='>f4')[0]
def f64(bits): return np.frombuffer(struct.pack('>Q',bits&0xffffffffffffffff),dtype='>f8')[0]
def b32(x): return struct.unpack('>I',np.array([x],dtype='>f4').tobytes())[0]
def b64(x): return struct.unpack('>Q',np.array([x],dtype='>f8').tobytes())[0]
def patch_cop1x(mu,start,end,hooks):
    """replace madd/msub/nmadd/nmsub with nop and emulate them from a code hook"""
    n=0; kinds=set()
    for a in range(start,end,4):
        w=struct.unpack('>I',bytes(mu.mem_read(a,4)))[0]
        if w>>26==0x13:
            fn=w&0x3f; fr=(w>>21)&31; ft=(w>>16)&31; fs=(w>>11)&31; fd=(w>>6)&31
            kinds.add(hex(fn))
            if fn in (0x20,0x21,0x28,0x29,0x30,0x31,0x38,0x39):
                hooks[a]=(fn,fd,fr,fs,ft); mu.mem_write(a,b'\0\0\0\0'); n+=1
    return n,kinds
def emu_cop1x(mu,a,hooks):
    fn,fd,fr,fs,ft=hooks[a]
    dbl=fn&1
    rd=(lambda r: f64(mu.reg_read(F(r)))) if dbl else (lambda r: f32(mu.reg_read(F(r))))
    x,y,z=rd(fs),rd(ft),rd(fr)
    T=np.float64 if dbl else np.float32
    prod=T(x)*T(y)
    base=fn&0x38
    if base==0x20: r=prod+T(z)
    elif base==0x28: r=prod-T(z)
    elif base==0x30: r=-(prod+T(z))
    else: r=-(prod-T(z))
    mu.reg_write(F(fd), b64(r) if dbl else b32(r))

def compare(cond,x,y):
    """Result of c.cond.fmt for the 4-bit condition field (IEEE ordered and unordered forms)."""
    un=bool(np.isnan(x) or np.isnan(y))
    lt,eq=bool(x<y),bool(x==y)
    return [False,un,eq,un or eq,lt,un or lt,lt or eq,un or lt or eq,
            False,un,eq,un or eq,lt,un or lt,lt or eq,un or lt or eq][cond]

def emu_cmp(mu,a,seen,ccs):
    _,fmt,fs,ft,cond,cc=seen[a]
    rd=(lambda r: f64(mu.reg_read(F(r)))) if fmt==0x11 else (lambda r: f32(mu.reg_read(F(r))))
    ccs[cc]=compare(cond,rd(fs),rd(ft))

def R_(n): return getattr(mc,'UC_MIPS_REG_%d'%n) if n else None
def patch_moves(mu,start,end,hooks):
    n=0
    for a in range(start,end,4):
        w=struct.unpack('>I',bytes(mu.mem_read(a,4)))[0]
        op=w>>26; fn=w&0x3f
        if op==0 and fn in (0x0a,0x0b):
            hooks[a]=('mz',fn,(w>>11)&31,(w>>21)&31,(w>>16)&31); mu.mem_write(a,b'\0\0\0\0'); n+=1
        elif op==0 and fn==1:
            hooks[a]=('mci',(w>>16)&1,(w>>11)&31,(w>>21)&31,0); mu.mem_write(a,b'\0\0\0\0'); n+=1
        elif op==0x11 and ((w>>21)&31) in (0x10,0x11) and fn in (0x11,0x12):
            # movf/movt fmt: bit16 tf; funct 0x11 = movcf
            hooks[a]=('mcf',(w>>16)&1,(w>>6)&31,(w>>11)&31,(w>>21)&31); mu.mem_write(a,b'\0\0\0\0'); n+=1
    return n
def emu_move(mu,a,hooks,seen=None,ccs=None):
    h=hooks[a]
    if h[0]=='mz':
        _,fn,rd,rs,rt=h
        v=mu.reg_read(R_(rt)) if rt else 0
        if (fn==0x0a and v==0) or (fn==0x0b and v!=0):
            mu.reg_write(R_(rd), mu.reg_read(R_(rs)) if rs else 0)
    elif h[0]=='mci':
        _,tf,rd,rs,_=h
        c=int(ccs[seen[a][1]])      # Unicorn's FCC registers read as 0, so the compare is redone here
        if c==tf: mu.reg_write(R_(rd), mu.reg_read(R_(rs)) if rs else 0)
    elif h[0]=='mcf':
        _,tf,fd,fs,_=h
        c=int(ccs[seen[a][1]])
        if c==tf: mu.reg_write(F(fd), mu.reg_read(F(fs)))




def enable_fr1(mu):
    """Run with 32 independent 64-bit floating-point registers, as the N32 ABI assumes.

    The libraries convert and multiply doubles in odd-numbered registers (`cvt.d.s $f7,$f7`).
    With Status.FR clear the core treats that as a reserved instruction and stops silently
    with the program counter at 0. Status.FR is bit 26 and Status.CU1 (floating-point unit
    enabled) bit 29.
    """
    st = mu.reg_read(mc.UC_MIPS_REG_CP0_STATUS)
    mu.reg_write(mc.UC_MIPS_REG_CP0_STATUS, st | (1 << 26) | (1 << 29))


def install(mu, start, end):
    """Make [start, end) of the emulated image runnable; returns the hook table."""
    enable_fr1(mu)
    hooks, seen, ccs = {}, {}, {}
    n, _, conflicts = patch(mu, start, end, seen)
    if conflicts:
        raise SystemExit('compares overlap, folding condition codes is not safe: %s' % conflicts)
    patch_cop1x(mu, start, end, hooks)
    patch_moves(mu, start, end, hooks)

    def on_code(mu, a, s, u):
        if a in hooks:
            if isinstance(hooks[a][0], int):
                emu_cop1x(mu, a, hooks)
            else:
                emu_move(mu, a, hooks, seen, ccs)
        elif a in seen and seen[a][0] == 'cmp':
            emu_cmp(mu, a, seen, ccs)
    mu.hook_add(UC_HOOK_CODE, on_code)
    return hooks
