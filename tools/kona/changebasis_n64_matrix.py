#!/usr/bin/env python3
"""scripts/changebasis_n64_matrix.py - print the matrix the 64-bit libGLcore routine
`changebasis` applies for each order, by interpreting its instructions.

The O32 routine is run under Unicorn (scripts/changebasis_o32_matrix.py). The
64-bit routine uses the MIPS IV fused multiply-add instructions (madd.d, msub.d,
nmsub.d) that Unicorn does not execute, so this script disassembles the routine
with objdump (address and size from docs/inventory/functions.tsv, usr/gfx/arch/
IP27KONA64/libGLcore.so) and interprets the small instruction subset it uses:
single and double loads and stores, the double arithmetic, 64-bit address
arithmetic, the jump-table `jr` and the closing copy loop. Constants and the
jump table are read from the library's own segments. The routine is linear in
its control values, so the unit vectors of an order n give the n by n matrix
(row r is output r, column c is input c). Needs pyelftools (the toolchain
container has it):

  python3 scripts/changebasis_n64_matrix.py [first_order last_order]
"""
import csv
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import toolchain  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PATH = 'usr/gfx/arch/IP27KONA64/libGLcore.so'
LIB = os.path.join(ROOT, 'root', PATH)
ELF = ELFFile(open(LIB, 'rb'))
segs = [(s['p_vaddr'], s.data()) for s in ELF.iter_segments() if s['p_type'] == 'PT_LOAD']
GP = ELF.get_section_by_name('.got')['sh_addr'] + 0x7ff0


def routine():
    with open(os.path.join(ROOT, 'docs/inventory/functions.tsv'), newline='') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            if r['binary'] == PATH and r['name'] == 'changebasis':
                return int(r['address'], 16), int(r['size'])


START, SIZE = routine()
text = subprocess.run([toolchain.objdump(), '-d', '--no-show-raw-insn',
                       '--start-address=%d' % START, '--stop-address=%d' % (START + SIZE), LIB],
                      capture_output=True, text=True, check=True).stdout


def rd(addr, n):
    for va,d in segs:
        if va<=addr<va+len(d): return d[addr-va:addr-va+n]
    raise Exception('unmapped %x'%addr)
ins = {}
for l in text.splitlines():
    m = re.match(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$', l)
    if m:
        ins[int(m.group(1), 16)] = (m.group(2), m.group(3).split(';')[0].split('<')[0].strip())
M=(1<<64)-1
def f32(x): return struct.unpack('>f',struct.pack('>f',x))[0]
def run(order,vin,stride=1):
    R={'zero':0,'gp':GP,'sp':0x7000,'a0':0x1000,'a1':order,'a2':0x2000,'a3':stride,'ra':0}
    F={}
    mem={}
    for i,v in enumerate(vin): mem[0x1000+4*stride*i]=f32(v)
    outbase=0x2000
    def g(r): return R.get(r,0) if r!='zero' else 0
    def addr(s):
        m=re.match(r'^(-?\d+)\((\w+)\)$',s); return (int(m.group(1))+g(m.group(2)))&M
    pc=min(ins); steps=0; delay=None; prev=0
    def sgn(x): 
        x&=0xffffffff; return x-(1<<32) if x>>31 else x
    while True:
        steps+=1
        if steps>5000: raise Exception('loop')
        if pc not in ins:
            if min(ins)<=pc<=max(ins): pc+=4; continue
            print('BAD pc',hex(pc),'prev',hex(prev)); raise SystemExit
        prev=pc
        op,ops=ins[pc]; a=[x.strip() for x in ops.split(',')] if ops else []
        # execute delay slot first for branches/jumps
        isb=op in('b','jr','beqz','bnez','beq','bne')
        target=None
        if op=='jr':
            if a[0]=='ra': 
                # execute delay then finish
                dop,dops=ins[pc+4]; do(dop,dops,R,F,mem,g,addr,sgn); return [mem.get(outbase+4*stride*i) for i in range(order)]
            target=g(a[0])
        elif op=='b': target=int(a[0].split()[0],16)
        elif op in('beqz','bnez'):
            v=g(a[0]); 
            if (v==0)==(op=='beqz'): target=int(a[1].split()[0],16)
        elif op in('beq','bne'):
            v=(g(a[0])==g(a[1]))
            if v==(op=='beq'): target=int(a[2].split()[0],16)
        if isb:
            dop,dops=ins[pc+4]
            if op=='beqz' and False: pass
            do(dop,dops,R,F,mem,g,addr,sgn)
            pc=target if target is not None else pc+8
        else:
            do(op,ops,R,F,mem,g,addr,sgn); pc+=4
def do(op,ops,R,F,mem,g,addr,sgn):
    a=[x.strip() for x in ops.split(',')] if ops else []
    def gp_(r): return R.get(r,0) if r!='zero' else 0
    def s(r,v): 
        if r!='zero': R[r]=v&M
    def fl(r): return F[r]
    if op=='nop': return
    if op=='move': s(a[0],gp_(a[1]))
    elif op=='li': s(a[0],int(a[1],0))
    elif op in('daddiu','addiu'): s(a[0],gp_(a[1])+int(a[2],0)) if op=='daddiu' else s(a[0],sgn(gp_(a[1])+int(a[2],0)))
    elif op in('daddu',): s(a[0],gp_(a[1])+gp_(a[2]))
    elif op=='addu': s(a[0],sgn(gp_(a[1])+gp_(a[2])))
    elif op=='subu': s(a[0],sgn(gp_(a[1])-gp_(a[2])))
    elif op=='dsubu': s(a[0],gp_(a[1])-gp_(a[2]))
    elif op=='dsll': s(a[0],gp_(a[1])<<int(a[2],0))
    elif op=='sll': s(a[0],sgn(gp_(a[1])<<int(a[2],0)))
    elif op=='sltiu': s(a[0],1 if gp_(a[1])<(int(a[2],0)&M) else 0)
    elif op=='ld': s(a[0],struct.unpack('>Q',rd(addr(a[1]),8))[0])
    elif op=='lw': s(a[0],sgn(struct.unpack('>I',rd(addr(a[1]),4))[0]))
    elif op=='lwc1':
        ad=addr(a[1]); F[a[0]]=mem[ad] if ad in mem else struct.unpack('>f',rd(ad,4))[0]
    elif op=='ldc1':
        ad=addr(a[1]); F[a[0]]=mem[ad] if ad in mem else struct.unpack('>d',rd(ad,8))[0]
    elif op=='sdc1': mem[addr(a[1])]=F.get(a[0],0.0)
    elif op=='mul.s': F[a[0]]=f32(F[a[1]]*F[a[2]])
    elif op=='slti': s(a[0],1 if sgn(gp_(a[1]))<int(a[2],0) else 0)
    elif op=='andi': s(a[0],gp_(a[1])&int(a[2],0))
    elif op=='sra': s(a[0],sgn(gp_(a[1]))>>int(a[2],0))
    elif op=='swc1':
        ad=addr(a[1]); mem[ad]=f32(F[a[0]]) if True else 0
        if ad<0x7000 and False: pass
    elif op=='cvt.d.s': F[a[0]]=F[a[1]]
    elif op=='cvt.s.d': F[a[0]]=f32(F[a[1]])
    elif op=='mul.d': F[a[0]]=F[a[1]]*F[a[2]]
    elif op=='add.d': F[a[0]]=F[a[1]]+F[a[2]]
    elif op=='sub.d': F[a[0]]=F[a[1]]-F[a[2]]
    elif op=='neg.d': F[a[0]]=-F[a[1]]
    elif op=='mov.d': F[a[0]]=F[a[1]]
    elif op=='madd.d': F[a[0]]=F[a[1]]+F[a[2]]*F[a[3]]
    elif op=='msub.d': F[a[0]]=F[a[2]]*F[a[3]]-F[a[1]]
    elif op=='nmadd.d': F[a[0]]=-(F[a[1]]+F[a[2]]*F[a[3]])
    elif op=='nmsub.d': F[a[0]]=F[a[1]]-F[a[2]]*F[a[3]]
    elif op=='mtc1' or op=='dmtc1': F[a[1]]=0.0 if a[0]=='zero' else float(gp_(a[0]))
    else: raise Exception('op '+op+' '+ops)
if __name__=='__main__':
    lo,hi=int(sys.argv[1]),int(sys.argv[2])
    for n in range(lo,hi+1):
        cols=[run(n,[1.0 if k==c else 0.0 for k in range(n)]) for c in range(n)]
        print('order',n)
        for r in range(n): print('  ',[round(cols[c][r],3) for c in range(n)])
