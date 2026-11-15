#!/usr/bin/env python3
"""Hand-encoded IA-64 bundles and the listing they must give.

  synthetic.py               check the reference decoder (tools/ia64_isa.py)
  synthetic.py write DIR     write DIR/synthetic.bin for run-ghidra.sh
  synthetic.py check SLOTS   check run-ghidra.sh's slots.tsv for that image
  synthetic.py check-emu OUT check EmuSynthetic.java's output (DIR/emu.tsv is its spec)
  synthetic.py addr          the address of the status function, for DecompileAt.java
  synthetic.py check-dec C   check DecompileAt.java's C for it
  synthetic.py caller        the address of the calling function (run DecompileAt with r1=1000)
  synthetic.py check-call C  check DecompileAt.java's C for it
  synthetic.py pal           the address of the br.ia function (run DecompileAt with pal=ADDR)
  synthetic.py check-pal C   check DecompileAt.java's C for it, and check-plain C for the same
                             code decompiled without the pal flag
  synthetic.py predloop      the address of the predicate save and restore loop
  synthetic.py check-predloop C  check DecompileAt.java's C for it: it decompiles
  synthetic.py breaks        the addresses of the three break functions (BUG, a system call, predicated)
  synthetic.py check-breaks DIR  check DecompileAt.java's C for them: `break 0` ends its function
  synthetic.py voids         the addresses of the store, caller and r8 functions (run DecompileAt with sigs)
  synthetic.py check-voids DIR  check their C: the first two are void, the third returns a value
  synthetic.py frames        the addresses of the register stack programs' functions
  synthetic.py check-frames DIR  check DecompileAt.java's C for them

The encodings are built here from the instruction formats of the Intel
Itanium Architecture SDM rev 2.3 vol 3 (323207) chapter 4; the expected text
is the GNU assembler syntax, compared after check.py's normalisation.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
sys.path.insert(0, HERE)
import ia64_isa as isa  # noqa: E402
from check import norm  # noqa: E402

BASE = 0x80000


def slot(*fields, qp=0):
    """A 41-bit slot from (low bit, width, value) triples."""
    v = qp
    for lo, w, val in fields:
        v |= (val & ((1 << w) - 1)) << lo
    return v


def bundle(t, s0, s1, s2):
    return (t | (s0 << 5) | (s1 << 46) | (s2 << 87)).to_bytes(16, 'little')


def op(n):
    return (37, 4, n)


NOP_M = slot(op(0), (27, 4, 1))
NOP_I = slot(op(0), (27, 6, 1))
NOP_F = slot(op(0), (27, 6, 1))
NOP_B = slot(op(2))


def rel(target, here, *parts):
    """Branch displacement fields for target, from the bundle at here."""
    d = (target - here) >> 4
    out, pos = [], 0
    for lo, w in parts:
        out.append((lo, w, d >> pos))
        pos += w
    return out


def cases():
    """[(bundle bytes, [(slot offset, expected text)])], laid out from BASE."""
    out = []

    def add(t, s0, s1, s2, expect):
        out.append((bundle(t, s0, s1, s2), expect))
    # MII, no stop: adds with a negative 14-bit immediate.
    add(0x00, NOP_M, slot(op(8), (34, 2, 2), (6, 7, 12), (20, 7, 12), (13, 7, -16), (27, 6, -1), (36, 1, 1)),
        NOP_I, [(0, 'nop.m 0x0'), (6, 'adds r12=-16,r12'), (12, 'nop.i 0x0')])
    # MI;;I;;: cr.lid read, extr.u, and dep.z shown as its shl alias.
    add(0x03, slot(op(1), (27, 6, 0x24), (6, 7, 2), (20, 7, 64)),
        slot(op(5), (34, 2, 1), (6, 7, 2), (20, 7, 2), (14, 6, 23), (27, 6, 3)),
        slot(op(5), (34, 2, 1), (33, 1, 1), (6, 7, 2), (13, 7, 2), (20, 6, 59), (27, 6, 59)),
        [(0, 'mov r2=cr.lid'), (6, 'extr.u r2=r2,23,4;;'), (12, 'shl r2=r2,4;;')])
    # MLX: movl takes its upper bits from the L slot.
    imm = 0x8000008150031500
    lslot = (imm >> 22) & (2 ** 41 - 1)
    x = slot(op(6), (6, 7, 3), (13, 7, imm), (27, 9, imm >> 7), (22, 5, imm >> 16), (21, 1, imm >> 21),
             (36, 1, imm >> 63))
    add(0x04, NOP_M, lslot, x, [(0, 'nop.m 0x0'), (6, 'movl r3=0x8000008150031500')])
    # MIB;;: acquire load, compare into a predicate pair, predicated branch.
    here = BASE + 16 * len(out)
    add(0x11, slot(op(4), (30, 6, 0x17), (6, 7, 8), (20, 7, 2)),
        slot(op(0xe), (34, 2, 2), (6, 6, 6), (27, 6, 7), (20, 7, 8)),
        slot(op(4), (33, 2, 2), *rel(here + 0x40, here, (13, 20), (36, 1)), qp=6),
        [(0, 'ld8.acq r8=[r2]'), (6, 'cmp.eq p6,p7=0,r8'),
         (12, '(p06) br.cond.dptk.few %#x;;' % (here + 0x40))])
    # BBB;;: a call, the return, a nop.
    here = BASE + 16 * len(out)
    add(0x17, slot(op(5), (12, 1, 1), *rel(here - 0x100, here, (13, 20), (36, 1))),
        slot(op(0), (27, 6, 0x21), (6, 3, 4), (12, 1, 1)), NOP_B,
        [(0, 'br.call.sptk.many b0=%#x' % (here - 0x100)), (6, 'br.ret.sptk.many b0'), (12, 'nop.b 0x0;;')])
    # MMI: alloc, release store, mov from ip.
    add(0x08, slot(op(1), (33, 3, 6), (6, 7, 34), (13, 7, 4), (20, 7, 3)),
        slot(op(4), (30, 6, 0x37), (20, 7, 14), (13, 7, 15)),
        slot(op(0), (27, 6, 0x30), (6, 7, 1)),
        [(0, 'alloc r34=ar.pfs,4,3,0'), (6, 'st8.rel [r14]=r15'), (12, 'mov r1=ip')])
    # MMI;;: model-specific and cpuid reads through a general register.
    add(0x09, slot(op(1), (27, 6, 0x16), (6, 7, 9), (20, 7, 10)),
        slot(op(1), (27, 6, 0x17), (6, 7, 11), (20, 7, 10)), NOP_I,
        [(0, 'mov r9=msr[r10]'), (6, 'mov r11=cpuid[r10]'), (12, 'nop.i 0x0;;')])
    # M;;MI: srlz.d, then an M-unit encoding (opcode 0, x4 1, x2 2) that has
    # no published meaning: shown as unknown with its raw bits.
    add(0x0a, slot(op(0), (27, 4, 0), (31, 2, 3)), slot(op(0), (27, 4, 1), (31, 2, 2)), NOP_I,
        [(0, 'srlz.d;;'), (6, 'unknown.m 0x108000000'), (12, 'nop.i 0x0')])
    # MIB: B-unit opcode 0 with x6 9 is unassigned too.
    add(0x10, NOP_M, NOP_I, slot(op(0), (27, 6, 9)),
        [(0, 'nop.m 0x0'), (6, 'nop.i 0x0'), (12, 'unknown.b 0x48000000')])
    # MFB;;: rsm, nop.f, rfi.
    add(0x1d, slot(op(0), (27, 4, 7), (6, 21, 0x6000)), NOP_F, slot(op(0), (27, 6, 8)),
        [(0, 'rsm 0x6000'), (6, 'nop.f 0x0'), (12, 'rfi;;')])
    # MIB: mov to ar.lc and a counted loop branch.
    here = BASE + 16 * len(out)
    add(0x10, NOP_M, slot(op(0), (27, 6, 0x2a), (20, 7, 65), (13, 7, 16)),
        slot(op(4), (6, 3, 5), *rel(here - 0x30, here, (13, 20), (36, 1))),
        [(0, 'nop.m 0x0'), (6, 'mov.i ar.lc=r16'), (12, 'br.cloop.sptk.few %#x' % (here - 0x30))])
    # A reserved template: nothing in it decodes.
    add(0x06, 0, 0, 0, [(0, 'unknown 0x0'), (6, 'unknown 0x0'), (12, 'unknown 0x0')])
    # MFI: fma in slot 1, dep in slot 2 whose r1 straddles the slot-2 carry.
    add(0x0c, NOP_M, slot(op(8), (34, 2, 1), (6, 7, 6), (20, 7, 7), (27, 7, 8), (13, 7, 9)),
        slot(op(4), (6, 7, 14), (13, 7, 15), (20, 7, 16), (31, 6, 55), (27, 4, 7)),
        [(0, 'nop.m 0x0'), (6, 'fma.s1 f6=f7,f8,f9'), (12, 'dep r14=r15,r16,8,8')])
    # MMF: getf/setf and xma with f0, which reads as xmpy.l.
    add(0x0e, slot(op(4), (27, 1, 1), (30, 6, 0x1c), (6, 7, 8), (13, 7, 6)),
        slot(op(6), (27, 1, 1), (30, 6, 0x1c), (6, 7, 6), (13, 7, 9)),
        slot(op(0xe), (36, 1, 1), (6, 7, 6), (20, 7, 7), (27, 7, 8)),
        [(0, 'getf.sig r8=f6'), (6, 'setf.sig f6=r9'), (12, 'xmpy.l f6=f7,f8')])
    # MII;; with predicates in slots 1 and 2 and a high register in slot 2.
    add(0x01, NOP_M, slot(op(8), (34, 2, 2), (6, 7, 127), (20, 7, 1), (13, 7, 5), qp=63),
        slot(op(8), (6, 7, 125), (13, 7, 126), (20, 7, 127), qp=17),
        [(0, 'nop.m 0x0'), (6, '(p63) adds r127=5,r1'), (12, '(p17) add r125=r126,r127;;')])
    return out


def emu_cases():
    """[(bundle bytes, text expectations, name, steps, regs, memory, expected)]
    laid out after cases(): each is run in Ghidra's emulator and its result
    compared with the SDM's semantics."""
    out = []

    def add(t, s0, s1, s2, expect, name, steps, regs, mem, want):
        out.append((bundle(t, s0, s1, s2), expect, name, steps, regs, mem, want))

    def extr(pos, length, r1=9, r3=10):
        return slot(op(5), (34, 2, 1), (33, 1, 0), (13, 1, 1), (6, 7, r1), (20, 7, r3), (14, 6, pos),
                    (27, 6, length - 1))
    ones = 'f0f0f0f0f0f0f0f0'
    for name, pos, length, r10, want, text in [
            ('extr in range', 8, 8, ones, 'fffffffffffffff0', 'extr r9=r10,8,8'),
            # pos + len > 64: len is cut to 64 - pos (SDM vol 3, extr).
            ('extr clamps len', 60, 8, ones, 'ffffffffffffffff', 'extr r9=r10,60,8'),
            ('extr len 64', 32, 64, '8000000012345678', 'ffffffff80000000', 'extr r9=r10,32,64')]:
        add(0x00, NOP_M, extr(pos, length), NOP_I, [(6, text)], name, 2, {'r10': r10}, {}, {'r9': want})
    # ld8 r9=[r10],r9: the increment is r9 before the load overwrites it.
    ld = slot(op(4), (36, 1, 1), (30, 6, 0x03), (6, 7, 9), (13, 7, 9), (20, 7, 10))
    add(0x08, ld, NOP_M, NOP_I, [(0, 'ld8 r9=[r10],r9')], 'ld post-increment by its own target', 1,
        {'r9': '8', 'r10': '100000'}, {'100000': '1122334455667788'},
        {'r9': '1122334455667788', 'r10': '100008'})
    return out


def status_function():
    """A function that sets r8 only through complementary predicated moves:
    r8 = r32 == 0 ? 0 : -33. Its decompilation must return a value."""
    imm = -33
    cmp_ = slot(op(0xe), (34, 2, 2), (6, 6, 6), (27, 6, 7), (20, 7, 32))
    mov = [slot(op(8), (34, 2, 2), (6, 7, 8), (20, 7, 0), (13, 7, v), (27, 6, v >> 7), (36, 1, v < 0), qp=q)
           for q, v in ((6, 0), (7, imm))]
    ret = slot(op(0), (27, 6, 0x21), (6, 3, 4), (12, 1, 1))
    return [bundle(0x01, NOP_M, cmp_, NOP_I), bundle(0x10, mov[0], mov[1], ret)]


def function_addr():
    return BASE + 16 * (len(cases()) + len(emu_cases()))


def caller_addr():
    return function_addr() + 16 * len(status_function())


def caller_function():
    """A frame of two locals (the saved ar.pfs and a copy of gp) and one output,
    which a call passes: the call has exactly one argument."""
    here = caller_addr() + 16
    alloc = slot(op(1), (33, 3, 6), (6, 7, 32), (13, 7, 3), (20, 7, 2))
    mov_gp = slot(op(8), (34, 2, 2), (6, 7, 33), (20, 7, 1), (13, 7, 0))
    out0 = slot(op(8), (34, 2, 2), (6, 7, 34), (20, 7, 12), (13, 7, 16))
    call = slot(op(5), (12, 1, 1), *rel(BASE, here, (13, 20), (36, 1)))
    ret = slot(op(0), (27, 6, 0x21), (6, 3, 4), (12, 1, 1))
    return [bundle(0x01, alloc, mov_gp, out0), bundle(0x17, call, NOP_B, NOP_B),
            bundle(0x17, ret, NOP_B, NOP_B)]


def pal_addr():
    return caller_addr() + 16 * len(caller_function())


def pal_function():
    """r5 = 1; br.ia; return r1 in r8. Flagged as a PAL service site it must decompile
    to a call that returns r1 and carries on; unflagged it stays an IA-32 branch."""
    mov5 = slot(op(8), (34, 2, 2), (6, 7, 5), (20, 7, 0), (13, 7, 1))
    br_ia = slot(op(0), (27, 6, 0x20), (6, 3, 1), (13, 3, 0))
    mov8 = slot(op(8), (34, 2, 2), (6, 7, 8), (20, 7, 1), (13, 7, 0))
    ret = slot(op(0), (27, 6, 0x21), (6, 3, 4), (12, 1, 1))
    return [bundle(0x11, NOP_M, mov5, br_ia), bundle(0x10, NOP_M, mov8, ret)]


# Encoders for the register stack programs (SDM vol 3 chapter 4 formats).
def adds(r1, imm, r3=0, qp=0):         # A4
    return slot(op(8), (34, 2, 2), (6, 7, r1), (20, 7, r3), (13, 7, imm), (27, 6, imm >> 7), (36, 1, imm < 0), qp=qp)


def add(r1, r2, r3, qp=0):              # A1
    return slot(op(8), (6, 7, r1), (13, 7, r2), (20, 7, r3), qp=qp)


def alloc(r1, sof, sol, sor=0):         # M34
    return slot(op(1), (33, 3, 6), (6, 7, r1), (13, 7, sof), (20, 7, sol), (27, 4, sor >> 3))


def mov_from_b(r1, b2):                 # I22
    return slot(op(0), (27, 6, 0x31), (6, 7, r1), (13, 3, b2))


def mov_to_b(b1, r2):                   # I21
    return slot(op(0), (33, 3, 7), (20, 2, 1), (6, 3, b1), (13, 7, r2))


def mov_i_ar(ar, r2):                   # I26
    return slot(op(0), (27, 6, 0x2a), (20, 7, ar), (13, 7, r2))


def mov_i_ar_imm(ar, imm):              # I27
    return slot(op(0), (27, 6, 0x0a), (20, 7, ar), (13, 7, imm), (36, 1, imm < 0))


def mov_m_ar(ar, r2):                   # M29
    return slot(op(1), (27, 6, 0x2a), (20, 7, ar), (13, 7, r2))


def mov_m_from_ar(r1, ar):              # M31
    return slot(op(1), (27, 6, 0x22), (6, 7, r1), (20, 7, ar))


def mov_pr_rot(value):                  # I24: value is the predicate mask from p16
    return slot(op(0), (33, 3, 2), (6, 27, value >> 16), (36, 1, value < 0))


def ld8_inc(r1, r3, imm, qp=0):        # M3
    return slot(op(5), (30, 6, 0x03), (6, 7, r1), (20, 7, r3), (13, 7, imm), (27, 1, imm >> 7), (36, 1, imm < 0),
                qp=qp)


def br_call(target, here):              # B3
    return slot(op(5), (12, 1, 1), *rel(target, here, (13, 20), (36, 1)))


def br_loop(btype, target, here):       # B1: 7 ctop, 6 cexit, 3 wtop, 2 wexit
    return slot(op(4), (6, 3, btype), (12, 1, 1), *rel(target, here, (13, 20), (36, 1)))


BR_RET = slot(op(0), (27, 6, 0x21), (6, 3, 4), (12, 1, 1))
COVER = slot(op(0), (27, 6, 0x02))
CLRRRB = slot(op(0), (27, 6, 0x04))
RFI = slot(op(0), (27, 6, 0x08))
FLUSHRS = slot(op(0), (27, 4, 0xc))
LOADRS = slot(op(0), (27, 4, 0xa))
AR = {'bsp': 17, 'bspstore': 18, 'pfs': 64, 'lc': 65, 'ec': 66}


def programs_addr():
    return pal_addr() + 16 * len(pal_function())


def programs():
    """Multi-bundle programs for the register stack: [(name, [(bundle, [(slot offset,
    text)])])], laid out after caller_function(). Addresses come from prog_addrs()."""
    a = prog_addrs()
    calls, cov = a['calls'], a['cover']
    f1, f2 = calls + 0x50, calls + 0xa0
    out = []
    # Nested calls. main (sof 6, sol 4) passes 5 and 7 to f1 (sof 10, sol 7), which
    # passes 12 and 3 to f2 (sof 5, sol 5), which clobbers its own r33 (f1's r40).
    main = [
        (bundle(0x01, alloc(35, 6, 4), adds(32, 0x11), adds(33, 0x22)),
         [(0, 'alloc r35=ar.pfs,6,4,0'), (6, 'adds r32=17,r0'), (12, 'adds r33=34,r0;;')]),
        (bundle(0x01, adds(36, 5), adds(37, 7), mov_from_b(34, 0)),
         [(0, 'adds r36=5,r0'), (6, 'adds r37=7,r0'), (12, 'mov r34=b0;;')]),
        (bundle(0x17, br_call(f1, calls + 0x20), NOP_B, NOP_B),
         [(0, 'br.call.sptk.many b0=%#x' % f1), (6, 'nop.b 0x0'), (12, 'nop.b 0x0;;')]),
        (bundle(0x01, add(8, 8, 32), NOP_I, NOP_I), [(0, 'add r8=r8,r32'), (6, 'nop.i 0x0'), (12, 'nop.i 0x0;;')]),
        (bundle(0x11, NOP_M, mov_i_ar(AR['pfs'], 35), BR_RET),
         [(0, 'nop.m 0x0'), (6, 'mov.i ar.pfs=r35'), (12, 'br.ret.sptk.many b0;;')]),
        (bundle(0x01, alloc(38, 10, 7), mov_from_b(34, 0), add(35, 32, 33)),
         [(0, 'alloc r38=ar.pfs,10,7,0'), (6, 'mov r34=b0'), (12, 'add r35=r32,r33;;')]),
        (bundle(0x01, adds(39, 0, 35), adds(40, 3), adds(32, 1, 32)),
         [(0, 'mov r39=r35'), (6, 'adds r40=3,r0'), (12, 'adds r32=1,r32;;')]),
        (bundle(0x17, br_call(f2, calls + 0x70), NOP_B, NOP_B),
         [(0, 'br.call.sptk.many b0=%#x' % f2), (6, 'nop.b 0x0'), (12, 'nop.b 0x0;;')]),
        (bundle(0x01, add(8, 8, 35), add(8, 8, 33), mov_i_ar(AR['pfs'], 38)),
         [(0, 'add r8=r8,r35'), (6, 'add r8=r8,r33'), (12, 'mov.i ar.pfs=r38;;')]),
        (bundle(0x11, NOP_M, mov_to_b(0, 34), BR_RET),
         [(0, 'nop.m 0x0'), (6, 'mov b0=r34'), (12, 'br.ret.sptk.many b0;;')]),
        (bundle(0x01, alloc(34, 5, 5), add(8, 32, 33), adds(33, 100)),
         [(0, 'alloc r34=ar.pfs,5,5,0'), (6, 'add r8=r32,r33'), (12, 'adds r33=100,r0;;')]),
        (bundle(0x11, NOP_M, mov_i_ar(AR['pfs'], 34), BR_RET),
         [(0, 'nop.m 0x0'), (6, 'mov.i ar.pfs=r34'), (12, 'br.ret.sptk.many b0;;')]),
    ]
    out.append(('calls', main))
    # cover, flushrs, loadrs, a move to ar.bspstore, and rfi back into the covered frame.
    out.append(('cover', [
        (bundle(0x01, alloc(35, 4, 4), adds(32, 0x11), adds(33, 0x22)),
         [(0, 'alloc r35=ar.pfs,4,4,0'), (6, 'adds r32=17,r0'), (12, 'adds r33=34,r0;;')]),
        (bundle(0x11, NOP_M, NOP_I, COVER), [(0, 'nop.m 0x0'), (6, 'nop.i 0x0'), (12, 'cover;;')]),
        (bundle(0x01, alloc(34, 3, 3), adds(32, 0x55), adds(33, 0x66)),
         [(0, 'alloc r34=ar.pfs,3,3,0'), (6, 'adds r32=85,r0'), (12, 'adds r33=102,r0;;')]),
        (bundle(0x09, FLUSHRS, mov_m_from_ar(16, AR['bsp']), NOP_I),
         [(0, 'flushrs'), (6, 'mov.m r16=ar.bsp'), (12, 'nop.i 0x0;;')]),
        (bundle(0x09, mov_m_from_ar(17, AR['bspstore']), NOP_M, NOP_I),
         [(0, 'mov.m r17=ar.bspstore'), (6, 'nop.m 0x0'), (12, 'nop.i 0x0;;')]),
        (bundle(0x09, LOADRS, mov_m_from_ar(18, AR['bspstore']), NOP_I),
         [(0, 'loadrs'), (6, 'mov.m r18=ar.bspstore'), (12, 'nop.i 0x0;;')]),
        (bundle(0x09, mov_m_ar(AR['bspstore'], 19), NOP_M, NOP_I),
         [(0, 'mov.m ar.bspstore=r19'), (6, 'nop.m 0x0'), (12, 'nop.i 0x0;;')]),
        (bundle(0x11, mov_m_from_ar(20, AR['bsp']), NOP_I, RFI),
         [(0, 'mov.m r20=ar.bsp'), (6, 'nop.i 0x0'), (12, 'rfi;;')]),
        (bundle(0x01, NOP_M, NOP_I, NOP_I), [(0, 'nop.m 0x0'), (6, 'nop.i 0x0'), (12, 'nop.i 0x0;;')]),
    ]))
    # A modulo-scheduled sum of three qwords at [r14]: stage 1 loads into r32,
    # stage 2 adds what rotation has moved to r33 (sof 16, sol 16, sor 8), then clrrrb.
    loop = a['loop']
    body = loop + 0x20
    out.append(('loop', [
        (bundle(0x01, alloc(47, 16, 16, 8), mov_i_ar_imm(AR['lc'], 2), mov_i_ar_imm(AR['ec'], 2)),
         [(0, 'alloc r47=ar.pfs,16,16,8'), (6, 'mov.i ar.lc=2'), (12, 'mov.i ar.ec=2;;')]),
        (bundle(0x01, adds(8, 0), mov_pr_rot(0x10000), NOP_I),
         [(0, 'mov r8=r0'), (6, 'mov pr.rot=0x10000'), (12, 'nop.i 0x0;;')]),
        (bundle(0x11, ld8_inc(32, 14, 8, qp=16), add(8, 8, 33, qp=17), br_loop(7, body, body)),
         [(0, '(p16) ld8 r32=[r14],8'), (6, '(p17) add r8=r8,r33'), (12, 'br.ctop.sptk.many %#x;;' % body)]),
        (bundle(0x11, NOP_M, NOP_I, CLRRRB), [(0, 'nop.m 0x0'), (6, 'nop.i 0x0'), (12, 'clrrrb;;')]),
        (bundle(0x11, NOP_M, mov_i_ar(AR['pfs'], 47), BR_RET),
         [(0, 'nop.m 0x0'), (6, 'mov.i ar.pfs=r47'), (12, 'br.ret.sptk.many b0;;')]),
    ]))
    return out


PROG_SIZES = {'calls': 12, 'cover': 9, 'loop': 5}


def prog_addrs():
    a, out = programs_addr(), {}
    for name in PROG_SIZES:
        out[name] = a
        a += 16 * PROG_SIZES[name]
    return out


def predloop_addr():
    return programs_addr() + 16 * sum(PROG_SIZES.values())


def predloop_function():
    """A loop that saves the predicates with `mov r72=pr` and restores them with `mov pr=r72,-2`,
    as the PAL's FIT walk does around its br.ia: it must decompile."""
    here = predloop_addr()
    save = slot(op(0), (27, 6, 0x33), (6, 7, 72))
    restore = slot(op(0), (33, 3, 3), (13, 7, 72), (6, 7, 0x7f), (24, 8, 0xff), (36, 1, 1))
    loop = slot(op(4), (6, 3, 0), (12, 1, 1), *rel(here, here + 0x20, (13, 20), (36, 1)), qp=21)
    return [bundle(0x01, NOP_M, NOP_I, save), bundle(0x01, NOP_M, restore, NOP_I),
            bundle(0x11, NOP_M, NOP_I, loop), bundle(0x17, BR_RET, NOP_B, NOP_B)]


def breaks_addr():
    return predloop_addr() + 16 * 4


def break_functions():
    """Three functions that run `break.m IMM` and then `r8 = 0x77`: with IMM 0 (the kernel's BUG())
    the code behind the break is not part of the function; with a system call's immediate, or with
    a qualifying predicate, it is."""
    out = []
    for imm, qp in ((0, 0), (0x1234, 0), (0, 6)):
        brk = slot(op(0), (6, 20, imm), (36, 1, imm >> 20), qp=qp)
        mov8 = slot(op(8), (34, 2, 2), (6, 7, 8), (20, 7, 0), (13, 7, 0x77))
        out += [bundle(0x00, brk, NOP_I, NOP_I), bundle(0x11, NOP_M, mov8, BR_RET)]
    return out


def check_breaks(d):
    a = breaks_addr()
    bug, sysc, pred = (open(os.path.join(d, '%#x.c' % x)).read() for x in (a, a + 32, a + 64))
    ok = '0x77' not in bug and '0x77' in sysc and '0x77' in pred and 'decompile failed' not in bug + sysc + pred
    print('%s: break 0 ends the function, a system call break or a predicated break does not' % ('ok' if ok else 'FAIL break'))
    return 0 if ok else 1


def voids_addr():
    return breaks_addr() + 16 * 6


def void_functions():
    """A function that only stores through r32, one that calls it, and one that sets r8:
    IA64Signatures makes the first two return void and leaves the third a value."""
    here = voids_addr()
    st8 = slot(op(4), (30, 6, 0x34), (20, 7, 32), (13, 7, 33))
    call = br_call(here, here + 0x20)
    return [bundle(0x01, st8, NOP_I, NOP_I), bundle(0x17, BR_RET, NOP_B, NOP_B),
            bundle(0x17, call, NOP_B, NOP_B), bundle(0x17, BR_RET, NOP_B, NOP_B)] + status_function()


def check_voids(d):
    a = voids_addr()
    store, caller, status = (open(os.path.join(d, '%#x.c' % x)).read() for x in (a, a + 0x20, a + 0x40))
    ok = all(t.lstrip().startswith('void ') for t in (store, caller)) and not status.lstrip().startswith('void ')
    print('%s: functions that never write r8 return void' % ('ok' if ok else 'FAIL void return'))
    return 0 if ok else 1


def prog_runs():
    """Emulator runs over programs(): (name, start, stop, regs, memory, expected)."""
    a = prog_addrs()
    calls, cov, loop = a['calls'], a['cover'], a['loop']
    return [
        # f2 returns 12 + 3; f1 adds its preserved r35 (12) and r33 (7); main adds its r32.
        # main's outputs come back as f1's r32 and r33 when f1 returned (SDM vol 3 br.ret).
        ('nested calls keep each frame', calls, calls + 0x40, {'ar.bsp': '1000'}, {},
         {'r8': '33', 'r32': '11', 'r33': '22', 'r36': '6', 'r37': '7', 'ar.bsp': '1000',
          'ar.pfs': '206', 'cfm_sof': '6', 'cfm_sol': '4'}),
        # cover adds the 4-register frame to the dirty partition and records it in cr.ifs;
        # loadrs leaves 0x18 bytes dirty; the move to ar.bspstore keeps them; rfi takes the
        # frame back (the last of its registers below a NaT collection slot) and resumes at
        # slot 1 of cr.iip.
        ('cover flushrs loadrs rfi', cov, calls + 6,
         {'ar.bsp': '1000', 'ar.bspstore': '1000', 'ar.rsc': '180000', 'r19': '2000',
          'cr.iip': '%x' % calls, 'cr.ipsr': '20000000000'}, {},
         {'r16': '1020', 'r17': '1020', 'r18': '1008', 'r20': '2018', 'cr.ifs': '8000000000000204',
          'r32': '11', 'r33': '22', 'cfm_sof': '4', 'cfm_sol': '4', 'ar.bsp': '1ff0',
          'psr': '20000000000'}),
        # Four rotations: the loads (1, 2, 4) went to the registers r32 named at rrb 0, -1, -2.
        ('loop rotates gr fr and pr', loop, loop + 0x30, {'r14': '100000', 'f32': '1234'},
         {'100000': '1', '100008': '2', '100010': '4'},
         {'r8': '7', 'r36': '1', 'r35': '2', 'r34': '4', 'f36': '1234', 'p16': '0', 'p20': '1',
          'rrb_gr': '4', 'rrb_fr': '5c', 'rrb_pr': '2c', 'ar.lc': '0', 'ar.ec': '0'}),
        ('clrrrb puts the rotation back', loop, loop + 0x40, {'r14': '100000', 'f32': '1234'},
         {'100000': '1', '100008': '2', '100010': '4'},
         {'r32': '1', 'r39': '2', 'r38': '4', 'f32': '1234', 'rrb_gr': '0', 'rrb_fr': '0', 'rrb_pr': '0'}),
    ]


def image():
    return (b''.join(b for b, _ in cases()) + b''.join(c[0] for c in emu_cases())
            + b''.join(status_function()) + b''.join(caller_function()) + b''.join(pal_function())
            + b''.join(b for _, prog in programs() for b, _ in prog) + b''.join(predloop_function())
            + b''.join(break_functions()) + b''.join(void_functions()))


def expected():
    res = {}
    for i, (_, exp) in enumerate(cases()):
        for off, text in exp:
            res[BASE + 16 * i + off] = text
    n = len(cases())
    for i, c in enumerate(emu_cases()):
        for off, text in c[1]:
            res[BASE + 16 * (n + i) + off] = text
    a = programs_addr()
    for _, prog in programs():
        for b, exp in prog:
            for off, text in exp:
                res[a + off] = text
            a += 16
    return res


def emu_spec():
    """Lines for EmuSynthetic.java."""
    n = len(cases())
    lines = []
    for i, (_, _, name, steps, regs, mem, want) in enumerate(emu_cases()):
        lines.append('\t'.join([
            name.replace(' ', '_'), '%x' % (BASE + 16 * (n + i)), str(steps),
            ','.join('%s=%s' % kv for kv in regs.items()), ','.join('%s=%s' % kv for kv in mem.items()),
            ','.join('%s=%s' % kv for kv in want.items())]))
    for name, start, stop, regs, mem, want in prog_runs():
        lines.append('\t'.join([
            name.replace(' ', '_'), '%x' % start, '@%x' % stop,
            ','.join('%s=%s' % kv for kv in regs.items()), ','.join('%s=%s' % kv for kv in mem.items()),
            ','.join('%s=%s' % kv for kv in want.items())]))
    return '\n'.join(lines) + '\n'


def check_dec(path):
    """The decompiled status function must return r8, not void."""
    text = open(path).read()
    ok = not text.lstrip().startswith('void') and re.search(r'\breturn [^;]+;', text)
    print('%s: %s' % ('status function returns a value' if ok else 'FAIL status function came out void', path))
    return 0 if ok else 1


def check_call(path):
    """The decompiled caller passes one argument: not the saved gp beside it."""
    text = open(path).read()
    m = re.search(r'\b\w+_(?:0x)?00080000\(([^;]*)\);', text)
    ok = m is not None and m.group(1).count(',') == 0 and m.group(1).strip() != ''
    print('%s: %s' % ('call passes one argument' if ok else 'FAIL call arguments (%s)' % (m and m.group(1)), path))
    return 0 if ok else 1


def check_pal(path):
    """A flagged br.ia is a service call whose result is r1, and the code after it is reached."""
    text = open(path).read()
    ok = 'pal_special_service(' in text and 'br_ia' not in text and re.search(r'\breturn [^;]+;', text)
    print('%s: %s' % ('flagged br.ia is a service call' if ok else 'FAIL flagged br.ia', path))
    return 0 if ok else 1


def check_plain(path):
    """Unflagged, br.ia keeps its IA-32 branch semantics."""
    text = open(path).read()
    ok = 'br_ia(' in text and 'pal_special_service' not in text
    print('%s: %s' % ('plain br.ia stays a branch' if ok else 'FAIL plain br.ia', path))
    return 0 if ok else 1


def check_predloop(path):
    """The decompiler once failed on this loop ("Unable to find unique hash for varnode")."""
    text = open(path).read()
    ok = not text.lstrip().startswith('// decompile failed') and 'while' in text
    print('%s: %s' % ('predicate save and restore loop decompiles' if ok else 'FAIL predicate loop', path))
    return 0 if ok else 1


def frame_functions():
    """The functions of programs() a decompiler check reads: main, f1, f2, the loop."""
    a = prog_addrs()
    return [a['calls'], a['calls'] + 0x50, a['calls'] + 0xa0] + [a['loop']]


def check_frames(d):
    """Each call passes exactly the callee's arguments, each function returns r8, and
    the pipelined loop adds what it loaded."""
    main, f1, f2, *more = (open(os.path.join(d, '%#x.c' % a)).read() for a in frame_functions())
    checks = [
        ('main passes f1 5 and 7', re.search(r'= \w+_%08x\(5,7\);' % frame_functions()[1], main)),
        ('main returns what f1 did plus its own r32', re.search(r'return \w+ \+ 0x11;', main)),
        ('f1 takes two parameters', re.search(r'\w+_%08x\(\w+ param_1,\w+ param_2\)' % frame_functions()[1], f1)),
        ('f1 passes f2 its sum and 3', re.search(r'\w+_%08x\(param_1 \+ param_2,3\);' % frame_functions()[2], f1)),
        ('f2 returns the sum of its two', re.search(r'return param_1 \+ param_2;', f2)),
    ]
    checks.append(('the loop accumulates and returns', re.search(r'(\w+) = \1 \+ \w+;(?s:.*)return \1;', more[0])))
    bad = 0
    for name, ok in checks:
        if not ok:
            print('FAIL %s' % name)
            bad += 1
    print('%d of %d register stack decompile checks as expected' % (len(checks) - bad, len(checks)))
    return 1 if bad else 0


def check_emu(path):
    bad = 0
    got = dict(line.rstrip('\n').split(' ', 1) for line in open(path))
    names = [c[2] for c in emu_cases()] + [r[0] for r in prog_runs()]
    for name in names:
        res = got.get(name.replace(' ', '_'), 'missing')
        if res != 'PASS':
            print('FAIL %s: %s' % (name, res))
            bad += 1
    print('%d of %d emulated cases as expected' % (len(names) - bad, len(names)))
    return 1 if bad else 0


def compare(got):
    bad = 0
    for addr, text in sorted(expected().items()):
        g = got.get(addr)
        if g is None or norm(g) != norm(text):
            print('FAIL %#x: want "%s", got "%s"' % (addr, text, g))
            bad += 1
    print('%d of %d slots as expected' % (len(expected()) - bad, len(expected())))
    return 1 if bad else 0


def reference():
    got = {}
    data = image()
    for off in range(0, len(data), 16):
        for a, p, txt, stop in isa.decode_bundle(data[off:off + 16], BASE + off):
            got[a] = ('(p%02d) ' % p if p else '') + (txt or '<none>') + (';;' if stop else '')
    exp = expected()
    # The reference decoder leaves undecodable slots as None; the module shows
    # them as unknown, so compare only the decodable ones here.
    for a, text in exp.items():
        if text.startswith('unknown') and got.get(a, '').startswith('<none>'):
            got[a] = text
    return compare(got)


def main():
    if len(sys.argv) == 1:
        return reference()
    if sys.argv[1] == 'write':
        os.makedirs(sys.argv[2], exist_ok=True)
        with open(os.path.join(sys.argv[2], 'synthetic.bin'), 'wb') as f:
            f.write(image())
        with open(os.path.join(sys.argv[2], 'emu.tsv'), 'w') as f:
            f.write(emu_spec())
        return 0
    if sys.argv[1] == 'check':
        got = {}
        for line in open(sys.argv[2]):
            addr, text = line.rstrip('\n').split('\t', 1)
            got[int(addr.split(':')[-1], 16)] = text
        return compare(got)
    if sys.argv[1] == 'addr':
        print('%#x' % function_addr())
        return 0
    if sys.argv[1] == 'caller':
        print('%#x' % caller_addr())
        return 0
    if sys.argv[1] == 'pal':
        print('%#x' % pal_addr())
        return 0
    if sys.argv[1] == 'check-pal':
        return check_pal(sys.argv[2])
    if sys.argv[1] == 'check-plain':
        return check_plain(sys.argv[2])
    if sys.argv[1] == 'predloop':
        print('%#x' % predloop_addr())
        return 0
    if sys.argv[1] == 'check-predloop':
        return check_predloop(sys.argv[2])
    if sys.argv[1] == 'breaks':
        print('%#x %#x %#x' % (breaks_addr(), breaks_addr() + 32, breaks_addr() + 64))
        return 0
    if sys.argv[1] == 'check-breaks':
        return check_breaks(sys.argv[2])
    if sys.argv[1] == 'voids':
        print(' '.join('%#x' % (voids_addr() + o) for o in (0, 0x20, 0x40)))
        return 0
    if sys.argv[1] == 'check-voids':
        return check_voids(sys.argv[2])
    if sys.argv[1] == 'frames':
        print(' '.join('%#x' % a for a in frame_functions()))
        return 0
    if sys.argv[1] == 'check-frames':
        return check_frames(sys.argv[2])
    if sys.argv[1] == 'check-call':
        return check_call(sys.argv[2])
    if sys.argv[1] == 'check-dec':
        return check_dec(sys.argv[2])
    if sys.argv[1] == 'check-emu':
        return check_emu(sys.argv[2])
    sys.exit(__doc__)


if __name__ == '__main__':
    sys.exit(main())
