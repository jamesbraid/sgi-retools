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


def image():
    return (b''.join(b for b, _ in cases()) + b''.join(c[0] for c in emu_cases())
            + b''.join(status_function()) + b''.join(caller_function()) + b''.join(pal_function()))


def expected():
    res = {}
    for i, (_, exp) in enumerate(cases()):
        for off, text in exp:
            res[BASE + 16 * i + off] = text
    n = len(cases())
    for i, c in enumerate(emu_cases()):
        for off, text in c[1]:
            res[BASE + 16 * (n + i) + off] = text
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


def check_emu(path):
    bad = 0
    got = dict(line.rstrip('\n').split(' ', 1) for line in open(path))
    for _, _, name, *_ in emu_cases():
        res = got.get(name.replace(' ', '_'), 'missing')
        if res != 'PASS':
            print('FAIL %s: %s' % (name, res))
            bad += 1
    print('%d of %d emulated cases as expected' % (len(emu_cases()) - bad, len(emu_cases())))
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
    if sys.argv[1] == 'check-call':
        return check_call(sys.argv[2])
    if sys.argv[1] == 'check-dec':
        return check_dec(sys.argv[2])
    if sys.argv[1] == 'check-emu':
        return check_emu(sys.argv[2])
    sys.exit(__doc__)


if __name__ == '__main__':
    sys.exit(main())
