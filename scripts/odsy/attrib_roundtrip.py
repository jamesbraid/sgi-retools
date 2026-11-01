#!/usr/bin/env python3
"""Push, then pop, one attribute-stack group of an IRIX N32 libGLcore under Unicorn.

Usage: attrib_roundtrip.py BINARY MASK [MASK ...] [--push ADDR] [--pop ADDR] [--inventory FILE]

Runs the library's attribute-save routine (default 0xd957f00, the IP30 build's, 3772 bytes) on a
context in which every word from 0x10 to 0x1a000 holds 0x3f000000 | its own offset,
with the group mask MASK, then runs the restore routine (default 0xd958f60, 7472 bytes) on a second
context whose words hold 0x3e000000 | offset, handing it the two records the save made.
It prints the command words the restore sent and every offset of the second context
that changed, split into offsets that now hold the first context's word from the same
offset (a restore that went back where it came from) and the rest.

Library calls and the context's own function-pointer entries (0x2e00 to 0x3000, the
allocator at 0, 4, 8 and 0xc, the dispatch table at +0x17f4) are replaced by stubs that
return 0, except the allocator, which hands out zeroed memory; so a copy the library does
through memcpy is not performed (the call is listed). Instructions the emulator lacks are
replaced by `mips_shim.install`. The emulator keeps 32-bit floating-point registers, so a
routine that holds a double in an odd-numbered register (the viewport group of the restore)
stops there without an error. This is software evidence of what the
shipped code does with those inputs, not of what the board does.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from glcore_probe import Probe, CTX, STACK, DONE, ARGREGS  # noqa: E402
from mips_shim import install  # noqa: E402
from unicorn import Uc, UcError, UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN, UC_MODE_MIPS64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE  # noqa: E402
from unicorn.mips_const import (UC_MIPS_REG_0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_GP,  # noqa: E402
                                UC_MIPS_REG_PC, UC_MIPS_REG_RA, UC_MIPS_REG_SP, UC_MIPS_REG_T9,
                                UC_MIPS_REG_V0)

ALLOC, STUB, TAB, HEAP = 0x38000000, 0x38001000, 0x39000000, 0x3a000000


class RoundTrip(Probe):
    def setup(self):
        mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN)
        for va, msz, data in self.segs:
            lo, hi = va & ~0xfff, (va + msz + 0xfff) & ~0xfff
            try:
                mu.mem_map(lo, hi - lo)
            except UcError:
                pass
            mu.mem_write(va, data)
        for lo, sz in ((0, 0x20000), (CTX, 0x200000), (STACK - 0x10000, 0x20000), (DONE, 0x1000),
                       (ALLOC, 0x2000), (TAB, 0x10000), (HEAP, 0x400000)):
            mu.mem_map(lo, sz)
        for k in range(self.gotsym, len(self.syms)):
            if self.syms[k]['st_value']:
                mu.mem_write(self.got + 4 * (self.loc + k - self.gotsym),
                             struct.pack('>I', self.syms[k]['st_value']))
        self.mu, self.heap = mu, HEAP

    def fill(self, base, pat):
        mu = self.mu
        for o in range(0x10, 0x1a000, 4):
            mu.mem_write(base + o, struct.pack('>I', (pat | o) & 0xffffffff))
        for o in range(0x2e00, 0x3000, 4):
            mu.mem_write(base + o, struct.pack('>I', STUB))
        for o in (0, 4, 8):
            mu.mem_write(base + o, struct.pack('>I', ALLOC))
        mu.mem_write(base + 0xc, struct.pack('>I', STUB))
        mu.mem_write(base + 0x17f4, struct.pack('>I', TAB))
        mu.mem_write(base + 0x168d0, struct.pack('>I', 0))
        mu.mem_write(base + 0xe04, struct.pack('>I', 4))   # light count
        mu.mem_write(base + 0xe10, struct.pack('>I', 6))   # clip-plane count
        mu.mem_write(TAB, struct.pack('>I', STUB) * 0x1000)

    def call(self, addr, args, ctxbase):
        mu = self.mu
        mu.mem_write(0x1010, struct.pack('>I', ctxbase))
        mu.mem_write(0x1018, struct.pack('>I', 0))
        calls, fifo = [], []

        def on_code(mu, a, size, ud):
            if a == DONE:
                mu.emu_stop()
            elif a == ALLOC:
                n1, n2 = mu.reg_read(UC_MIPS_REG_A1) & 0xffffffff, mu.reg_read(UC_MIPS_REG_A2) & 0xffffffff
                n = n1 * n2 if n1 < 0x100 and n2 else n1
                mu.reg_write(UC_MIPS_REG_V0, self.heap)
                self.heap += (n + 15) & ~15
                mu.reg_write(UC_MIPS_REG_PC, mu.reg_read(UC_MIPS_REG_RA))
            elif a == STUB:
                calls.append(('entry', [mu.reg_read(r) & 0xffffffff for r in ARGREGS[:6]]))
                mu.reg_write(UC_MIPS_REG_V0, 0)
                mu.reg_write(UC_MIPS_REG_PC, mu.reg_read(UC_MIPS_REG_RA))
            elif a != addr and a in self.names:
                calls.append((self.names[a], [mu.reg_read(r) & 0xffffffff for r in ARGREGS[:6]]))
                mu.reg_write(UC_MIPS_REG_V0, 0)
                mu.reg_write(UC_MIPS_REG_PC, mu.reg_read(UC_MIPS_REG_RA))

        def on_w(mu, access, a, size, value, ud):
            if size == 4:
                fifo.append(value & 0xffffffff)

        # a write hook over the whole space re-runs a loop's first instruction on this build of
        # Unicorn; hook only the command window
        h1 = mu.hook_add(UC_HOOK_CODE, on_code)
        h2 = mu.hook_add(UC_HOOK_MEM_WRITE, on_w, None, 0x10000, 0x10fff)
        for r in range(1, 32):
            mu.reg_write(UC_MIPS_REG_0 + r, 0)
        for r, v in zip(ARGREGS, args):
            mu.reg_write(r, v)
        mu.reg_write(UC_MIPS_REG_GP, self.gp)
        mu.reg_write(UC_MIPS_REG_SP, STACK)
        mu.reg_write(UC_MIPS_REG_T9, addr)
        mu.reg_write(UC_MIPS_REG_RA, DONE)
        err = None
        try:
            mu.emu_start(addr, DONE, count=5000000)
        except UcError as e:
            if mu.reg_read(UC_MIPS_REG_PC) != 0:
                err = '%s at pc 0x%x' % (e, mu.reg_read(UC_MIPS_REG_PC))
        mu.hook_del(h1)
        mu.hook_del(h2)
        return calls, fifo, err


def ranges(offs):
    out = []
    for o in sorted(offs):
        if out and o == out[-1][1] + 4:
            out[-1][1] = o
        else:
            out.append([o, o])
    return ' '.join('0x%x' % a if a == b else '0x%x-0x%x' % (a, b) for a, b in out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('masks', nargs='+', type=lambda s: int(s, 0))
    ap.add_argument('--push', type=lambda s: int(s, 0), default=0xd957f00)
    ap.add_argument('--pop', type=lambda s: int(s, 0), default=0xd958f60)
    ap.add_argument('--inventory', default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                         '..', 'docs', 'inventory', 'functions.tsv'))
    a = ap.parse_args()
    for mask in a.masks:
        p = RoundTrip(a.binary, a.inventory)
        p.setup()
        ctx_a, ctx_b, slots = CTX, CTX + 0x80000, CTX + 0x1c0000
        install(p.mu, a.push, a.push + 3772)
        install(p.mu, a.pop, a.pop + 7472)
        p.fill(ctx_a, 0x3f000000)
        p.fill(ctx_b, 0x3e000000)
        p.mu.mem_write(slots, b'\0' * 16)
        _, _, e1 = p.call(a.push, [mask, slots, slots + 4], ctx_a)
        rec1, rec2 = struct.unpack('>II', p.mu.mem_read(slots, 8))
        before = bytes(p.mu.mem_read(ctx_b, 0x1a000))
        calls, fifo, e2 = p.call(a.pop, [rec1, rec2], ctx_b)
        after = bytes(p.mu.mem_read(ctx_b, 0x1a000))
        same, other = [], []
        for o in range(0x10, 0x1a000, 4):
            b, v = struct.unpack('>I', before[o:o + 4])[0], struct.unpack('>I', after[o:o + 4])[0]
            if v != b:
                (same if v == (0x3f000000 | o) else other).append((o, v))
        print('mask 0x%x: push %s, pop %s' % (mask, e1 or 'ok', e2 or 'ok'))
        print('  restored from the same offset:', ranges([o for o, _ in same]))
        print('  other changes:', ', '.join('0x%x=0x%x' % x for x in other))
        print('  command words:', ' '.join('0x%x' % w for w in fifo))
        print('  calls:', '; '.join('%s(%s)' % (n, ', '.join('0x%x' % x for x in r)) for n, r in calls))


if __name__ == '__main__':
    sys.exit(main())
