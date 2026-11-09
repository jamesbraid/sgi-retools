#!/usr/bin/env python3
"""Tabulate the board-to-host read header words the N32 libGLcore builds, by running its own routines.

Usage: read_header_sweep.py BINARY
Run it as `tools/re-run python3 scripts/read_header_sweep.py BINARY`: the image has numpy, unicorn and pyelftools.

For each window kind it runs, under Unicorn (the machinery of glcore_probe.py):
  1. __glOdysseyImageDescribeWindow (0x0d989710) on a mode record filled to describe the visual,
     giving the description's pixel class (+0x34), storage code S (+0x2c) and layout code L (+0x30);
  2. __glOdysseyImageCalcXferReadParams (0x0d9bf200) for the requested format and type, giving the
     class (word 4 bits 2:0), the code (bits 7:3) and the class field (bits 15:13);
  3. ImageCalcDmaFieldOffsets (0x0d9beb40) with the depth-or-stencil flag the read builder
     (0x0d9bb8a0) passes, giving the two field codes (bits 23:20 and 27:24).
It prints word 4 with bits 31, 28 and 19:16 left out: they come from the window and the read buffer, and
are the same for every read of one window and buffer. The routines the walk skips (the log2 helper)
return 0, so description +0x28 is -1 here and is not printed. Software evidence only.

The mode-record bytes it fills (context +3376 + offset, the read drawable's record): +4 colour-index
mode flag (0: RGBA), +6 double buffer, +9 depth, +39 index bits, +43/+47/+51/+55 component sizes,
+84 the word the description tests against 1 for 8-bit visuals.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from glcore_probe import Probe, CTX, STACK, DONE, ARGREGS, CTXSZ  # noqa: E402
import mips_shim  # noqa: E402
from unicorn import Uc, UcError, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED  # noqa: E402
from unicorn.mips_const import (UC_MIPS_REG_0, UC_MIPS_REG_GP, UC_MIPS_REG_PC, UC_MIPS_REG_RA,  # noqa: E402
                                UC_MIPS_REG_SP, UC_MIPS_REG_T9, UC_MIPS_REG_V0)
from unicorn import UcError, UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN, UC_MODE_MIPS64  # noqa: E402

DESCRIBE, READPARAMS, FIELDS = 0x0d989710, 0x0d9bf200, 0x0d9beb40
SIZES = {DESCRIBE: 1060, READPARAMS: 3324, FIELDS: 604}
DESC, OUT, F1, F2 = CTX + 0x30000, CTX + 0x31000, CTX + 0x31100, CTX + 0x31104
MODE = CTX + 3376

GL = dict(DEPTH=0x1902, STENCIL=0x1901, CI=0x1900, BGRA=0x80e1, RGBA=0x1908,
          UB=0x1401, US=0x1403, UI=0x1405, UI8888REV=0x8367)


class Run(Probe):
    def call(self, addr, args, pokes=()):
        mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN)
        for va, msz, data in self.segs:
            lo, hi = va & ~0xfff, (va + msz + 0xfff) & ~0xfff
            try:
                mu.mem_map(lo, hi - lo)
            except UcError:
                pass
            mu.mem_write(va, data)
        for lo, sz in ((0, 0x20000), (CTX, CTXSZ), (STACK - 0x10000, 0x20000), (DONE, 0x1000)):
            mu.mem_map(lo, sz)
        for k in range(self.gotsym, len(self.syms)):
            if self.syms[k]['st_value']:
                mu.mem_write(self.got + 4 * (self.loc + k - self.gotsym),
                             struct.pack('>I', self.syms[k]['st_value']))
        mu.mem_write(0x1010, struct.pack('>I', CTX))
        for a, b in pokes:
            mu.mem_write(a, b)
        # the conditional moves the Unicorn MIPS core lacks are done by a code hook
        mips_shim.install(mu, addr, addr + SIZES[addr])

        def on_code(mu, a, size, ud):
            if a == DONE:
                mu.emu_stop()
            elif a != addr and a in self.names:
                mu.reg_write(UC_MIPS_REG_V0, 0)
                mu.reg_write(UC_MIPS_REG_PC, mu.reg_read(UC_MIPS_REG_RA))

        mu.hook_add(UC_HOOK_CODE, on_code)
        for r in range(1, 32):
            mu.reg_write(UC_MIPS_REG_0 + r, 0)
        for r, v in zip(ARGREGS, args):
            mu.reg_write(r, v)
        mu.reg_write(UC_MIPS_REG_GP, self.gp)
        mu.reg_write(UC_MIPS_REG_SP, STACK)
        mu.reg_write(UC_MIPS_REG_T9, addr)
        mu.reg_write(UC_MIPS_REG_RA, DONE)
        try:
            mu.emu_start(addr, DONE, count=2000000)
        except UcError:
            if mu.reg_read(UC_MIPS_REG_PC) != 0:
                raise
        return mu


def w32(mu, a):
    return struct.unpack('>I', bytes(mu.mem_read(a, 4)))[0]


def mode_record(rgba, dbl, depth, sizes=(0, 0, 0, 0), index_bits=0, lvl=0):
    b = bytearray(96)
    b[4] = 1 if rgba else 0
    b[6] = dbl
    b[9] = depth
    b[39] = index_bits
    for o, s in zip((43, 47, 51, 55), sizes):
        b[o] = s
    b[84:88] = struct.pack('>I', lvl)
    return (MODE, bytes(b))


def main():
    path = sys.argv[1]
    inv = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs', 'inventory', 'functions.tsv')
    r = Run(path, inv)

    def describe(name, rec):
        mu = r.call(DESCRIBE, [DESC, 1], [rec])
        cls, S, L = w32(mu, DESC + 52), w32(mu, DESC + 44), w32(mu, DESC + 48)
        return cls, S, L

    def read(fmt, typ, S, L, cls, ci_byte=0):
        # out struct: byte 8 = image byte 0 (client memory), byte 9 = 4:2:2 flag
        desc = bytearray(64)
        struct.pack_into('>III', desc, 44, S, L, cls)
        out = bytearray(32)
        out[8] = ci_byte
        mu = r.call(READPARAMS, [fmt, typ, DESC, OUT], [(DESC, bytes(desc)), (OUT, bytes(out))])
        o = bytes(mu.mem_read(OUT, 32))
        ok, rcls, code, cf = o[0], o[1], o[2], struct.unpack('>I', o[4:8])[0]
        # field codes: depth-or-stencil flag as the read builder passes it
        ds = 1 if fmt in (GL['DEPTH'], GL['STENCIL']) else 0
        mu2 = r.call(FIELDS, [S, L, 1, ds, F1, F2])  # 1: a left or front read, the default; 0 is a right buffer
        f1, f2 = w32(mu2, F1), w32(mu2, F2)
        return ok, rcls, code, cf, f1, f2

    scen = [
        ('RGBA8 window, double-buffered, depth', mode_record(1, 1, 1, (8, 8, 8, 8))),
        ('RGBA8 window, single-buffered', mode_record(1, 0, 0, (8, 8, 8, 8))),
        ('RGBA8 window, double-buffered, no depth', mode_record(1, 1, 0, (8, 8, 8, 8))),
        ('RGBA12 window, double-buffered, depth', mode_record(1, 1, 1, (12, 12, 12, 12))),
        ('CI8 window, level 0', mode_record(0, 1, 1, index_bits=8)),
        ('CI8 window, +84 == 1', mode_record(0, 1, 1, index_bits=8, lvl=1)),
        ('CI12 window, double-buffered, depth', mode_record(0, 1, 1, index_bits=12)),
    ]
    reads = [('depth UI', GL['DEPTH'], GL['UI']), ('depth US', GL['DEPTH'], GL['US']),
             ('stencil UB', GL['STENCIL'], GL['UB']), ('colour index UB', GL['CI'], GL['UB']),
             ('colour index US', GL['CI'], GL['US']),
             ('BGRA UI_8_8_8_8_REV', GL['BGRA'], GL['UI8888REV']), ('RGBA UB', GL['RGBA'], GL['UB'])]
    print('%-42s %-3s %-3s %-3s %-22s %-5s %-4s %-6s %-8s' %
          ('window', 'cls', 'S', 'L', 'read', 'class', 'code', 'cfield', 'fields   word 4 less bits 31, 28 and 19:16'))
    for name, rec in scen:
        cls, S, L = describe(name, rec)
        for rn, f, t in reads:
            ok, rcls, code, cf, f1, f2 = read(f, t, S, L, cls)
            if not ok:
                res = 'refused'
            else:
                w4 = rcls | code << 3 | 1 << 12 | cf << 13 | f1 << 20 | f2 << 24
                res = '%-5d %-4d %-6d (%d,%d)   0x%08x' % (rcls, code, cf, f1, f2, w4)
            print('%-42s %-3d %-3d %-3d %-22s %s' % (name, cls, S, L, rn, res))


if __name__ == '__main__':
    main()
