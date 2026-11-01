#!/usr/bin/env python3
"""Run the texture-format routines of a libGLcore build under Unicorn and print their tables.

Usage: texfmt_sweep.py BUILD            (a name from BUILDS below, or "all" to compare every build)
       texfmt_sweep.py --list

Runs the shipped code of four routines with no context and no board:

  ChooseSuitableBuzzTexObjFormat   every GL enumerant 0 to 0xffff -> board format index (0 = default)
  CalcTexelSizes                   index 0 to 51 -> six component widths and the size code
  GetImageFmtEnumFromBuzzTexFormat index 0 to 51 -> pixel class (-1 = none)
  ChooseSuitableBuzzTexModeBaseFmt index x GL format -> 3-bit class (sweeps the enumerants a texture can name)

None of the four reads the context or calls another routine, so the emulation needs only the
object's segments, its global offset table and the calling convention of its ABI (o32 passes the
fifth and later arguments on the stack). The output is a text table, identical for every build
that has the same answers; "all" prints the builds that differ from the first. This is software
evidence of the shipped code, not of what the board does with the numbers.

Run inside the toolchain environment (needs pyelftools and unicorn): tools/re-run python3 scripts/texfmt_sweep.py all
"""
import os
import struct
import sys

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN, UC_MODE_MIPS32, UC_MODE_MIPS64
from unicorn.mips_const import (UC_MIPS_REG_0, UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2,
                                UC_MIPS_REG_A3, UC_MIPS_REG_GP, UC_MIPS_REG_PC, UC_MIPS_REG_RA,
                                UC_MIPS_REG_SP, UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2,
                                UC_MIPS_REG_T3, UC_MIPS_REG_T9, UC_MIPS_REG_V0)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'root')
A30 = 'usr/gfx/arch/IP30ODSY%s/libGLcore.so'
A35 = 'usr/gfx/arch/IP35ODSY%s/libGLcore.so'
P = 'builds/vpro-patch-4103/usr/gfx/arch/IP30ODSY%s/libGLcore.so'
# name: (path, abi, ObjFormat, ModeBaseFmt, GetImageFmtEnum, CalcTexelSizes)
BUILDS = {
    'IP30-n32': (A30 % '32', 'n32', 0xd9cfdc0, 0xd9cfc80, 0xd9cfbd0, 0xd9d01d0),
    'IP35-n32': (A35 % '32', 'n32', 0xd9cfdc0, 0xd9cfc80, 0xd9cfbd0, 0xd9d01d0),
    'IP30-n64': (A30 % '64', 'n64', 0x32643c0, 0x3264280, 0x32641c0, 0x32647d0),
    'IP35-n64': (A35 % '64', 'n64', 0x22143c0, 0x2214280, 0x22141c0, 0x22147d0),
    'IP30-o32': (A30 % '', 'o32', 0xd9e1ea4, 0xd9e1dc8, 0xd9e1d08, 0xd9e2018),
    'IP35-o32': (A35 % '', 'o32', 0xd9e1ea4, 0xd9e1dc8, 0xd9e1d08, 0xd9e2018),
    'patch4103-o32': (P % '', 'o32', 0xdab5cf4, 0xdab5c18, 0xdab5b58, 0xdab5e68),
    'patch4103-n64': (P % '64', 'n64', 0xb3984c0, 0xb398380, 0xb3982c0, 0xb398920),
}
DONE, STACK, OUT = 0xdead0000, 0x3f000000, 0x30000000
# the base-format routine is swept over the enumerants a texture can name: the small integers, the
# base formats, GL_R3_G3_B2, the sized and extension formats and the two ICC formats
PROBE = (list(range(0x10)) + list(range(0x1900, 0x1910)) + [0x2a10] + list(range(0x8000, 0x8100))
         + list(range(0x8460, 0x8470)))


class Build:
    def __init__(self, name):
        path, self.abi, self.obj, self.base, self.img, self.sz = BUILDS[name]
        elf = ELFFile(open(os.path.join(ROOT, path), 'rb'))
        tags = {t.entry.d_tag: t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags()}
        self.gp = tags.get('DT_MIPS_GP_VALUE') or tags.get(0x70000030) \
            or elf.get_section_by_name('.got')['sh_addr'] + 0x7ff0
        mode = UC_MODE_MIPS32 if self.abi == 'o32' else UC_MODE_MIPS64
        self.mu = mu = Uc(UC_ARCH_MIPS, mode | UC_MODE_BIG_ENDIAN)
        for s in elf.iter_segments():
            if s['p_type'] != 'PT_LOAD':
                continue
            va = s['p_vaddr']
            lo, hi = va & ~0xfff, (va + s['p_memsz'] + 0xfff) & ~0xfff
            try:
                mu.mem_map(lo, hi - lo)
            except UcError:
                pass
            mu.mem_write(va, s.data())
        for lo, sz in ((OUT, 0x1000), (STACK - 0x10000, 0x20000), (DONE, 0x1000)):
            mu.mem_map(lo, sz)

    def call(self, addr, args):
        mu = self.mu
        for r in range(1, 32):
            mu.reg_write(UC_MIPS_REG_0 + r, 0)
        regs = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3]
        if self.abi == 'o32':
            for k, v in enumerate(args[4:]):
                mu.mem_write(STACK + 16 + 4 * k, struct.pack('>I', v))
        else:
            regs += [UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_T3]
        for r, v in zip(regs, args):
            mu.reg_write(r, v)
        mu.reg_write(UC_MIPS_REG_GP, self.gp)
        mu.reg_write(UC_MIPS_REG_SP, STACK)
        mu.reg_write(UC_MIPS_REG_T9, addr)
        mu.reg_write(UC_MIPS_REG_RA, DONE)
        try:
            mu.emu_start(addr, DONE, count=100000)
        except UcError:
            pass
        if mu.reg_read(UC_MIPS_REG_PC) not in (0, DONE):
            raise SystemExit('routine at 0x%x stopped at pc 0x%x' % (addr, mu.reg_read(UC_MIPS_REG_PC)))
        return mu.reg_read(UC_MIPS_REG_V0) & 0xffffffff

    def report(self):
        out = []
        by = {}
        for e in range(0x10000):
            v = self.call(self.obj, [e])
            if v:
                by.setdefault(v, []).append(e)
        out.append('ChooseSuitableBuzzTexObjFormat: enumerants with a nonzero index (every other value of 0..0xffff gives 0)')
        for v in sorted(by):
            out.append('  index %d: %s' % (v, ' '.join('0x%x' % e for e in by[v])))
        out.append('CalcTexelSizes: index, six widths, size code (- = not written: the caller\'s value stays)')
        for i in range(52):
            self.mu.mem_write(OUT, b'\xee' * 0x40)
            ptr = [OUT + 4 * k for k in range(7)]
            self.call(self.sz, [i] + ptr)
            w = [struct.unpack('>I', bytes(self.mu.mem_read(p, 4)))[0] for p in ptr]
            out.append('  %2d  %s' % (i, ' '.join('-' if v == 0xeeeeeeee else str(v) for v in w)))
        out.append('GetImageFmtEnumFromBuzzTexFormat: index -> pixel class (-1 none)')
        cls = {}
        for i in range(52):
            v = self.call(self.img, [i])
            cls[i] = v - (1 << 32) if v >= 1 << 31 else v
        out.append('  ' + ' '.join('%d:%d' % kv for kv in cls.items()))
        out.append('ChooseSuitableBuzzTexModeBaseFmt: index -> class; formats that give the RGB class 5 where the class varies')
        for i in range(52):
            seen = {}
            for e in PROBE:
                seen.setdefault(self.call(self.base, [i, e]), []).append(e)
            if len(seen) == 1:
                out.append('  %2d  %d' % (i, next(iter(seen))))
            else:
                out.append('  %2d  5 for %s, 6 otherwise' % (i, ' '.join('0x%x' % e for e in seen[5])))
        return out


def main():
    a = sys.argv[1:]
    if not a or a[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    if a[0] == '--list':
        print('\n'.join(BUILDS))
        return 0
    names = list(BUILDS) if a[0] == 'all' else [a[0]]
    ref = None
    for n in names:
        rep = Build(n).report()
        if ref is None:
            ref = rep
            print('== %s' % n)
            print('\n'.join(rep))
        elif rep == ref:
            print('== %s: identical to %s' % (n, names[0]))
        else:
            print('== %s: DIFFERS from %s' % (n, names[0]))
            print('\n'.join(l for l in rep if l not in ref))
    return 0


if __name__ == '__main__':
    sys.exit(main())
