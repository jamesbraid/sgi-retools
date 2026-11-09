#!/usr/bin/env python3
"""Run one routine of an IRIX N32 libGLcore under Unicorn and print what it writes.

Usage: glcore_probe.py BINARY ADDRESS [ARG ...] [--fill zero|ones] [--inventory FILE]

The shared object's segments are mapped at their link addresses, the global offset
table's global entries are filled from the dynamic symbol table, gp is the
object's recorded value, and a zeroed context record is mapped at 0x30000000
with its address stored at the process address 0x1010 (where the library keeps
its current context) and 0x1018 (the in-progress marker) zero. The routine runs
with the integer arguments given in a0, a1, ...; every store to the context, to
the low process words and to the command window at 0x10000 is printed in order,
and every call to a routine of the library (named from the inventory) or to an
imported one is printed with its first four arguments and skipped (it returns 0).

--fill ones starts every context word from 0x10 to 0x1a000 as 0xffffffff, so a
routine that only clears bits shows the mask it clears. A run that dereferences
a context pointer reports a fault where it stopped. This is software evidence of
what the shipped code does with those inputs, not of what the board does.
"""
import argparse
import os
import struct
import sys

from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UcError, UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN, UC_MODE_MIPS64, UC_HOOK_CODE,
                     UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE)
from unicorn.mips_const import (UC_MIPS_REG_0, UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2,
                                UC_MIPS_REG_A3, UC_MIPS_REG_GP, UC_MIPS_REG_PC, UC_MIPS_REG_RA,
                                UC_MIPS_REG_SP, UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2,
                                UC_MIPS_REG_T3, UC_MIPS_REG_T9, UC_MIPS_REG_V0)

CTX, CTXSZ, STACK, DONE = 0x30000000, 0x40000, 0x3f000000, 0xdead0000
ARGREGS = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
           UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_T3]


class Probe:
    def __init__(self, path, inventory):
        self.elf = ELFFile(open(path, 'rb'))
        self.segs = [(s['p_vaddr'], s['p_memsz'], s.data())
                     for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        tags = {t.entry.d_tag: t.entry.d_val for t in self.elf.get_section_by_name('.dynamic').iter_tags()}
        self.gp = tags['DT_MIPS_GP_VALUE'] if 'DT_MIPS_GP_VALUE' in tags else tags[0x70000030]
        self.loc, self.gotsym = tags['DT_MIPS_LOCAL_GOTNO'], tags['DT_MIPS_GOTSYM']
        self.syms = list(self.elf.get_section_by_name('.dynsym').iter_symbols())
        self.got = self.elf.get_section_by_name('.got')['sh_addr']
        self.names = {}
        base = os.path.basename(os.path.dirname(path)), os.path.basename(path)
        if inventory and os.path.exists(inventory):
            for ln in open(inventory):
                c = ln.rstrip('\n').split('\t')
                if (len(c) > 7 and c[0].endswith('/'.join(base)) and c[4].startswith('0x')
                        and int(c[4], 16)):
                    self.names[int(c[4], 16)] = c[6]
        for k in range(self.gotsym, len(self.syms)):
            if self.syms[k]['st_value']:
                self.names.setdefault(self.syms[k]['st_value'], self.syms[k].name)

    def run(self, addr, args, fill):
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
        if fill == 'ones':
            mu.mem_write(CTX + 0x10, b'\xff' * (0x1a000 - 0x10))
        mu.mem_write(0x1010, struct.pack('>I', CTX))
        log = []

        def on_write(mu, access, a, size, value, ud):
            v = value & ((1 << (8 * size)) - 1)
            if size == 4 and 0x10000 <= a < 0x11000:
                log.append('fifo  0x%08x' % v)
            elif CTX <= a < CTX + CTXSZ:
                log.append('ctx+0x%x = 0x%x (%d bytes)' % (a - CTX, v, size))
            elif a < 0x20000:
                log.append('word 0x%x = 0x%x' % (a, v))

        def on_code(mu, a, size, ud):
            if a == DONE:
                mu.emu_stop()
            elif a != addr and a in self.names:
                regs = [mu.reg_read(r) & 0xffffffff for r in ARGREGS[:4]]
                log.append('call  %s(%s)' % (self.names[a], ', '.join('0x%x' % r for r in regs)))
                mu.reg_write(UC_MIPS_REG_V0, 0)
                mu.reg_write(UC_MIPS_REG_PC, mu.reg_read(UC_MIPS_REG_RA))

        def on_fault(mu, access, a, size, value, ud):
            log.append('fault at pc 0x%x (address 0x%x)' % (mu.reg_read(UC_MIPS_REG_PC), a))
            return False

        mu.hook_add(UC_HOOK_MEM_WRITE, on_write)
        mu.hook_add(UC_HOOK_CODE, on_code)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_fault)
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
        except UcError as e:
            # the return into DONE ends in an exception at pc 0 on a normal return; any other stop is real
            if mu.reg_read(UC_MIPS_REG_PC) != 0:
                log.append('stopped: %s at pc 0x%x' % (e, mu.reg_read(UC_MIPS_REG_PC)))
        return log, mu.reg_read(UC_MIPS_REG_V0) & 0xffffffff


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('address', type=lambda s: int(s, 0))
    ap.add_argument('args', nargs='*', type=lambda s: int(s, 0))
    ap.add_argument('--fill', choices=('zero', 'ones'), default='zero')
    ap.add_argument('--inventory', default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                         '..', 'docs', 'inventory', 'functions.tsv'))
    a = ap.parse_args()
    log, v0 = Probe(a.binary, a.inventory).run(a.address, a.args, a.fill)
    print('\n'.join(log))
    print('v0 = 0x%x' % v0)


if __name__ == '__main__':
    sys.exit(main())
