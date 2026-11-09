#!/usr/bin/env python3
"""scripts/changebasis_o32_matrix.py - run the O32 libGLcore routine `changebasis`
on unit vectors under Unicorn and print the matrix it applies for each order.

The routine is linear in its control values, so feeding the unit vectors of an
order n through it recovers the n by n matrix (row r is output r, column c is
input c). The routine address is the one in docs/inventory/functions.tsv for
usr/gfx/arch/IP27KONA/libGLcore.so. Needs pyelftools and unicorn (the toolchain
container has both):

  python3 scripts/changebasis_o32_matrix.py [first_order last_order]
"""
import os
import struct
import sys

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN, UcError
from unicorn.mips_const import (UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2,
                                UC_MIPS_REG_A3, UC_MIPS_REG_GP, UC_MIPS_REG_RA,
                                UC_MIPS_REG_SP, UC_MIPS_REG_T9)

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'root',
                   'usr/gfx/arch/IP27KONA/libGLcore.so')
ENTRY = 0xd97af10
STACK, IO, RET = 0x700f0000, 0x70010000, 0x70000100


def run(order, vin):
    with open(LIB, 'rb') as f:
        elf = ELFFile(f)
        gp = elf.get_section_by_name('.got')['sh_addr'] + 0x7ff0
        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            lo = seg['p_vaddr'] & ~0xfff
            hi = (seg['p_vaddr'] + seg['p_memsz'] + 0xfff) & ~0xfff
            try:
                uc.mem_map(lo, hi - lo)
            except UcError:
                pass            # pages shared with the previous segment
            uc.mem_write(seg['p_vaddr'], seg.data())
    uc.mem_map(0x70000000, 0x100000)
    out = IO + 0x30000
    for i, v in enumerate(vin):
        uc.mem_write(IO + 4 * i, struct.pack('>f', v))
    uc.mem_write(RET, struct.pack('>II', 0, 0))
    for reg, val in ((UC_MIPS_REG_GP, gp), (UC_MIPS_REG_SP, STACK), (UC_MIPS_REG_RA, RET),
                     (UC_MIPS_REG_T9, ENTRY), (UC_MIPS_REG_A0, IO), (UC_MIPS_REG_A1, order),
                     (UC_MIPS_REG_A2, out), (UC_MIPS_REG_A3, 1)):
        uc.reg_write(reg, val)
    uc.emu_start(ENTRY, RET, count=200000)
    return [struct.unpack('>f', uc.mem_read(out + 4 * i, 4))[0] for i in range(order)]


def matrix(order):
    cols = [run(order, [1.0 if k == c else 0.0 for k in range(order)]) for c in range(order)]
    return [[cols[c][r] for c in range(order)] for r in range(order)]


if __name__ == '__main__':
    lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) > 2 else (2, 15)
    for n in range(lo, hi + 1):
        print('order', n)
        for row in matrix(n):
            print('  ', [round(x, 3) for x in row])
