#!/usr/bin/env python3
"""Run shipped routines from a MIPS object over chosen inputs, with a register-file stub.

Usage: retools/tools/chips/run_routine.py OBJECT.o [--window-hex ...] CALL [CALL ...]
       CALL is  name:arg,arg,...   (arguments are integers; the first, the driver's chip record, is built here)

The routine's own bytes are copied out of the object's text section (no relocations are applied,
so each call to another routine is replaced by `v0 = 0` and counted in the output). A chip record is built in emulated memory with the window base at +8 and the chip-type
halfword at +114; the window itself is a RAM stub whose every load and store is logged with its
offset, width and value. This shows what a routine does to the register file, not what the chip does.
Needs pyelftools and unicorn (the build container has both).
"""
import argparse
import struct
import sys
import os

from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN, UC_MODE_MIPS64, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE,
                     UC_HOOK_CODE, UcError)
import unicorn.mips_const as mc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mips_shim  # noqa: E402

TEXT, STACK, REC, WIN = 0x10000000, 0x20000000, 0x30000000, 0x40000000
STOP = 0x50000000


def routine(path, name):
    f = open(path, 'rb')
    elf = ELFFile(f)
    sec = elf.get_section_by_name('.text')
    sym = next(s for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name == name)
    off = sym['st_value']
    data = sec.data()[off:off + sym['st_size']]
    return data


def run(path, name, args, chip_type, log):
    code = routine(path, name)
    mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN)
    mu.mem_map(TEXT, 0x10000)
    mu.mem_map(STACK, 0x10000)
    mu.mem_map(REC, 0x10000)
    mu.mem_map(WIN, 0x100000)
    mu.mem_map(STOP, 0x1000)
    # a call (jal) to another routine is replaced by `v0 = 0` (its delay slot still runs): the shipped
    # callees here are the interrupt-level save and restore, which a register-file stub does not need
    patched = bytearray(code)
    ncalls = 0
    for i in range(0, len(patched), 4):
        if patched[i] >> 2 == 3:
            patched[i:i + 4] = struct.pack('>I', 0x00001021)
            ncalls += 1
    mu.mem_write(TEXT, bytes(patched))
    mips_shim.install(mu, TEXT, TEXT + len(code))
    # chip record: window base at +8, chip-type halfword at +114 (2 selects the PIC branch)
    mu.mem_write(REC + 8, struct.pack('>Q', WIN))
    mu.mem_write(REC + 114, struct.pack('>H', chip_type))
    ev = []

    def hook(uc, access, addr, size, value, user):
        if WIN <= addr < WIN + 0x100000:
            ev.append(('w' if access == UC_MEM_WRITE else 'r', addr - WIN, size,
                       value if access == UC_MEM_WRITE else int.from_bytes(bytes(uc.mem_read(addr, size)), 'big')))
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook)
    regs = [mc.UC_MIPS_REG_A0, mc.UC_MIPS_REG_A1, mc.UC_MIPS_REG_A2, mc.UC_MIPS_REG_A3,
            mc.UC_MIPS_REG_T0, mc.UC_MIPS_REG_T1, mc.UC_MIPS_REG_T2, mc.UC_MIPS_REG_T3]
    mu.reg_write(regs[0], REC)
    for r, v in zip(regs[1:], args):
        mu.reg_write(r, v)
    mu.reg_write(mc.UC_MIPS_REG_SP, STACK + 0x8000)
    mu.reg_write(mc.UC_MIPS_REG_RA, STOP)
    err = None
    try:
        mu.emu_start(TEXT, STOP, count=2000)
    except UcError as e:
        err = str(e)
    pc = mu.reg_read(mc.UC_MIPS_REG_PC)
    log.append((name, args, ev, pc == STOP, err, pc - TEXT, ncalls))
    return ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('object')
    ap.add_argument('calls', nargs='+')
    ap.add_argument('--chip-type', type=int, default=2)
    a = ap.parse_args()
    log = []
    for c in a.calls:
        n, _, rest = c.partition(':')
        args = [int(x, 0) for x in rest.split(',') if x]
        run(a.object, n, args, a.chip_type, log)
    for name, args, ev, ok, err, pc, ncalls in log:
        print('%s(%s): %s%s' % (name, ', '.join(hex(x) for x in args), 'returned' if ok else 'STOPPED at +0x%x (%s)' % (pc, err or 'unsupported instruction'), ' [%d call(s) replaced by v0=0]' % ncalls if ncalls else ''))
        for k, off, sz, v in ev:
            print('    %s +0x%x width %d%s' % (k, off, sz, ' value 0x%x' % v if k == 'w' else ' read 0x%x' % v))


if __name__ == '__main__':
    main()
