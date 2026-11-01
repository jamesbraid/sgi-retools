#!/usr/bin/env python3
"""Extract the buzz_ucode array from the kernel objects and describe it.

Usage: scripts/extract_buzz_ucode.py [--stats]

Reads odsy_kernel/odsy_init.o (IP30) and odsy_kernel_ip35/odsy_init.o (IP35),
finds the global object symbol `buzz_ucode` in .data, and writes its bytes
unchanged (big-endian) to root/usr/gfx/ucode/ODSY-kernel/buzz_ucode_<ip>.bin.
ucode/buzz_ucode_<ip>.bin is a relative symlink to that file, like every other
microcode file here; root/ is not tracked. With --stats it prints the layout
numbers quoted in ucode/buzz_ucode.md.
"""
import collections
import hashlib
import os
import struct
import sys

from elftools.elf.elffile import ELFFile

repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = {'ip30': 'odsy_kernel/odsy_init.o', 'ip35': 'odsy_kernel_ip35/odsy_init.o'}
OUTDIR = 'root/usr/gfx/ucode/ODSY-kernel'
LOADED = 12288          # halfwords the odsyInitCfifo loop sends (2048 groups of 6)


def array(path):
    elf = ELFFile(open(os.path.join(repo, path), 'rb'))
    sym = elf.get_section_by_name('.symtab').get_symbol_by_name('buzz_ucode')[0]
    sec = elf.get_section(sym['st_shndx'])
    off = sym['st_value']
    return sec.data()[off:off + sym['st_size']]


def main():
    os.makedirs(os.path.join(repo, OUTDIR), exist_ok=True)
    blobs = {}
    for tag, src in SRC.items():
        blobs[tag] = data = array(src)
        out = f'{OUTDIR}/buzz_ucode_{tag}.bin'
        with open(os.path.join(repo, out), 'wb') as f:
            f.write(data)
        link = os.path.join(repo, 'ucode', f'buzz_ucode_{tag}.bin')
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(os.path.relpath(os.path.join(repo, out), os.path.dirname(link)), link)
        print(f'{tag}: {len(data)} bytes sha256 {hashlib.sha256(data).hexdigest()}')
    print('ip30 == ip35:', blobs['ip30'] == blobs['ip35'])
    if '--stats' not in sys.argv[1:]:
        return
    data = blobs['ip30']
    h = struct.unpack('>%dH' % (len(data) // 2), data)
    print('halfwords', len(h), 'loaded', LOADED, 'unloaded tail', len(h) - LOADED)
    # The loader sends each group of six in reverse order; show per-slot
    # statistics in sending order (slot 0 = h[5] of the group).
    for name, rng in (('loaded', range(0, LOADED, 6)), ('tail', range(LOADED, len(h) - 5, 6))):
        slots = [[h[g + 5 - s] for g in rng] for s in range(6)]
        print(name, 'groups', len(slots[0]))
        for s, vals in enumerate(slots):
            orv = 0
            for v in vals:
                orv |= v
            nz = sum(1 for v in vals if v)
            print(f'  slot {s}: OR {orv:04x} nonzero {nz} distinct {len(set(vals))}')
    print('trailing halfwords', [hex(x) for x in h[-8:]], 'leftover', len(h) % 6)
    print('top-6-bit histogram (loaded)', collections.Counter(x >> 10 for x in h[:LOADED]).most_common(8))


if __name__ == '__main__':
    main()
