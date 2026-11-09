"""List the geometry-engine slot references inside the distributor program.

Usage: ged_relocs.py [GED1B_U] [GEIF_U] [GE_SYMBOLS] [OUT]
       defaults: ucode/KONA/ged1b.u ucode/KONA/geif.u ucode/KONA/ge_symbols
                 ucode/ged_relocs.tsv

arm1.u's init_ged_ucode (0x0c001e20) loads the distributor program as
1024 32-bit words and patches some of them before writing each to the
distributor: a word whose top two bits are 2, whose bits 27-29 are 0 and
whose bits 16-22 hold 0x3e, 0x45, 0x46, 0x47 or 0x48 carries a geometry-
engine slot number in its low 16 bits, and the ARM replaces that number
with the slot's handler address from its copy of geif.u. This script
applies the same test to ged1b.u and names each slot through geif.u and
ge_symbols.

ged1b.u uses the .u container (magic 0x45910003, then offset and length
of the build string, code, line table, file-offset table and file-name
table). Its code is two segments, each an 8-byte {byte address, byte
length} header and then 32-bit big-endian words: the program at byte 0
and a 528-word table at byte 0x1000 (word 0x400).
"""
import struct
import sys

ged = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/ged1b.u'
geif = sys.argv[2] if len(sys.argv) > 2 else 'ucode/KONA/geif.u'
symf = sys.argv[3] if len(sys.argv) > 3 else 'ucode/KONA/ge_symbols'
out = sys.argv[4] if len(sys.argv) > 4 else 'ucode/ged_relocs.tsv'

b = open(ged, 'rb').read()
hdr = struct.unpack('>11I', b[:44])
o, end = hdr[3], hdr[3] + hdr[4]
mem = {}
while o < end:
    ba, bl = struct.unpack('>II', b[o:o + 8])
    o += 8
    for i in range(bl // 4):
        mem[ba // 4 + i] = struct.unpack('>I', b[o + 4 * i:o + 4 * i + 4])[0]
    o += bl

g = struct.unpack('>1024H', open(geif, 'rb').read())
names = {}
for line in open(symf):
    n, a = line.split()
    if n[0] == 'm':
        names.setdefault(int(a, 16), []).append(n)

with open(out, 'w') as fh:
    fh.write('# Distributor (ged1b.u, IRIX 6.5.30m) words that arm1.u init_ged_ucode relocates:\n')
    fh.write('# low 16 bits = geometry-engine slot, replaced by geif.u entry 2*slot+1 at load.\n')
    fh.write('ged_word\tvalue\top\tslot\tge_address\tge_handler\n')
    for i in range(0x400):
        w = mem.get(i, 0)
        if w >> 30 == 2 and (w & 0x38000000) == 0 and ((w >> 16) & 0x7f) in (0x3e, 0x45, 0x46, 0x47, 0x48):
            slot = w & 0xffff
            pc = g[2 * slot + 1] if slot < 512 else None
            fh.write('0x%03x\t0x%08x\t0x%02x\t%d\t%s\t%s\n' % (
                i, w, (w >> 16) & 0x7f, slot, '0x%04x' % pc if pc is not None else '',
                ','.join(names.get(pc, []))))
