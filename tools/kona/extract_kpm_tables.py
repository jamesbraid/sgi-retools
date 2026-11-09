"""Extract the command-name and raster-register tables from the kpm tool.

Usage: extract_kpm_tables.py [KPM] [OUTDIR]
       defaults: diags/KONA_bin/kpm diags/kpm

kpm (IRIX 6.5.30, /usr/gfx/KONA/bin/kpm, N32 executable) carries two
decode tables in its .data section:

  - an array of string pointers naming every host command token, indexed by
    token value (located by searching for a pointer to the string "HP_DATA");
  - an array of 16-byte records {kind, name, value, width} describing the
    raster-side registers: kind 1 is a register (value = register index),
    kind 2 a field of the preceding register (value = low bit, width = bits),
    kind 3 a named value of the preceding field (located by searching for the
    record whose name is "BEF_DUMP").

It also holds a geometry-engine register table, a list of geometry-engine
special-register names and a host-interface register table, extracted the same way.

All are written as TSV with the virtual address of each entry, so every
row can be cited back to the binary.
"""
import os
import struct
import sys

from elftools.elf.elffile import ELFFile

kpm = sys.argv[1] if len(sys.argv) > 1 else 'diags/KONA_bin/kpm'
out = sys.argv[2] if len(sys.argv) > 2 else 'diags/kpm'

with open(kpm, 'rb') as fp:
    elf = ELFFile(fp)
    segs = [(s['p_vaddr'], s['p_offset'], s['p_filesz'])
            for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    fp.seek(0)
    data = fp.read()


def v2o(v):
    for va, off, sz in segs:
        if va <= v < va + sz:
            return off + v - va
    return None


def o2v(o):
    for va, off, sz in segs:
        if off <= o < off + sz:
            return va + o - off
    return None


def cstr(v, limit=64):
    o = v2o(v)
    if o is None:
        return None
    end = data.find(b'\0', o)
    if end < 0 or end == o or end - o > limit:
        return None
    s = data[o:end]
    if not all(32 <= c < 127 for c in s):
        return None
    return s.decode('ascii')


def word(o):
    return struct.unpack('>I', data[o:o + 4])[0]


def find_string(s):
    o = data.find(s.encode() + b'\0')
    while o >= 0 and data[o - 1] != 0:
        o = data.find(s.encode() + b'\0', o + 1)
    return o2v(o)


def find_pointer(v):
    return [o for o in range(0, len(data) - 4, 4) if word(o) == v]


os.makedirs(out, exist_ok=True)

# Command-name table: consecutive string pointers starting at "HP_DATA".
hp_data = find_string('HP_DATA')
start = find_pointer(hp_data)[0]
rows = []
o = start
while cstr(word(o)) is not None:
    rows.append((o2v(o), (o - start) // 4, cstr(word(o))))
    o += 4
with open(os.path.join(out, 'hp_commands.tsv'), 'w') as fp:
    fp.write('# kpm command-name table, %d entries from vaddr 0x%08x\n'
             % (len(rows), o2v(start)))
    fp.write('vaddr\ttoken\tname\n')
    for va, idx, name in rows:
        fp.write('0x%08x\t0x%03x\t%s\n' % (va, idx, name))

# Raster register descriptor table: 16-byte records around "BEF_DUMP".
bef = find_string('BEF_DUMP')
anchor = [p for p in find_pointer(bef) if word(p - 4) == 1][0] - 4


def is_rec(o):
    return word(o) in (1, 2, 3) and cstr(word(o + 4)) is not None


s = anchor
while is_rec(s - 16):
    s -= 16
e = anchor
while is_rec(e):
    e += 16
with open(os.path.join(out, 'raster_registers.tsv'), 'w') as fp:
    fp.write('# kpm raster register table, %d records from vaddr 0x%08x\n'
             % ((e - s) // 16, o2v(s)))
    fp.write('# kind 1 = register (value = index); 2 = field (value = low bit,'
             ' width = bits); 3 = named field value\n')
    fp.write('vaddr\tkind\tname\tvalue\twidth\n')
    for o in range(s, e, 16):
        kind, name, val, width = struct.unpack('>4I', data[o:o + 16])
        fp.write('0x%08x\t%d\t%s\t0x%x\t%d\n'
                 % (o2v(o), kind, cstr(name), val, width))

# Geometry-engine register table: 24-byte records {kind, address, name,
# value, mask, shift} starting at the record named
# "Execution Control Register". kind 1 = register, 2 = field.
ecr = find_string('Execution Control Register')
gs = [p for p in find_pointer(ecr) if word(p - 8) == 1][0] - 8
ge = gs
while word(ge) in (1, 2) and cstr(word(ge + 8), 80) is not None:
    ge += 24
with open(os.path.join(out, 'ge_registers.tsv'), 'w') as fp:
    fp.write('# kpm geometry-engine register table, %d records from vaddr'
             ' 0x%08x\n' % ((ge - gs) // 24, o2v(gs)))
    fp.write('# kind 1 = register, 2 = field; value column meaning unknown\n')
    fp.write('vaddr\tkind\taddress\tname\tvalue\tmask\tshift\n')
    for o in range(gs, ge, 24):
        kind, addr, name, val, mask, shift = struct.unpack('>6I',
                                                           data[o:o + 24])
        fp.write('0x%08x\t%d\t0x%05x\t%s\t0x%x\t0x%x\t%d\n'
                 % (o2v(o), kind, addr, cstr(name, 80), val, mask, shift))

# Geometry-engine special-register names: {number, name} pairs that start
# with CHIP_ID and end at a 0xffffffff number.
cid = find_string('CHIP_ID')
ss = [p for p in find_pointer(cid)][0] - 4
specials = []
o = ss
while word(o) != 0xffffffff and cstr(word(o + 4)) is not None:
    specials.append((o2v(o), word(o), cstr(word(o + 4))))
    o += 8
with open(os.path.join(out, 'ge_special_registers.tsv'), 'w') as fp:
    fp.write('# kpm geometry-engine special-register names, %d pairs from'
             ' vaddr 0x%08x\n' % (len(specials), o2v(ss)))
    fp.write('vaddr\tnumber\tname\n')
    for va, num, name in specials:
        fp.write('0x%08x\t0x%02x\t%s\n' % (va, num, name))

# Host-interface register table: 60-byte records {kind, offset, name[32],
# word, word, mask, word, shift} around the record named "HH_GFIFO_HI".
# kind 1 = register, 2 = field. The two leading tail words are always zero.
def hip_ok(o):
    kind, off = struct.unpack('>II', data[o:o + 8])
    name = data[o + 8:o + 40].split(b'\0')[0]
    return kind in (1, 2) and len(name) > 1 and all(32 < c < 127 for c in name)


hh = data.find(b'HH_GFIFO_HI\0') - 8
hs = hh
while hip_ok(hs - 60):
    hs -= 60
he = hh
while hip_ok(he):
    he += 60
with open(os.path.join(out, 'hip_registers.tsv'), 'w') as fp:
    fp.write('# kpm host-interface register table, %d records from vaddr'
             ' 0x%08x\n' % ((he - hs) // 60, o2v(hs)))
    fp.write('# kind 1 = register (offset 0xdead = address-bit layout, not a'
             ' register), 2 = field\n')
    fp.write('vaddr\tkind\toffset\tname\tmask\tshift\n')
    for o in range(hs, he, 60):
        kind, off = struct.unpack('>II', data[o:o + 8])
        name = data[o + 8:o + 40].split(b'\0')[0].decode('ascii')
        _, _, mask, _, shift = struct.unpack('>5I', data[o + 40:o + 60])
        fp.write('0x%08x\t%d\t0x%03x\t%s\t0x%x\t%d\n'
                 % (o2v(o), kind, off, name, mask, shift))

# XG (Xtalk widget) register table: the same 60-byte records, around the
# record named "XG_XT_CTRL". Some names carry a leading "$"; a third kind
# (3) appears for the window bases, whose offset is the base address.
def xg_ok(o):
    kind, off = struct.unpack('>II', data[o:o + 8])
    name = data[o + 8:o + 40].split(b'\0')[0]
    return (kind in (1, 2, 3) and len(name) > 1 and name.lstrip(b'$').startswith(b'XG_')
            and all(32 < c < 127 for c in name))


xh = data.find(b'XG_XT_CTRL\0') - 8
xs = xh
while xg_ok(xs - 60):
    xs -= 60
xe = xh
while xg_ok(xe):
    xe += 60
with open(os.path.join(out, 'xg_registers.tsv'), 'w') as fp:
    fp.write('# kpm XG register table, %d records from vaddr 0x%08x\n'
             % ((xe - xs) // 60, o2v(xs)))
    fp.write('# kind 1 = register, 2 = field, 3 = window base; offset is the'
             ' XG window offset (for a field, of its register)\n')
    fp.write('vaddr\tkind\toffset\tname\tmask\tshift\n')
    for o in range(xs, xe, 60):
        kind, off = struct.unpack('>II', data[o:o + 8])
        name = data[o + 8:o + 40].split(b'\0')[0].decode('ascii')
        _, _, mask, _, shift = struct.unpack('>5I', data[o + 40:o + 60])
        fp.write('0x%08x\t%d\t0x%06x\t%s\t0x%x\t%d\n'
                 % (o2v(o), kind, off, name, mask, shift))

print('hp_commands: %d, raster records: %d, ge records: %d, specials: %d,'
      ' hip records: %d, xg records: %d'
      % (len(rows), (e - s) // 16, (ge - gs) // 24, len(specials),
         (he - hs) // 60, (xe - xs) // 60))
