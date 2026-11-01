"""Dump the ARM firmware's vertex-array tables with the token each entry names.

Usage: ge_varray_tables.py [ARM1_U]     default: ucode/KONA/arm1.u

varray_build_command (arm1.u 0x0c0395fc) indexes six token tables and
three bit tables by [type][count], five words per type. This prints every
non-zero entry with the token's name from GE.h, so the type codes of the
HP_VARRAY_SET_CMDS key can be read from the tokens they select.
"""
import re
import struct
import sys

TABLES = [  # (name, address, types) from ucode/arm1_symbols.tsv
    ('vertex_table', 0x0405102c, 12), ('normal_table', 0x0405111c, 12),
    ('color_table', 0x0405120c, 12), ('index_table', 0x040512fc, 12),
    ('tex_coord_table', 0x040513ec, 12), ('wordCountTable', 0x040514dc, 12),
    ('lastWrdTable', 0x040515cc, 12), ('byteCmpTable', 0x040516bc, 12),
]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/arm1.u'
    img = open(path, 'rb').read()
    h = struct.unpack('>32I', img[:128])
    ro_size, rw_size, base, data_base = h[5], h[6], h[10], h[13]
    names = {int(v, 16): n for n, v in
             re.findall(r'KONA_HP_(\w+)\s+= (0x[0-9a-f]+)', open('GE.h').read())}

    def word(a):
        if base <= a < base + ro_size:
            off = 0x80 + a - base
        else:
            off = 0x80 + ro_size + a - data_base
        return struct.unpack('>I', img[off:off + 4])[0]

    for name, addr, types in TABLES:
        n = 1 if name == 'byteCmpTable' else 5
        for t in range(types):
            row = [word(addr + 4 * (t * n + c)) for c in range(n)]
            if not any(row):
                continue
            if name.endswith('_table'):
                cells = ['%d:%s' % (c, names.get(v, hex(v))) for c, v in enumerate(row) if v]
            else:
                cells = ['%d:%#x' % (c, v) for c, v in enumerate(row)]
            print('%s\ttype %d\t%s' % (name, t, ' '.join(cells)))


main()
