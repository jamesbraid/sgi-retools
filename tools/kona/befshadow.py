"""Extract the geometry board's 89-word register shadow layout from arm1.u.

Usage: befshadow.py [ARM1_U] [RASTER_TSV] [OUT_TSV]
       defaults: ucode/KONA/arm1.u diags/kpm/raster_registers.tsv
                 ucode/befshadow.tsv

arm1.u keeps two 89-word tables in its read-write data (AIF layout, see
arm1_disasm.py): befsh_addrs at 0x04067c0c and befsh_init at 0x04067d70
(addresses from the image's debug table, ucode/arm1_symbols.tsv). Shadow word
i is shadow register BEF_REGSHADOW + i (0x100 + i); befsh_addrs[i] names the
register it mirrors and befsh_init[i] is the value init_befshadow stores at
start-up. Names come from the raster register table when the address (low 15
bits) matches a register index.
"""
import struct
import sys

RO_SIZE, DATA_BASE = 0x40248, 0x4040260  # AIF header words 5 and 13
N = 0x59


def words(d, a):
    off = 0x80 + RO_SIZE + (a - DATA_BASE)
    return struct.unpack('>%dI' % N, d[off:off + 4 * N])


def main():
    arm = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/arm1.u'
    rtab = sys.argv[2] if len(sys.argv) > 2 else 'diags/kpm/raster_registers.tsv'
    out = sys.argv[3] if len(sys.argv) > 3 else 'ucode/befshadow.tsv'
    d = open(arm, 'rb').read()
    addrs, init = words(d, 0x04067c0c), words(d, 0x04067d70)
    names = {}
    for line in open(rtab):
        if line.startswith('#') or line.startswith('vaddr'):
            continue
        p = line.rstrip('\n').split('\t')
        if len(p) >= 4 and p[1] == '1':
            names.setdefault(int(p[3], 0), p[2])
    with open(out, 'w') as f:
        f.write('# BEF register shadow: word i mirrors the register at address\n')
        f.write('# (low 15 bits) and holds init at start-up. Derived by scripts/befshadow.py.\n')
        f.write('word\tshadow_reg\taddr\ttag_bits\tname\tinit\n')
        for i in range(N):
            a = addrs[i]
            nm = names.get(a & 0x7fff, 'unknown')
            f.write('%d\t0x%03x\t0x%04x\t0x%x\t%s\t0x%x\n'
                    % (i, 0x100 + i, a & 0x7fff, a & ~0x7fff, nm, init[i]))


if __name__ == '__main__':
    main()
