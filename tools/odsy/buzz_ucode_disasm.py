#!/usr/bin/env python3
"""List a BUZZ microcode image record by record, split into provisional fields.

Usage: scripts/buzz_ucode_disasm.py IMAGE [--kernel] > LISTING

IMAGE is ucode/ODSY/buzz_xform.bin or ucode/buzz_ucode_ip30.bin. Both are
big-endian arrays of 16-bit values, six per record. A record is one 96-bit
microcode word, written here most significant halfword first (h0..h5, the
order stored in the file; the loaders send h5 first). ucode/buzz_isa.md
gives the evidence and the label (established, inferred, unknown) for each
field printed here. Field names are descriptive only, not SGI's.

--kernel says the image is the kernel's older copy, whose records from 792
on sit 99 places lower than in buzz_xform.bin (buzz_isa.md, "Two copies"), so
entry labels above 791 are moved down by 99.
"""
import struct
import sys

# Entry addresses (record indices of buzz_xform.bin) that libGLcore's
# AddProgram (N32 libGLcore.so, ody_program.s) stores into the per-program
# routine list, plus 410, which ody_lighting.s writes to sequencer register
# 0x29 around a host data load. Incomplete: entries built by arithmetic are
# missing.
ENTRIES = [12, 26, 40, 51, 77, 82, 87, 92, 97, 102, 107, 108, 119, 123, 127,
           145, 159, 410, 515, 606, 611, 626, 641, 656, 694, 719, 734, 758,
           768, 779, 891, 902, 911, 920, 931, 964, 975, 986, 997, 1013, 1023,
           1035, 1045, 1057, 1071, 1094, 1136, 1173, 1198, 1200, 1211, 1216]
OVERLAY_BASE = 1848        # first RAM address of the paged window
RAM_WORDS = 2048           # odsyDownloadUcode rejects addresses past 2047
INSERT_AT, INSERT_LEN = 792, 99

# (name, high bit, low bit). Bits 95:94 are never set.
FIELDS = [
    ('a', 93, 92), ('r1', 91, 87), ('r2', 86, 82), ('r3', 81, 77),
    ('b', 76, 75), ('ln', 74, 72), ('rb', 71, 67), ('bx', 66, 64),
    ('mc', 63, 58), ('ma', 57, 48),
    ('d0', 47, 44), ('d1', 43, 40), ('d2', 39, 32),
    ('e0', 31, 28), ('e1', 27, 24), ('e2', 23, 20), ('e3', 19, 16),
    ('s0', 15, 12), ('s1', 11, 2), ('sq', 1, 0),
]
GROUPS = [('r1', 'r2', 'r3'), ('a', 'b'), ('ln', 'rb', 'bx'), ('mc', 'ma'),
          ('d0', 'd1', 'd2'), ('e0', 'e1', 'e2', 'e3'), ('s0', 's1')]
SEQ = {0: '', 1: 'end', 2: 'end2', 3: 'seq3'}
IDLE = 1 << 19             # the record with only bit 19 set


def field(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)


def records(path):
    data = open(path, 'rb').read()
    n = len(data) // 12
    vals = struct.unpack(f'>{n * 6}H', data[:n * 12])
    out = []
    for i in range(n):
        w = 0
        for h in vals[i * 6:i * 6 + 6]:
            w = (w << 16) | h
        out.append(w)
    return out, data[n * 12:]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    kernel = '--kernel' in sys.argv
    if len(args) != 1:
        sys.exit(__doc__)
    recs, rest = records(args[0])
    entries = set()
    for e in ENTRIES:
        if kernel and e >= INSERT_AT:
            if e < INSERT_AT + INSERT_LEN:
                continue        # inside the 99 records the kernel copy lacks
            e -= INSERT_LEN
        entries.add(e)
    ends = {i + 5 for i, w in enumerate(recs) if field(w, 1, 0) in (1, 2)}
    width = {name: (hi - lo + 4) // 4 for name, hi, lo in FIELDS}
    pos = {name: (hi, lo) for name, hi, lo in FIELDS}
    print(f'; {args[0]}: {len(recs)} records of 96 bits'
          + (f', {len(rest)} trailing bytes {rest.hex()}' if rest else ''))
    print('; columns: address, h0..h5, field groups (ucode/buzz_isa.md)')
    for i, w in enumerate(recs):
        if i == RAM_WORDS:
            print(f'; ---- record {i}: past the {RAM_WORDS}-word RAM; '
                  'reaches the board only through the overlay window '
                  f'at {OVERLAY_BASE}')
        if i in entries:
            print(f'entry_{i}:')
        elif i in ends:
            print(f'; ---- {i}: follows an end mark five records back')
        raw = ' '.join(f'{field(w, 95 - 16 * k, 80 - 16 * k):04x}'
                       for k in range(6))
        if w == IDLE:
            print(f'{i:04d}  {raw}  idle')
            continue
        parts = []
        for g in GROUPS:
            parts.append('.'.join(
                f'{field(w, *pos[n]):0{width[n]}x}' for n in g))
        seq = SEQ[field(w, 1, 0)]
        print(f'{i:04d}  {raw}  ' + ' '.join(parts) + (f'  {seq}' if seq else ''))


if __name__ == '__main__':
    main()
