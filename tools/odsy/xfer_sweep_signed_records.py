#!/usr/bin/env python3
"""Run the Odyssey host-to-board transfer parameter routine over every signed pixel type.

Reproduces the claim in docs/pixel-paths.md, in the signed-type paragraph of the host-to-board
table entry for `__glOdysseyImageCalcXferWriteParams` ("the parameter routine reads bit 7
itself"): with bit 7 of the context word at +0x7b70 set, a signed component type gets the
same output record as the unsigned type of the same width (type code in word 7, format
code and fields alike) except byte 0 (accepted) and byte 4 (signed flag). Signed
COLOR_INDEX and BGRA bytes are refused when the bit is set (the routine also refuses
signed COLOR_INDEX shorts and ints).

Usage, from the repository root with root/ filled (IRIX_FILES.md):

    tools/re-run python3 scripts/xfer_sweep_signed_records.py

It runs the 4924-byte routine at 0xd9bd800 of the IP30 32-bit libGLcore under Unicorn
over 14 pixel formats, 18 destination classes and the six integer component types
(BYTE, UNSIGNED_BYTE, SHORT, UNSIGNED_SHORT, INT, UNSIGNED_INT), once with bit 7 of
+0x7b70 clear and once set. Library calls and the context's function-pointer entries are
stubbed as in scripts/attrib_roundtrip.py, which this uses; the result is what the
shipped code computes from those inputs, not what the board does with the record.

Output: the count of signed/unsigned pairs whose first 24 record bytes agree apart from
bytes 0 and 4, the pairs that differ (grouped by bit, format and type), and a table of
byte 0 and byte 4 per (bit, type). Against the committed library it reports 1210 pairs
equal apart from bytes 0 and 4 and 128 differing, every one an ACCEPT-MISMATCH (the signed
type refused where its unsigned twin is accepted, with bit 7 set): signed COLOR_INDEX
(0x1900) bytes, shorts and ints, and signed BGRA (0x80e1) bytes.
"""
import collections
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from attrib_roundtrip import RoundTrip, CTX, ALLOC, STUB, TAB  # noqa: E402
from mips_shim import install  # noqa: E402

INVENTORY = os.path.join(REPO, 'docs/inventory/functions.tsv')
LIBRARY = os.path.join(REPO, 'root/builds/6.5.30-media/usr/gfx/arch/IP30ODSY32/libGLcore.so')
ROUTINE = 0xd9bd800
OUT = 0x30100000

FORMATS = [0x1900, 0x1901, 0x1902, 0x1903, 0x1904, 0x1905, 0x1906, 0x1907,
           0x1908, 0x1909, 0x190a, 0x80e0, 0x80e1, 0x8000]
TYPES = [(0x1400, 'BYTE'), (0x1401, 'UB'), (0x1402, 'SHORT'),
         (0x1403, 'US'), (0x1404, 'INT'), (0x1405, 'UI')]
TWIN = {'BYTE': 'UB', 'SHORT': 'US', 'INT': 'UI'}


def sweep():
    p = RoundTrip(LIBRARY, INVENTORY)
    p.setup()
    mu = p.mu
    install(mu, ROUTINE, ROUTINE + 0x2000)
    for o in (0, 4, 8):
        mu.mem_write(CTX + o, struct.pack('>I', ALLOC))
    mu.mem_write(CTX + 0xc, struct.pack('>I', STUB))
    for o in range(0x2e00, 0x3000, 4):
        mu.mem_write(CTX + o, struct.pack('>I', STUB))
    mu.mem_write(CTX + 0x17f4, struct.pack('>I', TAB))
    mu.mem_write(TAB, struct.pack('>I', STUB) * 0x1000)
    rows = {}
    for bit in (0, 0x80):
        mu.mem_write(CTX + 0x7b70, struct.pack('>I', bit))
        for fmt in FORMATS:
            for dest_class in range(18):
                for code, name in TYPES:
                    mu.mem_write(OUT, b'\0' * 32)
                    _calls, _fifo, err = p.call(ROUTINE, [fmt, code, dest_class, OUT, 0, 0, 0, 0], CTX)
                    rows[(bit, fmt, dest_class, name)] = (bytes(mu.mem_read(OUT, 24)), err)
    return rows


def main():
    if not os.path.exists(LIBRARY):
        sys.exit('missing %s: fill root/ as IRIX_FILES.md describes' % LIBRARY)
    rows = sweep()
    same = 0
    odd = []
    for (bit, fmt, dest_class, name), (rec, _err) in rows.items():
        if name not in TWIN:
            continue
        twin, _ = rows[(bit, fmt, dest_class, TWIN[name])]
        if bit == 0x80:
            if (rec[0] == 1) != (twin[0] == 1):
                odd.append(('ACCEPT-MISMATCH', hex(fmt), dest_class, name, rec.hex(), twin.hex()))
            if rec[0] != 1:
                continue
        a, b = bytearray(rec), bytearray(twin)
        for r in (a, b):
            r[0] = 0
            r[4] = 0
        if a != b:
            odd.append((bit, hex(fmt), dest_class, name, rec.hex(), twin.hex()))
        else:
            same += 1
    print('pairs equal apart from byte0/byte4:', same, 'differing:', len(odd))
    print(collections.Counter((o[0], o[1], o[3]) for o in odd if o[0] != 0))
    summary = collections.Counter()
    for (bit, _fmt, _dc, name), (rec, _err) in rows.items():
        summary[(bit, name, rec[0], rec[4])] += 1
    for k in sorted(summary):
        print('bit7=%x %-5s byte0=%d byte4=%d : %d' % (k[0], k[1], k[2], k[3], summary[k]))


if __name__ == '__main__':
    main()
