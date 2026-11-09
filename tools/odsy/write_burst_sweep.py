#!/usr/bin/env python3
"""Tabulate the pixel-burst tag the N32 libGLcore picks for each image-write source, by running its own routine.

Usage: write_burst_sweep.py BINARY
Run it as `tools/re-run python3 scripts/write_burst_sweep.py BINARY`: the image has numpy, unicorn and pyelftools.

Runs __glOdysseyImageCalcXferWriteParams (0x0d9bd800) under Unicorn (the machinery of read_header_sweep.py)
for every format and type the write builder can send and every destination pixel class, on a zeroed
context. Its fourth argument is an output record: byte 0 accepted, byte 1 format code (header word 7
bits 4:0), byte 2 type code (bits 8:5), byte 3 expand, byte 20 the burst tag, byte 21 the size-class
code. The pixel-burst sender (SendPixelsAsUserPIO, 0x0d9b9680) puts byte 20 in the low bits of every
burst's register word (0x14000 | tag | count << 10). Prints one line per accepted combination and, at the
end, the tags each source code (word 7 low nine bits) is sent under. Software evidence only.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from read_header_sweep import Run, CTX, SIZES  # noqa: E402

WRITE = 0x0d9bd800
OUT = CTX + 0x31000
SIZES[WRITE] = 4924

FORMATS = dict(DEPTH=0x1902, STENCIL=0x1901, CI=0x1900, RED=0x1903, GREEN=0x1904, BLUE=0x1905,
               ALPHA=0x1906, RGB=0x1907, RGBA=0x1908, LUMINANCE=0x1909, LUMINANCE_ALPHA=0x190a,
               INTENSITY=0x8049, BGR=0x80e0, BGRA=0x80e1, ABGR=0x8000)
TYPES = dict(B=0x1400, UB=0x1401, S=0x1402, US=0x1403, I=0x1404, UI=0x1405, UB332=0x8032,
             US4444=0x8033, US5551=0x8034, UI8888=0x8035, UI1010102=0x8036, UB233R=0x8362,
             US565=0x8363, US4444R=0x8365, US1555R=0x8366, UI8888R=0x8367, UI2101010R=0x8368,
             US565R=0x8364)


def main():
    path = sys.argv[1]
    inv = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs', 'inventory', 'functions.tsv')
    r = Run(path, inv)
    seen = {}
    print('%-16s %-10s %-5s %-6s %-6s %-6s %-4s %-4s' % ('format', 'type', 'dst', 'code', 'burst', 'size', 'expd', 'bpp?'))
    for cls in range(18):
        for fn, f in FORMATS.items():
            for tn, t in TYPES.items():
                mu = r.call(WRITE, [f, t, cls, OUT], [(OUT, bytes(32))])
                o = bytes(mu.mem_read(OUT, 32))
                if not o[0]:
                    continue
                code = (o[1] & 0x1f) | (o[2] & 0xf) << 5
                print('%-16s %-10s %-5d 0x%03x  0x%02x   %-6d %-4d' % (fn, tn, cls, code, o[20], o[21], o[3]))
                seen.setdefault(code, set()).add(o[20])
    print()
    for code in sorted(seen):
        print('source code 0x%03x: burst tags %s' % (code, ', '.join('0x%02x' % x for x in sorted(seen[code]))))


if __name__ == '__main__':
    main()
