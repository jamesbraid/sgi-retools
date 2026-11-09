#!/usr/bin/env python3
"""Compare a Ghidra import (tests/run-ghidra.sh) with the loader's own parse.

    check.py IMAGE DUMP

Checks that the three memory blocks have the loader's addresses and sizes, that
every global text symbol is a function at its address, and that the count of
IMPORTED-source symbols equals the number of symbols the loader placed inside a
block. Exits 1 on any mismatch.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', '..', '..', '..', 'tools', 'sysco'))
import mmsc_aout  # noqa: E402


def main(image, dump):
    img = mmsc_aout.Image(open(image, 'rb').read())
    blocks, funcs, imported = {}, {}, None
    for line in open(dump):
        f = line.rstrip('\n').split('\t')
        if f[0] == 'B':
            blocks[f[1]] = (int(f[2], 16), int(f[3]), f[4] == 'true')
        elif f[0] == 'F':
            funcs[int(f[1], 16)] = f[2]
        elif f[0] == 'I':
            imported = int(f[1])
    bad = []
    for s in img.segments:
        want = (s.addr, s.size, s.fileoff >= 0)
        if blocks.get(s.name) != want:
            bad.append('block %s: %s, want %s' % (s.name, blocks.get(s.name), want))
    inside = 0
    for s in img.symbols:
        if s.kind not in ('text', 'data', 'bss') or s.marker:
            continue
        # A symbol one past a segment's end (_etext, _edata, _end) lands in the
        # next block, or in none for _end; the script labels it where it falls.
        if any(g.addr <= s.value < g.addr + g.size for g in img.segments):
            inside += 1
        text = img.segment('text')
        if s.kind == 'text' and s.glob and s.value < text.addr + text.size \
                and s.value not in funcs:
            bad.append('no function at %#x for %s' % (s.value, s.name))
    if imported != inside:
        bad.append('%s imported symbols, loader placed %d' % (imported, inside))
    for b in bad[:20]:
        print('FAIL', b)
    print('%d blocks, %d functions, %s symbols imported, %d failures'
          % (len(blocks), len(funcs), imported, len(bad)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:3]))
