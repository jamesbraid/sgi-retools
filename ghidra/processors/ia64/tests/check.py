#!/usr/bin/env python3
"""Compare the IA-64 module's disassembly of an SN2 PROM with GNU objdump's.

Usage: check.py SLOTS IMAGE [BASE]   (BASE defaults to the address that makes
       IMAGE end at 4 GiB)

SLOTS is run-ghidra.sh's slots.tsv for IMAGE. The code regions are the
image's FIT entries for PAL_B (type 0x01), processor-specific PAL_A (0x0e),
SAL_A (0x10) and SAL_B (0x11), and the generic PAL_A that the entry at
0xFFFFFFD0 describes. Every slot in them is compared after normalising the
syntax (numbers by value, spacing); slots ia64-linux-gnu-objdump cannot decode
are listed with what Ghidra shows for them. Needs the toolchain image's
objdump (tools/re-run). Exits non-zero on any mismatch.
"""
import collections
import os
import re
import struct
import subprocess
import sys

CODE_TYPES = {0x01: 'PAL_B', 0x0e: 'PAL_A', 0x10: 'SAL_A', 0x11: 'SAL_B'}
OBJDUMP = 'ia64-linux-gnu-objdump'
NUM = re.compile(r'(?<![\w.])(-?)(0x[0-9a-f]+|\d+)\b')
OD_LINE = re.compile(r'^\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t?(.*)$')


def fit_regions(data, base):
    """[(name, start, end)] of the code components."""
    top = base + len(data)

    def at(addr, n):
        off = addr - base
        return data[off:off + n]
    fit = struct.unpack('<Q', at(top - 0x20, 8))[0] & 0xffffffff
    hdr = at(fit, 16)
    if hdr[:8] != b'_FIT_   ':
        raise SystemExit('check: no FIT at %#x' % fit)
    count = int.from_bytes(hdr[8:11], 'little')
    out = []
    for i in range(1, count):
        e = at(fit + 16 * i, 16)
        addr = struct.unpack('<Q', e[:8])[0] & 0xffffffff
        size = int.from_bytes(e[8:11], 'little') * 16
        kind = e[14] & 0x7f
        if kind in CODE_TYPES and size:
            out.append(('%s %x.%02x' % (CODE_TYPES[kind], e[13], e[12]), addr, addr + size))
    e = at(top - 0x30, 16)
    if e[14] & 0x7f == 0x0f:
        addr = struct.unpack('<Q', e[:8])[0] & 0xffffffff
        out.append(('generic PAL_A', addr, top - 0x40))
    return out


def norm(text):
    """(predicate, mnemonic, operands, stop) with numbers as 64-bit values."""
    text = text.strip()
    stop = text.endswith(';;')
    if stop:
        text = text[:-2].rstrip()
    pred = 0
    m = re.search(r'\(p(\d+)\)\s*', text)
    if m:
        pred = int(m.group(1))
        text = (text[:m.start()] + text[m.end():]).strip()
    mn, _, ops = text.partition(' ')

    def num(m):
        v = int(m.group(2), 0)
        return '%#x' % ((-v if m.group(1) else v) & (2 ** 64 - 1))
    ops = NUM.sub(num, re.sub(r'\s+', '', ops))
    return pred, mn, ops, stop


def objdump_slots(image, base):
    out = subprocess.run([OBJDUMP, '-D', '-z', '-b', 'binary', '-m', 'ia64-elf64',
                          '--adjust-vma=%#x' % base, image],
                         check=True, capture_output=True, text=True).stdout
    res = {}
    for line in out.splitlines():
        m = OD_LINE.match(line)
        if not m:
            continue
        t = re.sub(r'^\[[^\]]*\]', '', m.group(2)).strip()
        if t:
            res[int(m.group(1), 16)] = t
    return res


def ghidra_slots(path):
    res = {}
    for line in open(path):
        addr, text = line.rstrip('\n').split('\t', 1)
        res[int(addr.split(':')[-1], 16)] = text
    return res


def main():
    slots, image = sys.argv[1], sys.argv[2]
    if not os.path.isfile(image):
        print('check: %s is not here (no PROM root); skipped' % image)
        return 0
    data = open(image, 'rb').read()
    base = int(sys.argv[3], 0) if len(sys.argv) > 3 else (1 << 32) - len(data)
    gh = ghidra_slots(slots)
    od = objdump_slots(image, base)
    total = matched = 0
    bad = []
    undecoded = collections.Counter()
    undecoded_ex = {}
    for name, start, end in fit_regions(data, base):
        n = m = u = 0
        for a in range(start, end, 2):
            if a not in od:
                continue
            o = od[a]
            g = gh.get(a)
            n += 1
            if o.startswith('data8'):
                u += 1
                shown = g.split(' ')[0] if g else '<none>'
                undecoded[shown] += 1
                undecoded_ex.setdefault(shown, '%#x: objdump "%s", Ghidra "%s"' % (a, o, g))
                continue
            if g is not None and norm(g) == norm(o):
                m += 1
            else:
                bad.append('%#x %s: objdump "%s", Ghidra "%s"' % (a, name, o, g))
        print('%-16s %#010x-%#010x  %7d slots  %7d match  %6d objdump cannot decode'
              % (name, start, end, n, m, u))
        total += n - u
        matched += m
    print('decoded by objdump: %d, matching: %d, mismatches: %d' % (total, matched, len(bad)))
    print('slots objdump cannot decode, by what Ghidra shows:')
    for k, v in undecoded.most_common():
        print('  %7d %s   e.g. %s' % (v, k, undecoded_ex[k]))
    for b in bad[:40]:
        print('MISMATCH', b)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
