#!/usr/bin/env python3
"""Sweep one argument of an IRIX N32 libGLcore routine and print what each value does.

Usage: glcore_sweep.py BINARY ADDRESS --values V[,V|LO-HI ...] [--arg N] [--args A,B,...]
                       [--set OFFSET:SIZE:VALUE ...] [--poke ADDRESS:WORD,WORD ...] [--dump ADDRESS:COUNT ...] [--inventory FILE]

Runs the routine once per value of argument N (default 0) with the other integer
arguments from --args, on a zeroed context in which the --set fields are written first
(OFFSET in the context, SIZE 1, 2 or 4 bytes, VALUE; for example 0xc97:1:1 sets a byte).
For every run it prints the context words that changed (each as offset = final value) and the
command-window words written, then every call to a library routine with its first four arguments (the
calls are skipped and return 0). --poke writes 32-bit words (a number with a decimal
point is stored as a float) at an address of the emulated memory; the context occupies
0x30000000 to 0x30040000 and 0x30100000 to 0x301fffff is free for argument data. --dump prints COUNT words (hex and as a
float) at an address after each run and the faults. Instructions the emulator lacks are replaced by `mips_shim.install` over the routine's
extent (read from the inventory). The context's function-pointer entries
and dispatch table are stubbed as in attrib_roundtrip.py. It shows the decision tree of a
routine that compares an enumerant against many constants, one value at a time, as the
shipped code runs it: software evidence, not of what the board does.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attrib_roundtrip import RoundTrip, CTX, ALLOC, STUB, TAB  # noqa: E402
from mips_shim import install  # noqa: E402
import unicorn.mips_const as mc  # noqa: E402


def parse_values(text):
    out = []
    for part in text.split(','):
        if '-' in part[1:]:
            lo, hi = part.split('-', 1)
            out.extend(range(int(lo, 0), int(hi, 0) + 1))
        else:
            out.append(int(part, 0))
    return out


def routine_size(binary, address, inventory):
    tail = '/'.join(os.path.normpath(binary).split(os.sep)[-2:])
    with open(inventory) as f:
        for ln in f:
            c = ln.rstrip('\n').split('\t')
            if len(c) > 7 and c[0].endswith(tail) and c[4] == '0x%x' % address:
                return int(c[5])
    raise SystemExit('no inventory row for 0x%x in %s' % (address, tail))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('address', type=lambda s: int(s, 0))
    ap.add_argument('--values', required=True)
    ap.add_argument('--arg', type=int, default=0)
    ap.add_argument('--args', default='')
    ap.add_argument('--set', action='append', default=[])
    ap.add_argument('--poke', action='append', default=[])
    ap.add_argument('--dump', action='append', default=[])
    ap.add_argument('--inventory', default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                         '..', 'docs', 'inventory', 'functions.tsv'))
    a = ap.parse_args()
    size = routine_size(a.binary, a.address, a.inventory)
    fixed = [int(x, 0) for x in a.args.split(',')] if a.args else []
    for v in parse_values(a.values):
        p = RoundTrip(a.binary, a.inventory)
        p.setup()
        mu = p.mu
        install(mu, a.address, a.address + size)
        for o in (0, 4, 8):
            mu.mem_write(CTX + o, struct.pack('>I', ALLOC))
        mu.mem_write(CTX + 0xc, struct.pack('>I', STUB))
        for o in range(0x2e00, 0x3000, 4):
            mu.mem_write(CTX + o, struct.pack('>I', STUB))
        mu.mem_write(CTX + 0x17f4, struct.pack('>I', TAB))
        mu.mem_write(TAB, struct.pack('>I', STUB) * 0x1000)
        for s in a.set:
            off, width, val = (int(x, 0) for x in s.split(":"))
            mu.mem_write(CTX + off, val.to_bytes(width, "big"))
        for pk in a.poke:
            addr, words = pk.split(':', 1)
            data = b''.join(struct.pack('>f', float(w)) if '.' in w else struct.pack('>I', int(w, 0) & 0xffffffff)
                            for w in words.split(','))
            mu.mem_write(int(addr, 0), data)
        before = bytes(mu.mem_read(CTX, 0x1a000))
        args = list(fixed) + [0] * 8
        args[a.arg] = v
        calls, fifo, err = p.call(a.address, args[:8], CTX)
        after = bytes(mu.mem_read(CTX, 0x1a000))
        # a write hook over the context makes this build of Unicorn run some loops twice,
        # so the changes are found by comparing the context before and after
        writes = ['ctx+0x%x = 0x%x' % (o, struct.unpack('>I', after[o:o + 4])[0])
                  for o in range(0, 0x1a000, 4) if after[o:o + 4] != before[o:o + 4]]
        print('value 0x%x:' % v)
        print('  returned: 0x%x' % (mu.reg_read(mc.UC_MIPS_REG_V0) & 0xffffffff))
        if writes:
            print('  writes:', '; '.join(writes))
        if fifo:
            print('  command words:', ' '.join('0x%x' % w for w in fifo))
        for n, r in calls:
            print('  call %s(%s)' % (n, ', '.join('0x%x' % x for x in r)))
        for d in a.dump:
            addr, count = (int(x, 0) for x in d.split(':'))
            words = struct.unpack('>%dI' % count, mu.mem_read(addr, 4 * count))
            print('  words at 0x%x: %s' % (addr, ' '.join('0x%x(%g)' % (w, struct.unpack('>f', struct.pack('>I', w))[0]) for w in words)))
        if err:
            print('  stopped:', err)


if __name__ == '__main__':
    sys.exit(main())
