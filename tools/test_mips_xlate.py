#!/usr/bin/env python3
"""Tests of the .MIPS.Xlate decoder in mips_xlate.py on hand-built tables, plus the check against the symbol
tables of every libGL.so under root/ that has one (the evidence the layout is right).

Run from the repository root: python3 tools/test_mips_xlate.py
"""
import glob
import os
import shutil
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mips_xlate  # noqa: E402

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None

LO = 0x02142560


def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        if (v == 0 and not b & 0x40) or (v == -1 and b & 0x40):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def build(bits, pairs, hi=None, lo=LO, pad=16):
    """A table of (A, B) pairs: lengths in words and signed moves of the old start, in words."""
    hi = lo + 4 * sum(a for a, _ in pairs) if hi is None else hi
    n = len(pairs)
    if bits == 32:
        h = struct.pack('>6I', 5, 0x01000000, 0x1000, 0, 1, n)
        h += struct.pack('>4I', lo, hi, lo, hi + 0x40) + bytes(12) + struct.pack('>3I', lo, lo, n) + struct.pack('>2I', lo, hi + 0x40)
        assert len(h) == 0x48
    else:
        h = struct.pack('>8I', 6, 0x01000000, 0x1000, 0, 0, 1, 0, n)
        h += struct.pack('>4Q', lo, hi, lo, hi + 0x40) + bytes(0x58 - 0x40) + struct.pack('>3Q', lo, lo, n) + struct.pack('>2Q', lo, hi + 0x40)
        assert len(h) == 0x80
    return h + b''.join(uleb(a) + sleb(b) for a, b in pairs) + bytes(pad)


# range 0 is the stub area (does not move); the others are reordered: old starts at +0x40, +0x10, +0x2000-ish
PAIRS = [(0x168, 0), (18, 0x2c58), (115, -0x2af0), (20, 0x2b04), (47, 0x58)]


class Decode(unittest.TestCase):
    def test_both_widths_give_the_same_ranges(self):
        for bits in (32, 64):
            x = mips_xlate.parse(build(bits, PAIRS), bits)
            self.assertEqual(x.lo, LO)
            self.assertEqual(len(x.ranges), 5)
            # range 1: new start after the 0x168 words of range 0, old start 0x2c58 words past LO
            self.assertIn((LO + 4 * 0x2c58, LO + 4 * 0x168, 4 * 18), x.ranges)
            self.assertEqual(x.hi, LO + 4 * sum(a for a, _ in PAIRS))

    def test_a_move_backwards_is_signed(self):
        x = mips_xlate.parse(build(32, PAIRS), 32)
        self.assertIn((LO + 4 * (0x2c58 - 0x2af0), LO + 4 * (0x168 + 18), 4 * 115), x.ranges)

    def test_a_trailing_zero_record_is_not_taken_for_padding(self):
        x = mips_xlate.parse(build(32, [(4, 0), (4, 0)]), 32)      # both B values are the single byte 0
        self.assertEqual(len(x.ranges), 2)

    def test_translate(self):
        x = mips_xlate.parse(build(64, PAIRS), 64)
        old = LO + 4 * 0x2c58
        new = LO + 4 * 0x168
        self.assertEqual(x.translate(old), new)
        self.assertEqual(x.translate(old + 8), new + 8)
        self.assertEqual(x.translate(old, 4 * 18), new)
        self.assertIsNone(x.translate(old, 4 * 18 + 4))     # leaves the range
        self.assertIsNone(x.translate(old + 4 * 18))
        self.assertIsNone(x.translate(LO - 4))

    def test_a_table_that_is_not_one_is_refused(self):
        good = build(32, PAIRS)
        self.assertIsNone(mips_xlate.parse(good[:0x40], 32))
        bad = bytearray(good)
        bad[0x3c:0x40] = struct.pack('>I', 6)                  # count disagrees with its other copy
        self.assertIsNone(mips_xlate.parse(bytes(bad), 32))
        self.assertIsNone(mips_xlate.parse(build(32, PAIRS, hi=LO + 4), 32))   # ranges do not reach HI
        self.assertIsNone(mips_xlate.parse(good + b'\x01', 32))                 # data after the records
        self.assertIsNone(mips_xlate.parse(good, 16))


@unittest.skipIf(ELFFile is None, 'pyelftools is not installed')
class AgainstSymbols(unittest.TestCase):
    """Every function DWARF and a symbol table both name must land on the symbol's address."""

    def test_libraries_under_root(self):
        import inventory
        if not shutil.which(os.environ.get('DWARFDUMP', 'dwarfdump')):
            self.skipTest('dwarfdump is not installed (it is in the toolchain image)')
        libs = [p for p in glob.glob(os.path.join(HERE, '..', 'root', 'usr', 'gfx', 'arch', '*', 'libGL.so')) +
                glob.glob(os.path.join(HERE, '..', 'root', 'builds', '*', 'usr', 'gfx', 'arch', '*', 'libGL.so'))]
        checked = 0
        for p in libs:
            with open(p, 'rb') as f:
                elf = ELFFile(f)
                x = mips_xlate.of_elf(elf)
                if x is None:
                    continue
                sym = {}
                for sn in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sn)
                    for s in (sec.iter_symbols() if sec is not None else ()):
                        if s['st_info']['type'] == 'STT_FUNC' and s['st_value']:
                            sym.setdefault(s.name, set()).add(s['st_value'])
            for name, lo, hi in inventory.dwarf_subprograms(p):
                if name in sym:
                    self.assertIn(x.translate(lo, hi - lo), sym[name], '%s %s' % (p, name))
                    checked += 1
        if not checked:
            self.skipTest('no libGL.so with a .MIPS.Xlate under root/')


if __name__ == '__main__':
    unittest.main()
