#!/usr/bin/env python3
"""Tests of the selector-set arithmetic, the compare-tree walk and the public-list parsers of
syssgi_selectors.py. They need no kernel image.

Run from the repository root: python3 scripts/test_syssgi_selectors.py
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import syssgi_selectors as ss  # noqa: E402


def walker(program):
    """A Walker over a hand-written function: {address: (mnemonic, operands)}."""
    w = ss.Walker.__new__(ss.Walker)
    w.ins = program
    w.base, w.end = min(program), max(program) + 4
    w.hits = ss.collections.defaultdict(set)
    w.tables = {}
    w.visited = set()
    w.img = None
    return w


class Sets(unittest.TestCase):
    def test_meet_and_minus(self):
        d = ((0, 100),)
        self.assertEqual(ss.meet(d, 10, 20), ((10, 20),))
        self.assertEqual(ss.minus(d, 10, 20), ((0, 9), (21, 100)))
        self.assertEqual(ss.minus(((5, 5),), 5, 5), ())
        self.assertEqual(ss.size(((0, 9), (21, 100))), 90)


class CompareTree(unittest.TestCase):
    def test_equality_and_range_tests_narrow_to_one_selector(self):
        # sel < 3 -> 0x3000 ; sel == 5 -> 0x2000 ; otherwise 0x4000
        p = {
            0x1000: ('ld', ['$t6', '($s0)']),
            0x1004: ('slti', ['$v0', '$t6', '3']),
            0x1008: ('bnez', ['$v0', '0x3000']),
            0x100c: ('addiu', ['$t0', '$zero', '5']),
            0x1010: ('beq', ['$t6', '$t0', '0x2000']),
            0x1014: ('nop', []),
            0x1018: ('b', ['0x4000']),
            0x101c: ('nop', []),
            0x2000: ('jr', ['$ra']), 0x2004: ('nop', []),
            0x3000: ('jr', ['$ra']), 0x3004: ('nop', []),
            0x4000: ('jr', ['$ra']), 0x4004: ('nop', []),
        }
        w = walker(p)
        w.walk(0x1000, {}, (ss.DOMAIN,), 0x1000, '$t6')
        self.assertEqual({s: {t for t, _ in v} for s, v in w.hits.items()}, {5: {0x2000}})

    def test_sltiu_range_check_before_table_bounds_the_selector(self):
        p = {
            0x1000: ('ld', ['$t6', '($s0)']),
            0x1004: ('sltiu', ['$v0', '$t6', '4']),
            0x1008: ('beqz', ['$v0', '0x4000']),
            0x100c: ('nop', []),
            0x1010: ('addiu', ['$t1', '$zero', '2']),
            0x1014: ('beq', ['$t6', '$t1', '0x2000']),
            0x1018: ('nop', []),
            0x101c: ('b', ['0x3000']),
            0x1020: ('nop', []),
            0x2000: ('jr', ['$ra']), 0x2004: ('nop', []),
            0x3000: ('jr', ['$ra']), 0x3004: ('nop', []),
            0x4000: ('jr', ['$ra']), 0x4004: ('nop', []),
        }
        w = walker(p)
        w.walk(0x1000, {}, (ss.DOMAIN,), 0x1000, '$t6')
        self.assertEqual({s for s in w.hits}, {2})


class PublicLists(unittest.TestCase):
    def test_syssgi_constants(self):
        with tempfile.TemporaryDirectory() as d:
            h = os.path.join(d, 'h')
            with open(h, 'w') as f:
                f.write('#define\tIRIX_SGI_SYSID\t\t\t1\n#define\tIRIX_SGI_X\t0x10\n')
            self.assertEqual(ss.parse_netbsd(h), {'SYSID': 1, 'X': 16})
            c = os.path.join(d, 'c')
            with open(c, 'w') as f:
                f.write('\tcase SGI_SYSID: {\n')
            self.assertEqual(ss.parse_linux_cases(c), ['SYSID'])


if __name__ == '__main__':
    unittest.main()
