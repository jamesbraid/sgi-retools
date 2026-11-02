#!/usr/bin/env python3
"""Tests of the SVF target naming in sysco_tables.py.

Run: python3 scripts/sysco/test_sysco_tables.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sysco_tables  # noqa: E402


def svf(idcode, mask='0fffffff'):
    return ('// IDTAG TEST\r\nTRST OFF;\r\nSIR 8 TDI (fe) SMASK (ff) ;\r\n'
            'SDR 32 TDI (00000000) SMASK (ffffffff) TDO (%s) MASK (%s) ;\r\n' % (idcode, mask)).encode()


class SvfTarget(unittest.TestCase):
    def test_named_parts(self):
        self.assertEqual(sysco_tables.svf_target(svf('f5045093')), 'XCF02S')
        self.assertEqual(sysco_tables.svf_target(svf('05044093')), 'XCF01S')
        self.assertEqual(sysco_tables.svf_target(svf('f5059093')), 'XCF32P')
        self.assertEqual(sysco_tables.svf_target(svf('f5036093', '0ffeffff')), 'XC18V04')
        self.assertEqual(sysco_tables.svf_target(svf('05026093')), 'XC18V04')

    def test_unmatched_id_stays_unnamed(self):
        self.assertEqual(sysco_tables.svf_target(svf('f5035093')), '')
        self.assertEqual(sysco_tables.svf_target(svf('f6c5f093', '0fff8fff')), '')

    def test_no_idcode_read(self):
        self.assertEqual(sysco_tables.svf_target(b'// no scan here\n'), '')

    def test_first_read_decides(self):
        d = svf('f5036093') + svf('f5045093')
        self.assertEqual(sysco_tables.svf_target(d), 'XC18V04')


if __name__ == '__main__':
    unittest.main()
