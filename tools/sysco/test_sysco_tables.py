#!/usr/bin/env python3
"""Tests of the SVF target naming in sysco_tables.py.

Run: python3 tools/sysco/test_sysco_tables.py
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
        self.assertEqual(sysco_tables.svf_target(svf('f5046093')), 'XCF04S')
        self.assertEqual(sysco_tables.svf_target(svf('f5035093')), 'XC18V02')
        self.assertEqual(sysco_tables.svf_target(svf('05025093')), 'XC18V02')

    def test_unmatched_id_stays_unnamed(self):
        self.assertEqual(sysco_tables.svf_target(svf('f5030093')), '')
        self.assertEqual(sysco_tables.svf_target(svf('f6c5f093', '0fff8fff')), '')

    def test_no_idcode_read(self):
        self.assertEqual(sysco_tables.svf_target(b'// no scan here\n'), '')

    def test_first_read_decides(self):
        d = svf('f5036093') + svf('f5045093')
        self.assertEqual(sysco_tables.svf_target(d), 'XC18V04')


class CitedIndex(unittest.TestCase):
    def setUp(self):
        self.saved = (sysco_tables.DOCS, sysco_tables._index)
        sysco_tables.DOCS = [
            ('docs/z.md', 'see 0xDEADBEEF and 12345678abcd'.lower()),
            ('docs/firmware-versions.md', 'only 00112233 here, abcdef0 short'),
            ('docs/a.md', 'deadbeef 00112233 xx12345678 9abcdef01'),
            ('docs/functions.tsv', 'f00dfeed'),
            ('docs/protocols.tsv', 'f00dfeed'),
        ]
        sysco_tables._index = None

    def tearDown(self):
        sysco_tables.DOCS, sysco_tables._index = self.saved

    def test_index_agrees_with_scan(self):
        probes = ['deadbeef', 'DEADBEEF', '00112233', '12345678', '2345678a', '5678abcd', '9abcdef0',
                  'bcdef01', 'abcdef01', 'f00dfeed', '00000000', 'cdef0123']
        for p in probes:
            self.assertEqual(sysco_tables.cited(p), sysco_tables.cited_scan(p), p)

    def test_search_order(self):
        self.assertEqual(sysco_tables.cited('00112233'), 'docs/firmware-versions.md')
        self.assertEqual(sysco_tables.cited('deadbeef'), 'docs/z.md')
        self.assertEqual(sysco_tables.cited('9abcdef0'), 'docs/a.md')
        self.assertEqual(sysco_tables.cited('f00dfeed'), '')

    def test_other_tokens_still_scan(self):
        self.assertEqual(sysco_tables.cited('abcdef0'), 'docs/firmware-versions.md')
        self.assertEqual(sysco_tables.cited('12345678a'), 'docs/z.md')


if __name__ == '__main__':
    unittest.main()
