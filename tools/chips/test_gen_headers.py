#!/usr/bin/env python3
"""Tests for define naming in gen_headers.py.

Run: python3 tools/chips/test_gen_headers.py
A symbol-less PROM is cut into pseudo-functions named after their start address. Those names must never reach
a define or its comment, and a register must keep the name its named routines gave it when a PROM image is added.
"""
import csv
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_headers  # noqa: E402

ROW = ['variant', 'offset', 'idx', 'name', 'access_seen', 'widths', 'halves', 'sites', 'functions', 'images']
SITE = ['image', 'function', 'addr', 'insn', 'rw', 'width', 'offset', 'idx', 'variant', 'basis']


def write(path, head, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='') as f:
        w = csv.writer(f, delimiter='\t')
        w.writerow(head)
        w.writerows(rows)


class Naming(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.addCleanup(os.chdir, self.old)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.chdir(tmp.name)
        d = 'chips/bedrock/census/'
        row = lambda off, idx, acc, imgs: ['bedrock', off, idx, '', acc, '8', '0', '1', '1', imgs]
        write(d + 'census.tsv', ROW, [
            row('0x20', '0', 'rw', 'ip35-kernel,ip35-prom'),   # named by a kernel routine, PROM sites outnumber it
            row('0x40', '0', 'r', 'ip35-prom'),                # reached only by the PROM
            row('0x800040', '0', 'r', 'ip35-prom'),            # PROM-only, same slot as an indexed kernel row
            row('0x800040', '1', 'r', 'ip35-kernel'),
        ])
        site = lambda img, fn, off, idx: [img, fn, '0', 'ld', 'r', '8', off, idx, 'bedrock', 'image-hint']
        write(d + 'census-sites.tsv', SITE, [
            site('ip35-kernel', 'get_slice', '0x20', '0'),
        ] + [site('ip35-prom', 'prom_c00000001fc00000', '0x20', '0')] * 5 + [
            site('ip35-prom', 'prom_c00000001fc01284', '0x40', '0'),
            site('ip35-prom', 'prom_c00000001fc01284', '0x800040', '0'),
            site('ip35-kernel', 'hub_error_init', '0x800040', '1'),
        ])
        write(d + 'fields.tsv', ['variant', 'register', 'kind', 'bits_or_value', 'source', 'sites'], [])
        self.text = gen_headers.gen('bedrock', gen_headers.CHIPS['bedrock'])
        self.defs = {m.group(1): m.group(2) for m in re.finditer(r'^#define\s+(\w+)\s+(0x\w+)', self.text, re.M)}

    def test_pseudo_function_names_stay_out(self):
        self.assertNotIn('prom_', self.text)
        self.assertNotIn('PROM_C0', self.text)

    def test_named_register_keeps_its_name(self):
        self.assertEqual(self.defs.get('BEDROCK_GET_SLICE'), '0x000020')

    def test_prom_only_register_is_named_by_offset(self):
        self.assertEqual(self.defs.get('BEDROCK_REG_000040'), '0x000040')

    def test_prom_only_row_does_not_take_a_kernel_rows_name(self):
        self.assertEqual(self.defs.get('BEDROCK_REG_800040'), '0x800040')
        self.assertEqual(self.defs.get('BEDROCK_HUB_ERROR_INIT'), '0x800040')


if __name__ == '__main__':
    unittest.main()
