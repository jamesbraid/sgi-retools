#!/usr/bin/env python3
"""Tests for define naming in gen_headers.py.

Run: python3 tools/chips/test_gen_headers.py
A symbol-less PROM is cut into pseudo-functions named after their start address. Those names must never reach
a define or its comment, and a register must keep the name its named routines gave it when a PROM image is added.
A register keeps the name of its own accessors, not those of a neighbour in the same 8-byte-aligned slot.
"""
import collections
import csv
import json
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
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
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


class SlotNaming(unittest.TestCase):
    """Chips with 4-byte (and byte) registers: names are matched to the row's own offset and width."""

    def setUp(self):
        self.old = os.getcwd()
        self.addCleanup(os.chdir, self.old)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.chdir(tmp.name)
        os.makedirs('tools/configs')
        json.dump({'slot_rules': [{'lo': 0, 'hi': '0x20000', 'bytes': 4}, {'lo': '0x20000', 'hi': '0x40000', 'bytes': 1}]},
                  open('tools/configs/ioc3.json', 'w'))
        d = 'chips/ioc3/census/'
        row = lambda off, w: ['?', off, '0', '', 'rw', w, '0', '1', '1', 'ip27-ioc3']
        write(d + 'census.tsv', ROW, [row('0x0', '4'), row('0x4', '4'), row('0x8', '4'), row('0x20000', '1'), row('0x20001', '1')])
        site = lambda fn, off, w: ['ip27-ioc3', fn, '0', 'lw', 'r', w, off, '0', '?', 'image-hint']
        # the first name in each pair is the one the sort order would hand to both registers if the 8-byte
        # alignment mask bled them together (it is also the more frequent)
        write(d + 'census-sites.tsv', SITE, [
            site('first_a', '0x0', '4'), site('first_a', '0x0', '4'), site('next_b', '0x4', '4'),
            site('only_c', '0x8', '4'),
            site('byte_a', '0x20000', '1'), site('byte_b', '0x20001', '1'),
        ])
        write(d + 'fields.tsv', ['variant', 'register', 'kind', 'bits_or_value', 'source', 'sites'], [])
        text = gen_headers.gen('ioc3', gen_headers.CHIPS['ioc3'])
        self.defs = {m.group(1): m.group(2) for m in re.finditer(r'^#define\s+(\w+)\s+(0x\w+)', text, re.M)}

    def test_four_byte_neighbours_keep_their_own_names(self):
        self.assertEqual(self.defs.get('IOC3_FIRST_A'), '0x000000')
        self.assertEqual(self.defs.get('IOC3_NEXT_B'), '0x000004')
        self.assertEqual(self.defs.get('IOC3_ONLY_C'), '0x000008')

    def test_byte_registers_keep_their_own_names(self):
        self.assertEqual(self.defs.get('IOC3_BYTE_A'), '0x020000')
        self.assertEqual(self.defs.get('IOC3_BYTE_B'), '0x020001')

    def test_a_name_never_crosses_a_width(self):
        # a 4-byte site at the offset of an 8-byte row is not that row's accessor
        names = gen_headers.SiteNames.__new__(gen_headers.SiteNames)
        names.slot_of = lambda off: off & ~7
        names.exact = {(0x10, 4, '0'): [collections.Counter({'half_reader': 1}), 0],
                       (0x10, 8, '0'): [collections.Counter({'full_reader': 1}), 0]}
        names.by_slot = {(0x10, '0'): list(names.exact)}
        got, _ = names.of_row({'offset': '0x10', 'idx': '0', 'widths': '8'})
        self.assertEqual(got, ['full_reader'])


if __name__ == '__main__':
    unittest.main()
