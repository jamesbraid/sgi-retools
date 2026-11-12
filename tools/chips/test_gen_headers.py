#!/usr/bin/env python3
"""Tests for macro naming in gen_headers.py (through the defs/ source it writes) and for the address-space key in join.py.

Run: python3 tools/chips/test_gen_headers.py
A symbol-less PROM is cut into pseudo-functions named after their start address. Those names must never reach
a define or its comment, and a register must keep the name its named routines gave it when a PROM image is added.
A register keeps the name of its own accessors, not those of a neighbour in the same 8-byte-aligned slot. An
access through a separate address-space window (the boot space) never merges with a register row at the same
offset, and a define whose meaning moved there keeps its old name as an alias.
"""
import collections
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_headers  # noqa: E402

sys.path.insert(0, os.path.join(HERE, '..', 'defs'))
from defslib import gen_c, loader  # noqa: E402
from defslib.model import normalize  # noqa: E402


def macros(chip):
    """(macro -> value, alias -> target) of the C header the generated source produces."""
    unit, _ = gen_headers.gen(chip, gen_headers.CHIPS[chip])
    _, names = gen_c.gen_c(normalize(unit), 'x')
    return names, unit['c'].get('aliases', {})

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
        self.defs, self.aliases = macros('bedrock')
        self.text = ' '.join(self.defs)

    def test_pseudo_function_names_stay_out(self):
        self.assertNotIn('prom_', self.text)
        self.assertNotIn('PROM_C0', self.text)

    def test_named_register_keeps_its_name(self):
        self.assertEqual(self.defs.get('BEDROCK_GET_SLICE'), 0x20)

    def test_prom_only_register_is_named_by_offset(self):
        self.assertEqual(self.defs.get('BEDROCK_REG_000040'), 0x40)

    def test_prom_only_row_does_not_take_a_kernel_rows_name(self):
        self.assertEqual(self.defs.get('BEDROCK_REG_800040'), 0x800040)
        self.assertEqual(self.defs.get('BEDROCK_HUB_ERROR_INIT'), None)
        self.assertEqual(self.aliases.get('BEDROCK_HUB_ERROR_INIT'), 'BEDROCK_REG_800040')


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
        self.defs, _ = macros('ioc3')

    def test_four_byte_neighbours_keep_their_own_names(self):
        self.assertEqual(self.defs.get('IOC3_FIRST_A'), 0)
        self.assertEqual(self.defs.get('IOC3_NEXT_B'), 4)
        self.assertEqual(self.defs.get('IOC3_ONLY_C'), 8)

    def test_byte_registers_keep_their_own_names(self):
        self.assertEqual(self.defs.get('IOC3_BYTE_A'), 0x20000)
        self.assertEqual(self.defs.get('IOC3_BYTE_B'), 0x20001)

    def test_a_name_never_crosses_a_width(self):
        # a 4-byte site at the offset of an 8-byte row is not that row's accessor
        names = gen_headers.SiteNames.__new__(gen_headers.SiteNames)
        names.slot_of = lambda off, space='': off & ~7
        names.exact = {('', 0x10, 4, '0'): [collections.Counter({'half_reader': 1}), 0],
                       ('', 0x10, 8, '0'): [collections.Counter({'full_reader': 1}), 0]}
        names.by_slot = {('', 0x10, '0'): list(names.exact)}
        got, _ = names.of_row({'space': '', 'offset': '0x10', 'idx': '0', 'widths': '8'})
        self.assertEqual(got, ['full_reader'])


class Overlay(unittest.TestCase):
    """A chip written as an overlay (XBridge on Bridge) loads to the unit the census gave it."""

    def test_overlay_merges_to_the_full_unit(self):
        import tomllib
        old = os.getcwd()
        self.addCleanup(os.chdir, old)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.chdir(tmp.name)
        os.makedirs('chips/bridge/census')
        row = lambda v, off, acc, sites: [v, off, '0', '', acc, '4', '4', sites, '1', 'ip27-kernel']
        write('chips/bridge/census/census.tsv', ROW, [row('bridge', '0x0', 'r', '5'), row('xbridge', '0x0', 'r', '3'),
                                                        row('xbridge', '0x170', 'r', '2')])
        write('chips/bridge/census/census-sites.tsv', SITE, [])
        write('chips/bridge/census/fields.tsv', ['variant', 'register', 'kind', 'bits_or_value', 'source', 'sites'], [])
        base = tomllib.loads(gen_headers.toml_of('bridge', gen_headers.CHIPS['bridge']))
        ov = tomllib.loads(gen_headers.overlay_of('xbridge', 'bridge'))
        merged = loader.apply_overlay(base, ov, 'x', 'xbridge')
        full, _ = gen_headers.gen('xbridge', gen_headers.CHIPS['xbridge'])
        want = normalize(full)
        got = normalize(merged)
        self.assertEqual(got['registers'], want['registers'])
        self.assertEqual(got['constants'], want['constants'])
        self.assertEqual(got['prefix'], 'XBRIDGE')
        self.assertEqual(got['c']['legacy_header'], 'include/xbridge.h')
        self.assertEqual(list(ov['add']['registers']), ['170'])


class BootSpace(unittest.TestCase):
    """Boot-space accesses keep their own rows, and the header keeps old names as aliases."""

    CFG = {'address_spaces': {'window-18': {'space': 'boot-space', 'slot_bytes': 4}},
           'deprecated_defines': [
               {'name': 'BEDROCK_OLD_NAME', 'space': 'boot-space', 'offset': '0x78', 'why': 'was a boot-space row'},
               {'name': 'BEDROCK_OLD_NAME_B_0', 'space': '', 'offset': '0x78', 'field': '_B_0', 'why': 'was a boot-space row'}]}
    SCAN = ['image', 'function', 'addr', 'insn', 'rw', 'width', 'partial', 'window', 'offset', 'idx', 'variant', 'basis']

    def setUp(self):
        self.old = os.getcwd()
        self.addCleanup(os.chdir, self.old)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.chdir(tmp.name)
        os.makedirs('tools/configs')
        cfg = dict(self.CFG, asic='bedrock', mode='no-spec', variant_model={'default': {'access': 'dw64'}})
        json.dump(cfg, open('tools/configs/bedrock.json', 'w'))
        site = lambda fn, win, insn, w, off: ['ip35-kernel', fn, '1000', insn, 'r', w, '0', win, off, '0', 'bedrock', 'image-hint']
        write('sites.tsv', self.SCAN, [
            site('reg_reader', 'local-block-window', 'ld', '8', '0x78'),
            site('reg_reader', 'local-block-window', 'ld', '8', '0x98'),
            site('boot_reader', 'window-18', 'ld', '8', '0x78'),
            site('boot_word', 'window-18', 'lwu', '4', '0x9c'),
        ])
        json.dump({}, open('ref.json', 'w'))
        subprocess.run([sys.executable, os.path.join(HERE, 'join.py'), 'tools/configs/bedrock.json', '--sites', 'sites.tsv',
                        '--ref', 'ref.json', '--out', 'out'], check=True, capture_output=True)
        self.rows = list(csv.DictReader(open('out-census.tsv'), delimiter='\t'))

    def test_window_is_part_of_the_row_key(self):
        got = sorted((r['space'], r['offset'], r['widths'], r['sites']) for r in self.rows)
        self.assertEqual(got, [('', '0x78', '8', '1'), ('', '0x98', '8', '1'),
                               ('boot-space', '0x78', '8', '1'), ('boot-space', '0x9c', '4', '1')])

    def test_boot_space_row_is_not_compared_and_has_no_register_flag(self):
        boot = [r for r in self.rows if r['space']]
        self.assertTrue(all(r['model'] == 'out-of-scope' and not r['flags'] for r in boot))

    def test_register_row_keeps_its_width(self):
        reg = {r['offset']: r for r in self.rows if not r['space']}
        self.assertEqual(reg['0x98']['widths'], '8')

    def test_sites_carry_their_space(self):
        sites = list(csv.DictReader(open('out-census-sites.tsv'), delimiter='\t'))
        self.assertEqual({(s['function'], s['space']) for s in sites},
                         {('reg_reader', ''), ('boot_reader', 'boot-space'), ('boot_word', 'boot-space')})

    def test_header_separates_the_spaces_and_keeps_old_names(self):
        d = 'chips/bedrock/census/'
        os.makedirs(d)
        for f in ('census', 'census-sites'):
            os.replace('out-%s.tsv' % f, d + f + '.tsv')
        write(d + 'fields.tsv', ['variant', 'space', 'register', 'source', 'kind', 'bits_or_value', 'sites', 'functions', 'example'],
              [['bedrock', '', '0x78', 'load', 'mask', '0', '1', '1', 'x']])
        defs, aliases = macros('bedrock')
        self.assertEqual(defs.get('BEDROCK_REG_READER'), 0x78)
        self.assertEqual(defs.get('BEDROCK_BOOT_SPACE_BOOT_READER'), 0x78)
        self.assertEqual(defs.get('BEDROCK_BOOT_SPACE_BOOT_WORD'), 0x9c)
        self.assertEqual(aliases.get('BEDROCK_OLD_NAME'), 'BEDROCK_BOOT_SPACE_BOOT_READER')


if __name__ == '__main__':
    unittest.main()
