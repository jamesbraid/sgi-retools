#!/usr/bin/env python3
"""Tests of the MMSC a.out loader.

Run: python3 scripts/sysco/test_mmsc_aout.py
The synthetic cases need nothing. The real-image case runs when MMSC_IMAGE names
an mmscfw.bin (a workspace's root/<release>/usr/cpu/firmware/mmscfw.bin) and is
skipped otherwise.
"""
import io
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mmsc_aout  # noqa: E402

BASE = 0x108000


def build(text, data, bss, syms, etext=None):
    """An a.out: syms is a list of (name, type byte, value)."""
    names = b''
    recs = b''
    for name, typ, val in syms:
        recs += struct.pack('<IBbhI', 4 + len(names), typ, 0, 0, val)
        names += name.encode() + b'\0'
    hdr = struct.pack('<8I', 0o407, len(text), len(data), bss, len(recs), BASE,
                      0x5aa5a55a, 0)
    return hdr + text + data + recs + struct.pack('<I', 4 + len(names)) + names


def small():
    text = b'\x55\x89\xe5\xc3' + b'\x90' * 12
    data = b'\x11\x22\x33\x44' + b'\0' * 12
    de = BASE + len(text) + len(data)
    syms = [('_sysInit', 5, BASE), ('_helper', 5, BASE + 4),
            ('_etext', 5, BASE + len(text)),
            ('_table', 7, BASE + len(text)), ('_edata', 7, de),
            ('_buf', 9, de), ('_end', 9, de + 32), ('gcc2_compiled.', 4, BASE),
            ('_stab', 0x24, BASE)]
    return build(text, data, 32, syms)


class Parse(unittest.TestCase):
    def test_segments_follow_each_other_without_padding(self):
        img = mmsc_aout.Image(small())
        t, d, b = img.segments
        self.assertEqual((t.addr, t.size, t.fileoff), (BASE, 16, 32))
        self.assertEqual((d.addr, d.size, d.fileoff), (BASE + 16, 16, 48))
        self.assertEqual((b.addr, b.size, b.fileoff), (BASE + 32, 32, -1))

    def test_symbol_kinds_and_sizes(self):
        img = mmsc_aout.Image(small())
        by = {s.name: s for s in img.symbols}
        self.assertEqual((by['_sysInit'].kind, by['_sysInit'].glob), ('text', True))
        self.assertEqual(by['_sysInit'].size, 4)       # up to _helper
        self.assertEqual(by['_table'].kind, 'data')
        self.assertEqual(by['_buf'].kind, 'bss')
        self.assertEqual(by['_stab'].kind, 'stab')
        self.assertEqual(by['_stab'].stab, 'fun')
        self.assertTrue(by['gcc2_compiled.'].marker)

    def test_read_is_by_load_address(self):
        img = mmsc_aout.Image(small())
        self.assertEqual(img.read(BASE, 3), b'\x55\x89\xe5')
        self.assertEqual(img.read(BASE + 16, 4), b'\x11\x22\x33\x44')
        with self.assertRaises(mmsc_aout.ImageError):
            img.read(BASE + 32, 4)                     # bss has no bytes

    def test_rejects_other_magic_and_bad_names(self):
        blob = bytearray(small())
        blob[0] = 0x0b
        with self.assertRaises(mmsc_aout.ImageError):
            mmsc_aout.Image(bytes(blob))
        blob = bytearray(small())
        struct.pack_into('<I', blob, 32 + 16 + 16, 0x7fffff)   # first name offset
        with self.assertRaises(mmsc_aout.ImageError):
            mmsc_aout.Image(bytes(blob))


class Output(unittest.TestCase):
    def test_tsv_skips_markers_and_stabs(self):
        out = io.StringIO()
        mmsc_aout.write_tsv(mmsc_aout.Image(small()), out)
        rows = [l.split('\t') for l in out.getvalue().splitlines()
                if not l.startswith('#')]
        self.assertEqual([r[0] for r in rows[:3]], ['SEG'] * 3)
        names = [r[3] for r in rows if r[0] == 'SYM']
        self.assertIn('_sysInit', names)
        self.assertNotIn('gcc2_compiled.', names)
        self.assertNotIn('_stab', names)
        self.assertEqual(rows[0][2:], ['0x108000', '32', '16'])

    def test_check_flags_a_misplaced_end_symbol(self):
        good = {n: ok for n, ok, _ in mmsc_aout.check(mmsc_aout.Image(small()))}
        self.assertTrue(good['_etext closes its segment'])
        blob = bytearray(small())
        # _etext is the third record: move its value off the segment end
        struct.pack_into('<I', blob, 32 + 16 + 16 + 12 * 2 + 8, BASE + 8)
        bad = {n: ok for n, ok, _ in mmsc_aout.check(mmsc_aout.Image(bytes(blob)))}
        self.assertFalse(bad['_etext closes its segment'])


@unittest.skipUnless(os.environ.get('MMSC_IMAGE'), 'MMSC_IMAGE not set')
class RealImage(unittest.TestCase):
    def setUp(self):
        with open(os.environ['MMSC_IMAGE'], 'rb') as f:
            self.img = mmsc_aout.Image(f.read())

    def test_every_check_passes(self):
        failed = [(n, d) for n, ok, d in mmsc_aout.check(self.img) if not ok]
        self.assertEqual(failed, [])

    def test_symbol_table_has_7907_entries_in_the_2_3_image(self):
        if b'MMSC VERSION 2.3' not in self.img.blob:
            self.skipTest('not the 2.3 image')
        self.assertEqual(len(self.img.symbols), 7907)
        self.assertEqual([hex(s.addr) for s in self.img.segments],
                         ['0x108000', '0x1afbd8', '0x1d87d8'])


if __name__ == '__main__':
    unittest.main()
