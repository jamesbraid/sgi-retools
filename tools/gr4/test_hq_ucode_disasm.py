#!/usr/bin/env python3
"""Tests of hq_ucode_disasm.py on a synthetic listing built from known words.
They need no microcode file.

Run from the repository root: python3 tools/gr4/test_hq_ucode_disasm.py
"""
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hq_ucode_disasm as hq  # noqa: E402


def make_listing():
    banner = b'uasm 6.0\ntest\n'
    names = b'/a/dir/\0/a/dir/main.uc\0/a/dir/ctx.uc\0'
    dispatch = struct.pack('>512I', *([0x28a, 0x318] + [0x28c] * 510))
    head_len = 4 * (11 + 512)
    b_off = head_len
    banner_off = head_len
    code_off = banner_off + len(banner)
    lines_off = code_off
    recs = struct.pack('>IHH', 0, 34, 1) + struct.pack('>IHH', 0x4fc, 879, 2)
    names_off = lines_off + len(recs)
    hdr = struct.pack('>11I', 0x00030003, banner_off, len(banner), code_off, lines_off,
                      lines_off, lines_off, lines_off + len(recs), 0, names_off, len(names))
    # word 7 is the end of the line table here; the name-offset table is empty.
    return hdr + dispatch + banner + recs + names, b_off


class Container(unittest.TestCase):
    def test_parse(self):
        data, _ = make_listing()
        uc = hq.parse_u(data)
        self.assertTrue(uc.banner.startswith('uasm 6.0'))
        self.assertEqual(uc.dispatch[0], 0x28a)
        self.assertEqual(uc.dispatch[1], 0x318)
        self.assertEqual(uc.lines[0], ('main.uc', 34))
        self.assertEqual(uc.lines[0x4fc], ('ctx.uc', 879))

    def test_bad_tag(self):
        data, _ = make_listing()
        with self.assertRaises(ValueError):
            hq.parse_u(b'\0\0\0\1' + data[4:])

    def test_bad_file_index(self):
        data, _ = make_listing()
        bad = data.replace(struct.pack('>IHH', 0x4fc, 879, 2), struct.pack('>IHH', 0x4fc, 879, 9))
        with self.assertRaises(ValueError):
            hq.parse_u(bad)


class Words(unittest.TestCase):
    # Words read from the 6.5.13f image: the vector at 4, the call into the
    # shared routine at 0x406, its return, a pointer-register load and moves.
    def test_forms(self):
        self.assertEqual(hq.disasm(0x000000), 'nop')
        self.assertTrue(hq.disasm(0x83836b).startswith('jmp?   0x36b'))
        self.assertTrue(hq.disasm(0x83c406).startswith('jmp?   0x406'))
        self.assertEqual(hq.disasm(0x83a000), 'ret?')
        self.assertEqual(hq.disasm(0x4e4004), 'imm    re, 0x4004')
        self.assertEqual(hq.disasm(0x4c0048), 'imm    rc, 0x0048')
        self.assertTrue(hq.disasm(0xdb2801).startswith('mov?   r27 -> d5.0'))
        self.assertTrue(hq.disasm(0x5f77b1).startswith('op5f'))

    def test_bin_words(self):
        raw = struct.pack('>3I', 0x00838268, 0x00000000, 0x004e4004)
        self.assertEqual(hq.parse_bin(raw), [0x838268, 0, 0x4e4004])

    def test_imm_writes(self):
        words = [0x4e4004, 0x000000, 0x4e0050, 0x4c0048]
        self.assertEqual(hq.imm_writes(words, 0xe, 0, 4), [(0, 0x4004), (2, 0x0050)])
        self.assertEqual(hq.imm_writes(words, 0xe, 1, 2), [])


if __name__ == '__main__':
    unittest.main()
