#!/usr/bin/env python3
"""promkit's asset codecs and readers, against bitmaps and code built here (never SGI bytes).

Run: python3 tools/prom/tests/test_assets.py
"""
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
import fixtures as fx  # noqa: E402
from prom.assets import glyphs, mips, png  # noqa: E402


def pack_rows(rows):
    """Rows (bottom first, lists of 0/1) as the PROM stores them: big-endian halfwords, leftmost pixel on top."""
    out = b''
    for row in rows:
        row = row + [0] * (-len(row) % 16)
        out += b''.join(struct.pack('>H', int(''.join(map(str, row[i:i + 16])), 2)) for i in range(0, len(row), 16))
    return out


def encode_rle(rows):
    """Run-length rows as the PROM stores them: alternating gap and run lengths from a gap, 255 then 0 to continue."""
    out = bytearray()
    for row in rows:
        x, ink = 0, 0
        while x < len(row):
            n = 0
            while x + n < len(row) and row[x + n] == ink:
                n += 1
            out += b'\xff\0' * (n // 255) + bytes([n % 255]) if n >= 255 else bytes([n])
            x += n
            ink ^= 1
    return bytes(out)


class Png(unittest.TestCase):
    def test_pixels_round_trip_and_the_output_is_stable(self):
        px = bytes(range(24))
        data = png.png(3, 2, px, png.RGBA)
        self.assertEqual(png.decode(data), (3, 2, png.RGBA, px))
        self.assertEqual(png.png(3, 2, px, png.RGBA), data)

    def test_a_mask_is_opaque_white_ink_on_transparent(self):
        w, h, _, px = png.decode(png.mask_png([[1, 0], [0, 1]]))
        self.assertEqual((w, h, px), (2, 2, b'\xff\xff\0\0\0\0\xff\xff'))

    def test_wrong_pixel_count_is_refused(self):
        with self.assertRaises(ValueError):
            png.png(2, 2, b'\0' * 7, png.GRAY_ALPHA)


class Glyphs(unittest.TestCase):
    ROWS = [[1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1], [0] * 17 + [1], [1] * 18]

    def test_rows_unpack_most_significant_bit_first_and_a_wide_row_takes_two_halfwords(self):
        data = pack_rows(self.ROWS)
        self.assertEqual(len(data), 3 * 2 * glyphs.stride(18))
        self.assertEqual(glyphs.unpack_rows(data, 18, 3), self.ROWS)

    def test_a_bitmap_of_the_wrong_size_is_refused(self):
        with self.assertRaises(ValueError):
            glyphs.unpack_rows(b'\0' * 5, 9, 2)

    def test_entries_are_signed_where_the_format_is(self):
        raw = struct.pack('>hBBbbH', -3, 9, 20, -2, -4, 12) + struct.pack('>hBBbbH', 7, 1, 1, 0, 0, 9)
        e = glyphs.parse_entries(raw, 2)
        self.assertEqual(e[0], glyphs.Entry(-3, 9, 20, -2, -4, 12))
        self.assertEqual(glyphs.entry_span(e[1]), (14, 16))

    def test_run_length_rows_with_split_gaps_and_runs_round_trip(self):
        rows = [[0] * 300, [0] * 255 + [1] * 45, [1] * 3 + [0] * 4 + [1] * 2 + [0] * 291, [1] * 300]
        data = encode_rle(rows)
        got, used = glyphs.decode_rle(data, 300, 4)
        self.assertEqual((used, [list(r) for r in got]), (len(data), rows))

    def test_leading_zero_length_pairs_decode_the_same(self):
        row = [0] * 20
        a, _ = glyphs.decode_rle(encode_rle([row]), 20, 1)
        b, _ = glyphs.decode_rle(b'\0' * 12 + encode_rle([row]), 20, 1)
        self.assertEqual(a, b)

    def test_truncated_run_length_data_is_refused(self):
        with self.assertRaises(ValueError):
            glyphs.decode_rle(b'\x05', 20, 1)

    def test_bdf_lists_rows_top_first_with_the_prom_offsets(self):
        g = {'encoding': 65, 'name': 'u0041', 'width': 3, 'height': 2, 'xoffset': 1, 'yoffset': -1, 'advance': 5,
             'rows': [[1, 0, 0], [0, 1, 1]]}
        text = glyphs.bdf('t', 7, 2, [g])
        self.assertIn('BBX 3 2 1 -1\nBITMAP\n60\n80\nENDCHAR', text)
        self.assertIn('FONT_ASCENT 5\nFONT_DESCENT 2', text)
        self.assertIn('DWIDTH 5 0', text)


BASE = 0x81000000


def run(*words, start=0):
    m = mips.Machine(mips.decode_all(fx.mips(*words), BASE), BASE)
    m.run(BASE + start)
    return m


class Mips(unittest.TestCase):
    def test_a_stored_address_is_built_from_lui_and_addiu(self):
        # t6 = 0x8105b971 (a negative low half), t7 = 0x1234; store t7 8 past it
        m = run(fx.lui(14, 0x8106), fx.addiu(14, 14, -0x468f), fx.addiu(15, 0, 0x1234), fx.sw(15, 8, 14),
                fx.JR_RA, fx.NOP)
        self.assertEqual([(w.addr, w.value) for w in m.writes], [(0x8105b979, 0x1234)])

    def test_a_call_through_a_table_slot_reports_the_slot_and_arguments(self):
        m = run(fx.addiu(5, 0, 7), fx.lw(25, 8, 16), fx.addiu(6, 0, 255), fx.jalr(25), fx.addiu(7, 0, 3),
                fx.JR_RA, fx.NOP)
        (c,) = m.calls
        self.assertEqual((c.slot, c.args[1:]), (8, [7, 255, 3]))

    def test_a_loop_runs_to_its_count_and_the_fifth_argument_is_read_from_the_stack(self):
        # s0 counts to 3 around a call; the stack slot at 16(sp) holds s0 + 10
        m = run(fx.addiu(16, 0, 0), fx.addiu(18, 0, 3),
                fx.addiu(8, 16, 10), fx.sw(8, 16, 29), fx.lw(25, 4, 17), fx.jalr(25), fx.addiu(5, 16, 100),
                fx.addiu(16, 16, 1), fx.bne(16, 18, -7 & 0xffff), fx.NOP, fx.JR_RA, fx.NOP)
        self.assertEqual([(c.args[1], c.stack0) for c in m.calls], [(100, 10), (101, 11), (102, 12)])

    def test_a_value_read_from_an_out_parameter_is_tagged(self):
        # the callee gets a pointer into the stack; the default stored after it is still tagged as its output
        m = run(fx.addiu(4, 29, 24), fx.lw(25, 4, 17), fx.jalr(25), fx.NOP,
                fx.addiu(8, 0, 9), fx.sw(8, 24, 29), fx.lw(6, 24, 29), fx.lw(25, 8, 17), fx.jalr(25), fx.NOP,
                fx.JR_RA, fx.NOP)
        self.assertEqual((m.calls[1].args[2], m.calls[1].tags[0]), (9, 'out:0'))

    def test_a_branch_on_an_unknown_register_is_refused(self):
        with self.assertRaises(mips.Unknown):
            run(fx.lw(8, 0, 16), fx.bne(8, 0, 2), fx.NOP, fx.JR_RA, fx.NOP)

    def test_routines_start_after_each_return_slot(self):
        code = mips.decode_all(fx.mips(fx.NOP, fx.JR_RA, fx.NOP, fx.NOP, fx.JR_RA, fx.NOP, fx.NOP), BASE)
        self.assertEqual(mips.routines(code), [0, 3, 6])
        self.assertEqual(mips.routine_at([0, 3, 6], 4), (3, 6))


if __name__ == '__main__':
    unittest.main()
