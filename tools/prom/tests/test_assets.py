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
from prom.assets import glyphs, png  # noqa: E402


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


if __name__ == '__main__':
    unittest.main()
