#!/usr/bin/env python3
"""promkit's asset codecs and readers, against bitmaps and code built here (never SGI bytes).

Run: python3 tools/prom/tests/test_assets.py
"""
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
import fixtures as fx  # noqa: E402
from prom.assets import AssetError, glyphs, ip32, mips, png  # noqa: E402


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


class Ip32Code(unittest.TestCase):
    """The finders that read constants from code, on routines built here."""

    def palette_routine(self, iterations=120, extra=()):
        # sets entry 1 to (255, 0, 9), then a ramp from index 96: r, g and b each a running 32-bit sum
        entry = [fx.lw(25, 8, 21), fx.addiu(5, 0, 1), fx.addiu(6, 0, 255), fx.addiu(8, 0, 9), fx.sw(8, 16, 29),
                 fx.jalr(25), fx.addiu(7, 0, 0)]
        setup = [fx.lui(18, 0x5f), fx.or_(17, 18, 0), fx.lui(19, 0x8f), fx.addiu(16, 0, 0)]
        body = [fx.sra(9, 19, 16), fx.sw(9, 16, 29), fx.lw(25, 8, 21), fx.addiu(5, 16, 96), fx.sra(6, 17, 16), fx.jalr(25),
                fx.sra(7, 18, 16), fx.ori(1, 0, 0x8199), fx.addu(17, 17, 1), fx.ori(1, 0, 0xb800), fx.addu(18, 18, 1),
                fx.ori(1, 0, 0xb333), fx.addu(19, 19, 1), fx.addiu(1, 0, iterations), fx.addiu(16, 16, 1),
                fx.bne(16, 1, -16 & 0xffff), fx.NOP]
        return [fx.addiu(29, 29, -104)] + entry + setup + body + list(extra) + [fx.JR_RA, fx.NOP]

    def test_the_palette_is_the_calls_and_the_ramp_comes_from_the_running_sums(self):
        r = ip32.Reader(fx.asset_segment(self.palette_routine()))
        ip32.palette(r, self.out())
        doc = json.loads(self.read('assets/palette.json'))
        by = {e['index']: e['rgb'] for e in doc['entries']}
        self.assertEqual(by[1], [255, 0, 9])
        self.assertEqual(len(by), 121)
        self.assertEqual(doc['ramp']['first_index'], 96)
        self.assertEqual([c['step'] for c in doc['ramp']['channels']], ['0x8199', '0xb800', '0xb333'])
        for i in (0, 57, 119):
            want = [(0x5f0000 + 0x8199 * i) >> 16, (0x5f0000 + 0xb800 * i) >> 16, (0x8f0000 + 0xb333 * i) >> 16]
            self.assertEqual(by[96 + i], want)
        self.assertEqual(doc['unwritten'][:3], [0, 2, 3])

    def test_the_swatch_paints_index_i_in_cell_i_and_leaves_unwritten_cells_clear(self):
        ip32.palette(ip32.Reader(fx.asset_segment(self.palette_routine())), self.out())
        w, h, _, px = png.decode(self.read('assets/palette.png', 'rb'))
        pixel = lambda i: px[((i // 16 * 16 + 3) * 256 + i % 16 * 16 + 5) * 4:][:4]
        self.assertEqual((w, h, pixel(1), pixel(2)), (256, 256, b'\xff\0\x09\xff', b'\0\0\0\0'))

    def test_a_routine_without_the_three_increments_is_not_a_palette(self):
        code = [w for w in self.palette_routine() if w != fx.ori(1, 0, 0xb800)]
        with self.assertRaises(AssetError):
            ip32.palette(ip32.Reader(fx.asset_segment(code)), self.out())

    def test_the_gradient_routine_is_the_one_with_the_divide_and_both_constants(self):
        gradient = [fx.lui(24, 0xa0), fx.lui(1, 0x60), fx.div(15, 24), fx.sra(5, 18, 16), fx.JR_RA, fx.NOP]
        decoy = [fx.lui(24, 0xa0), fx.JR_RA, fx.NOP]
        r = ip32.Reader(fx.asset_segment(decoy + gradient))
        ip32.gradient(r, self.out())
        doc = json.loads(self.read('assets/gradient.json'))
        self.assertEqual((doc['routine'], doc['numerator'], doc['base'], doc['first_index']), ('0x8100000c', '0xa00000', '0x600000', 96))
        with self.assertRaises(AssetError):
            ip32.gradient(ip32.Reader(fx.asset_segment(decoy)), self.out())

    def test_layout_needs_both_routines_with_their_constants(self):
        menu = [fx.slti(1, 2, 1051)] + [fx.addiu(8, 0, v) for v in (65, 150, 50, 60, 15, -75, -25, 3, 2)] + [fx.JR_RA, fx.NOP]
        bg = [fx.slti(1, 2, 1051)] + [fx.addiu(8, 0, v) for v in (601, 150, 200, 530, 520, 65, 445, 80, 66, 48, 49, 50)] + [fx.JR_RA, fx.NOP]
        r = ip32.Reader(fx.asset_segment(menu + bg))
        ip32.layout(r, self.out())
        doc = json.loads(self.read('assets/layout.json'))
        self.assertEqual((doc['menu']['routine'], doc['background']['routine']), ('0x81000000', '0x81000030'))
        with self.assertRaises(AssetError):
            ip32.layout(ip32.Reader(fx.asset_segment(menu + bg[:-8] + bg[-2:])), self.out())

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def out(self):
        return self.dir

    def read(self, rel, mode='r'):
        with open(os.path.join(self.dir, rel), mode) as f:
            return f.read()


if __name__ == '__main__':
    unittest.main()
