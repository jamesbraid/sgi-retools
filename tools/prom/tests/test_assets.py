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


def palette_routine(iterations=120, extra=()):
    # sets entry 1 to (255, 0, 9), then a ramp from index 96: r, g and b each a running 32-bit sum
    entry = [fx.lw(25, 8, 21), fx.addiu(5, 0, 1), fx.addiu(6, 0, 255), fx.addiu(8, 0, 9), fx.sw(8, 16, 29),
             fx.jalr(25), fx.addiu(7, 0, 0)]
    setup = [fx.lui(18, 0x5f), fx.or_(17, 18, 0), fx.lui(19, 0x8f), fx.addiu(16, 0, 0)]
    body = [fx.sra(9, 19, 16), fx.sw(9, 16, 29), fx.lw(25, 8, 21), fx.addiu(5, 16, 96), fx.sra(6, 17, 16), fx.jalr(25),
            fx.sra(7, 18, 16), fx.ori(1, 0, 0x8199), fx.addu(17, 17, 1), fx.ori(1, 0, 0xb800), fx.addu(18, 18, 1),
            fx.ori(1, 0, 0xb333), fx.addu(19, 19, 1), fx.addiu(1, 0, iterations), fx.addiu(16, 16, 1),
            fx.bne(16, 1, -16 & 0xffff), fx.NOP]
    return [fx.addiu(29, 29, -104)] + entry + setup + body + list(extra) + [fx.JR_RA, fx.NOP]


class Ip32Code(unittest.TestCase):
    """The finders that read constants from code, on routines built here."""

    def test_the_palette_is_the_calls_and_the_ramp_comes_from_the_running_sums(self):
        r = ip32.Reader(fx.asset_segment(palette_routine()))
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
        ip32.palette(ip32.Reader(fx.asset_segment(palette_routine())), self.out())
        w, h, _, px = png.decode(self.read('assets/palette.png', 'rb'))
        pixel = lambda i: px[((i // 16 * 16 + 3) * 256 + i % 16 * 16 + 5) * 4:][:4]
        self.assertEqual((w, h, pixel(1), pixel(2)), (256, 256, b'\xff\0\x09\xff', b'\0\0\0\0'))

    def test_a_routine_without_the_three_increments_is_not_a_palette(self):
        code = [w for w in palette_routine() if w != fx.ori(1, 0, 0xb800)]
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


def pen_glyph(seed, w, h):
    """A w by h glyph of rows (bottom first) from a fixed pattern, never all clear."""
    return [[(x * 7 + y * 3 + seed) % 3 == 0 or (x, y) == (0, 0) for x in range(w)] for y in range(h)]


def font_data(glyph_specs, pad=0):
    """A bitmap region and its entry table for glyphs given as (rows, xoffset, yoffset, advance)."""
    bitmap, table = b'', b''
    for rows, xo, yo, adv in glyph_specs:
        table += struct.pack('>hBBbbH', len(bitmap) // 2, len(rows[0]), len(rows), xo, yo, adv)
        bitmap += pack_rows([[int(v) for v in row] for row in rows])
    return bitmap + b'\0' * pad, table


def li32(rt, value):
    return [fx.lui(rt, value >> 16), fx.ori(rt, rt, value & 0xffff)]


def assemble(make_code, data):
    """A firmware segment whose code can name the data's run-time address: the code length cannot depend on it."""
    n = len(make_code(0))
    return fx.asset_segment(make_code(0x81000000 + 4 * n), data=data), 0x81000000 + 4 * n


class Ip32Fonts(unittest.TestCase):
    SPECS = [
        [(pen_glyph(1, 1, 1), 0, 0, 9), (pen_glyph(2, 5, 12), 2, -3, 9)],                          # font 0
        [(pen_glyph(3, 9, 2), 0, -4, 9), (pen_glyph(4, 9, 3), 0, -4, 0)],                          # font 1
        [(pen_glyph(5, 1, 1), 0, 0, 7), (pen_glyph(6, 17, 4), 1, 2, 18), (pen_glyph(7, 4, 5), 0, 0, 5)],   # font 2
        [(pen_glyph(8, 1, 1), 0, 0, 4), (pen_glyph(9, 6, 7), 1, 1, 8)],                            # font 3
    ]

    def build(self, specs=None, lookup=True, tails=(0, 0, 0, 0)):
        fonts = [font_data(s, pad=2 if k == 3 else 0) for k, s in enumerate(specs or self.SPECS)]
        data = b''.join(b + t + b'\0' * tails[k] for k, (b, t) in enumerate(fonts))

        def code(data_addr):
            at, ptrs = data_addr, []
            for k, (b, t) in enumerate(fonts):
                ptrs.append((at, at + len(b)))
                at += len(b) + len(t) + tails[k]
            w = li32(12, 0x81070000)
            for k, ((bp, tp), h, d) in enumerate(zip(ptrs, (17, 20, 23, 14), (4, 4, 5, 3))):
                w += li32(8, bp) + [fx.sw(8, 12 * k, 12)] + li32(8, tp) + [fx.sw(8, 12 * k + 4, 12),
                                                                        fx.addiu(9, 0, h), fx.sh(9, 12 * k + 8, 12),
                                                                        fx.addiu(9, 0, d), fx.sh(9, 12 * k + 10, 12)]
            w += [fx.JR_RA, fx.NOP]
            if lookup:
                w += [fx.slti(1, 4, 7), fx.andi(8, 5, 128), fx.addiu(4, 0, 32), fx.addiu(6, 0, 66), fx.JR_RA, fx.NOP]
            self.tables = [tp for bp, tp in ptrs]
            return w
        return assemble(code, data)

    def run_fonts(self, patch=None, **kw):
        seg, _ = self.build(**kw)
        if patch:
            patch(seg)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        r = ip32.Reader(seg)
        ip32.fonts(r, self.dir)
        return r

    def doc(self, k):
        with open(os.path.join(self.dir, 'assets/font-%d.json' % k)) as f:
            return json.load(f)

    def test_the_four_fonts_come_out_with_their_counts_heights_and_a_fixed_advance(self):
        self.run_fonts()
        self.assertEqual([self.doc(k)['entry_count'] for k in range(4)], [2, 2, 3, 2])
        self.assertEqual([(self.doc(k)['height'], self.doc(k)['descent']) for k in range(4)], [(17, 4), (20, 4), (23, 5), (14, 3)])
        self.assertEqual([self.doc(k)['fixed_advance'] for k in range(4)], [9, None, None, None])

    def test_a_glyph_in_the_bdf_has_the_rows_and_offsets_it_was_built_with(self):
        self.run_fonts()
        with open(os.path.join(self.dir, 'assets/font-2.bdf')) as f:
            text = f.read()
        rows = self.SPECS[2][1][0]
        # code 0x21 is entry 1 of font 2; BDF lists the top row first and pads each row to whole bytes
        want = '\n'.join('%06X' % int(''.join('1' if v else '0' for v in row).ljust(24, '0'), 2) for row in reversed(rows))
        self.assertIn('ENCODING 33\nSWIDTH 0 0\nDWIDTH 18 0\nBBX 17 4 1 2\nBITMAP\n' + want + '\nENDCHAR', text)
        self.assertIn('CHARS 3', text)       # codes 0x20 to 0x22; every higher code is past the 3 entries

    def test_font_1_entries_answer_to_the_codes_below_7_only(self):
        self.run_fonts()
        with open(os.path.join(self.dir, 'assets/font-1.bdf')) as f:
            text = f.read()
        self.assertIn('CHARS 2', text)
        self.assertIn('ENCODING 0\n', text)
        self.assertIn('ENCODING 1\n', text)

    def test_an_entry_that_runs_past_its_bitmap_is_marked_and_left_out(self):
        def patch(seg):             # font 2's last entry now claims 40 rows (the height byte is the 4th of its 8)
            off = ip32.Firmware(seg).offset(self.tables[2] + 16 + 3)
            seg.data = seg.data[:off] + bytes([40]) + seg.data[off + 1:]
        self.run_fonts(patch)
        self.assertEqual([e['index'] for e in self.doc(2)['entries'] if 'drawable' in e], [2])
        with open(os.path.join(self.dir, 'assets/font-2.bdf')) as f:
            self.assertIn('CHARS 2', f.read())

    def test_without_the_lookup_routine_the_fonts_are_refused(self):
        with self.assertRaises(AssetError):
            self.run_fonts(lookup=False)

    def test_a_table_that_does_not_end_on_whole_entries_is_refused(self):
        with self.assertRaises(AssetError):
            self.run_fonts(tails=(0, 4, 0, 0))


class Ip32Tagline(unittest.TestCase):
    GLYPHS = [(pen_glyph(1, 5, 6), 0, 0, 6), (pen_glyph(2, 12, 7), 1, -1, 13), (pen_glyph(3, 3, 3), 0, 2, 4)]

    def build(self, chars=(1, 0, 2, 2), pad=0):
        pool, table = font_data(self.GLYPHS)
        data = pool + b'\0' * pad + table + bytes(chars) + b'\xff'

        def code(at):
            ptrs = [at, at + len(pool) + pad, at + len(pool) + pad + len(table)]
            return ([fx.addiu(19, 0, 255), 0x88000000 | 17 << 16, 0x98000000 | 17 << 16, fx.sll(24, 17, 3)] +
                    li32(22, ptrs[0]) + li32(21, ptrs[1]) + li32(16, ptrs[2]) + [fx.addiu(16, 16, 1), fx.JR_RA, fx.NOP])
        return assemble(code, data)[0]

    def run_tagline(self, **kw):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        ip32.tagline(ip32.Reader(self.build(**kw)), self.dir)
        with open(os.path.join(self.dir, 'assets/tagline.json')) as f:
            return json.load(f)

    def test_the_pool_entries_and_index_are_found_in_address_order(self):
        doc = self.run_tagline()
        self.assertEqual((doc['entry_count'], doc['index'], doc['pool_size']), (3, [1, 0, 2, 2], 12 + 14 + 6))      # two bytes a row

    def test_the_bdf_holds_one_glyph_per_entry_encoded_by_entry_index(self):
        self.run_tagline()
        with open(os.path.join(self.dir, 'assets/tagline.bdf')) as f:
            text = f.read()
        self.assertIn('CHARS 3', text)
        self.assertIn('ENCODING 1\nSWIDTH 0 0\nDWIDTH 13 0\nBBX 12 7 1 -1', text)

    def test_a_pool_the_glyphs_do_not_consume_exactly_is_refused(self):
        with self.assertRaises(AssetError):
            self.run_tagline(pad=4)

    def test_an_index_naming_a_missing_entry_is_refused(self):
        with self.assertRaises(AssetError):
            self.run_tagline(chars=(0, 3))


class Ip32Icons(unittest.TestCase):
    """Ten icons: six stored into menu records by code, four named by a data table (as the dialog's)."""
    SIZE = (6, 5)

    def layers(self, k):
        # layer 0 fills the icon in palette colour 1; layer 1 is a 2 by 2 square at (1, 1) in colour 96
        return [(1, 0, 0, 6, 5, [[1] * 6 for _ in range(5)]), (96, 1, 1, 2, 2, [[1, 1], [1, 0]])]

    def build(self, menu_icons=6):
        bitmaps = [[pack_rows([[int(v) for v in row] for row in rows]).ljust(12, b'\0')
                    for _, _, _, _, _, rows in self.layers(k)] for k in range(10)]
        per_icon = sum(len(b) for b in bitmaps[0]) + 24 * 3 + 20

        def layout(at):
            """Each icon's bitmaps, layer list (two layers and the terminator) and object, back to back from at."""
            out = []
            for k in range(10):
                bm = [at + sum(len(x) for x in bitmaps[k][:n]) for n in range(2)]
                lst = at + sum(len(x) for x in bitmaps[k])
                out.append((bm, lst, lst + 72))
                at += per_icon
            return out, at

        def code(data_addr):
            self.addrs = [obj for _, _, obj in layout(data_addr)[0]]
            w = palette_routine() + li32(12, 0x81070000)
            for n in range(menu_icons):
                w += li32(8, self.addrs[n]) + [fx.sw(8, 12 + 16 * n, 12)]
            return w + [fx.JR_RA, fx.NOP]

        base = assemble(code, b'')[1]
        placed, end = layout(base)
        data = b''
        for k, (bm, lst, obj) in enumerate(placed):
            data += b''.join(bitmaps[k])
            for (colour, x, y, w, h, _), a in zip(self.layers(k), bm):
                data += struct.pack('>6I', colour, x, y, w, h, a)
            data += struct.pack('>6I', 0, 0, 0, 0, 0, 0) + struct.pack('>IIiiI', 6, 5, 0, -2 if k == 3 else 0, lst)
        data += b''.join(struct.pack('>6I', 0, 0, 0, 0, 0, a) for a in self.addrs[6:])
        return assemble(code, data)[0]

    def run_icons(self, **kw):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        r = ip32.Reader(self.build(**kw))
        ip32.icons(r, self.dir)
        with open(os.path.join(self.dir, 'assets/icons/icons.json')) as f:
            return json.load(f)

    def test_menu_icons_come_from_record_stores_and_the_rest_from_the_table(self):
        doc = self.run_icons()
        self.assertEqual([i['name'] for i in doc['icons']], ['menu-%d' % k for k in range(6)] + ['install-%d' % k for k in range(4)])
        self.assertEqual([i['object_address'] for i in doc['icons']], ['0x%x' % a for a in self.addrs])
        self.assertEqual(doc['icons'][3]['yoffset'], -2)

    def test_layers_paint_in_order_with_y_measured_up_from_the_bottom(self):
        doc = self.run_icons()
        w, h, _, px = png.decode(open(os.path.join(self.dir, doc['icons'][0]['composite']), 'rb').read())
        pix = lambda x, y_down: px[(y_down * w + x) * 4:][:4]
        red, ramp = b'\xff\0\x09\xff', bytes([95, 95, 143, 255])
        # layer 1 sits at y = 1 from the bottom of a 5-row icon, so its rows are image rows 2 and 3; its (1, 0) pixel is clear
        self.assertEqual([pix(1, 3), pix(2, 3), pix(1, 2), pix(2, 2)], [ramp, ramp, ramp, red])
        self.assertEqual(pix(0, 0), red)
        lw, lh, _, lpx = png.decode(open(os.path.join(self.dir, doc['icons'][0]['layers'][1]['file']), 'rb').read())
        self.assertEqual((lw, lh, lpx), (2, 2, b'\xff\xff\0\0\xff\xff\xff\xff'))

    def test_an_icon_the_code_never_uses_is_refused(self):
        with self.assertRaises(AssetError):
            self.run_icons(menu_icons=5)


LOGO_W, LOGO_H = 494, 237


class Ip32Logo(unittest.TestCase):
    def rows(self):
        return [[1 if r + 1 <= x < r + 101 else 0 for x in range(LOGO_W)] for r in range(LOGO_H)]

    def run_logo(self, lead=12, junk=b'\x06\xfd\x70', anchor=True):
        data = b'\0\0' + junk + b'\0' * lead + encode_rle(self.rows())
        data += b'\0' * (-len(data) % 4)
        data += struct.pack('>II', LOGO_W, LOGO_H) if anchor else b'\0' * 8
        seg, _ = assemble(lambda a: [fx.JR_RA, fx.NOP], data)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        r = ip32.Reader(seg)
        ip32.logo(r, self.dir)
        return r.files[0]

    def test_the_logo_decodes_from_the_words_after_it_with_the_twelve_zero_start(self):
        f = self.run_logo()
        w, h, _, px = png.decode(open(os.path.join(self.dir, 'assets/logo.png'), 'rb').read())
        self.assertEqual((w, h), (LOGO_W, LOGO_H))
        want = self.rows()[::-1]                       # the PNG is top row first; the data is bottom row first
        self.assertEqual([[px[(y * w + x) * 2 + 1] // 255 for x in range(w)] for y in (0, 100, 236)], [want[0], want[100], want[236]])
        self.assertEqual(f['details']['encoded_length'], len(encode_rle(self.rows())) + 12)

    def test_extra_zero_bytes_before_the_twelve_are_not_the_image(self):
        a, b = self.run_logo(lead=12), self.run_logo(lead=16)
        self.assertEqual((a['details']['encoded_length'], a['sha256']), (b['details']['encoded_length'], b['sha256']))

    def test_no_width_and_height_words_means_no_logo(self):
        with self.assertRaises(AssetError):
            self.run_logo(anchor=False)


if __name__ == '__main__':
    unittest.main()
