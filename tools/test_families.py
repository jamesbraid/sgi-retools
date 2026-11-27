#!/usr/bin/env python3
"""Tests of the family readings: the block syntax, the byte check and the per-member verification.

Needs no root/ and no pyelftools. Run from the repository root: python3 tools/test_families.py
"""
import io
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _families as fam  # noqa: E402

BLOCK = """binaries: usr/lib/libx.so
members: gl*
match: 8c 19 .. ..  03 20 00 08  00 00 00 00
field: slot = u16be@2
shape: Each stub loads one word into t9, jumps through it and leaves the delay slot empty.
varies: The slot, the low half of the absolute address the word is loaded from.
role: Inferred. Loads a function pointer from the absolute address in the slot into t9 and jumps to it.""".split('\n')

STUB = bytes.fromhex('8c191050 03200008 00000000')


def parsed(**change):
    lines = [ln for ln in BLOCK if not any(ln.startswith(k + ':') for k in change)]
    lines += ['%s: %s' % (k, v) for k, v in change.items() if v is not None]
    return fam.parse(lines)


class FakeSection:
    def __init__(self, addr, offset, data):
        self.fields = {'sh_type': 'SHT_PROGBITS', 'sh_addr': addr, 'sh_offset': offset, 'sh_size': len(data)}

    def __getitem__(self, key):
        return self.fields[key]


class FakeElf:
    """The little of pyelftools' ELFFile that function_bytes reads: one section at 0x1000, file offset 0x40."""
    def __init__(self, text, machine='EM_MIPS'):
        self.header = {'e_machine': machine}
        self.stream = io.BytesIO(b'\0' * 0x40 + text)
        self.sec = FakeSection(0x1000, 0x40, text)

    def get_section_by_name(self, name):
        return self.sec if name == '.text' else None

    def iter_segments(self):
        return iter(())


def rows_for(*specs):
    return [{'binary': 'usr/lib/libx.so', 'name': n, 'address': '0x%x' % a, 'size': sz, 'elf_section': '.text',
             'status': 'located'} for n, a, sz in specs]


class Blocks(unittest.TestCase):
    def test_a_block_is_found_with_its_heading(self):
        lines = ['# Top', '## The stubs', '', '```family'] + BLOCK + ['```', 'after']
        got = fam.blocks(lines)
        self.assertEqual([(i, h, b) for i, h, b in got], [(3, 'The stubs', BLOCK)])

    def test_other_fences_are_skipped_whole(self):
        lines = ['## A', '```c', '# not a heading', '```', '## B', '```family'] + BLOCK + ['```']
        self.assertEqual([(i, h) for i, h, _b in fam.blocks(lines)], [(5, 'B')])


class Parse(unittest.TestCase):
    def test_a_complete_block_parses(self):
        f, problems = parsed()
        self.assertEqual(problems, [])
        self.assertEqual((f.binaries, f.members, f.length()), (['usr/lib/libx.so'], ['gl*'], 12))

    def test_a_continuation_line_extends_its_key(self):
        lines = BLOCK[:-1] + ['role: Inferred. Loads a function pointer', '  from the slot and jumps to it.']
        f, problems = fam.parse(lines)
        self.assertEqual(problems, [])
        self.assertTrue(f.role.endswith('pointer from the slot and jumps to it.'))

    def test_no_pattern_is_no_family(self):
        f, problems = parsed(match=None)
        self.assertIsNone(f)
        self.assertEqual(problems, ['no "match" line'])

    def test_each_prose_key_is_required(self):
        for key in ('shape', 'varies', 'role', 'binaries', 'members'):
            self.assertEqual(parsed(**{key: None})[1], ['no "%s" line' % key], key)

    def test_a_pattern_of_wildcards_is_refused(self):
        _f, problems = parsed(match='.. .. .. .. .. .. .. .. .. .. .. ..')
        self.assertIn('fixes 0 bits', problems[0])

    def test_a_pattern_that_fixes_little_is_refused(self):
        self.assertIn('fixes 8 bits', parsed(match='8c .. .. .. .. .. .. ..')[1][0])

    def test_a_masked_byte_counts_only_its_bits(self):
        self.assertIsNone(parsed(match='08/fc 00 00 00 .. .. .. ..', field='slot = u16be@0 & 0x300')[0])
        self.assertIsNotNone(parsed(match='08/fc 00 00 00 00 00 00 00', field='slot = u16be@0 & 0x300')[0])

    def test_a_pattern_that_leaves_much_open_is_refused(self):
        # 32 of 96 bits open is a third: any function that ends in a nop
        _f, problems = parsed(match='.. .. .. .. 03 20 00 08 00 00 00 00', field='slot = u32be@0')
        self.assertEqual(len(problems), 1)
        self.assertIn('leaves 32 of its 96 bits open', problems[0])

    def test_a_bit_no_field_reads_is_refused(self):
        _f, problems = parsed(match='8c 19 .. ..  03 20 00 08  00 00 00 ..')
        self.assertEqual(problems, ['the pattern leaves 8 bits open that no field reads: name each varying '
                                    'operand with a field'])

    def test_a_field_mask_reads_only_its_bits(self):
        f, problems = parsed(match='8c 19 .. 00 03 20 00 08 00 00 00 00', field='slot = u16be@2 & 0xff00')
        self.assertEqual(problems, [])
        self.assertEqual(fam.covered_bits(f.fields, 12)[2:4], bytes([0xff, 0]))
        low, _p = parsed(match='8c 19 .. .. 03 20 00 08 00 00 00 00', field='slot = u16le@2')
        self.assertEqual(fam.covered_bits(low.fields, 12)[2:4], bytes([0xff, 0xff]))
        _f, problems = parsed(match='8c 19 .. .. 03 20 00 08 00 00 00 00', field='slot = u16be@2 & 0xff')
        self.assertIn('leaves 8 bits open that no field reads', problems[0])

    def test_a_glob_of_wildcards_alone_is_refused(self):
        self.assertIn('"members" has a glob of wildcards alone', parsed(members='*')[1][0])
        self.assertIn('"binaries" has a glob of wildcards alone', parsed(binaries='usr/lib/libx.so, *')[1][0])
        self.assertIsNotNone(parsed(members='gl*, __gl?*')[0])

    def test_a_bad_byte_is_named(self):
        self.assertIn('"8cx"', parsed(match='8cx 19')[1][0])

    def test_a_field_the_varies_text_does_not_name_is_refused(self):
        _f, problems = parsed(varies='The low half of the address.')
        self.assertEqual(problems, ['field "slot" is not named in the varies text, which has to say what it is'])

    def test_a_field_past_the_pattern_is_refused(self):
        self.assertIn('reads past the 12-byte pattern', parsed(field='slot = u32be@10')[1][0])

    def test_an_unknown_key_and_a_stray_line_are_reported(self):
        _f, problems = fam.parse(BLOCK + ['colour: red', 'not a key line'])
        self.assertEqual(len(problems), 2)
        self.assertIn('unknown key "colour"', problems[0])

    def test_the_role_check_has_the_last_word(self):
        _f, problems = fam.parse(BLOCK, lambda text: 'it is filler' if 'Inferred' in text else '')
        self.assertEqual(problems, ['the role is not one the inventory credits: it is filler'])


class Check(unittest.TestCase):
    def setUp(self):
        self.f = parsed()[0]

    def test_a_match_records_its_own_value(self):
        self.assertEqual(self.f.check(STUB), ({'slot': '0x1050'}, ''))
        self.assertEqual(self.f.check(bytes.fromhex('8c191664 03200008 00000000'))[0], {'slot': '0x1664'})

    def test_a_fixed_byte_that_differs_fails(self):
        values, why = self.f.check(bytes.fromhex('8c191050 03200009 00000000'))
        self.assertEqual(values, {})
        self.assertIn('byte 7 is 0x09, the pattern wants 0x08', why)

    def test_a_filled_delay_slot_fails(self):
        self.assertIn('byte 11', self.f.check(bytes.fromhex('8c191050 03200008 00000001'))[1])

    def test_the_wrong_size_fails(self):
        self.assertIn('size 8', self.f.check(STUB[:8])[1])

    def test_signed_little_endian_and_masked_fields(self):
        f, problems = fam.parse(['binaries: b', 'members: m*', 'match: 04/ff .. 0c 00 11 22 33 44',
                                 'field: back = s8be@1', 'field: low = u16le@1', 'field: top = u32be@0 & 0xff00',
                                 'shape: s', 'varies: back low top', 'role: r'])
        self.assertEqual(problems, [])
        self.assertEqual(f.check(bytes.fromhex('04fe0c00 11223344'))[0], {'back': '-2', 'low': '0xcfe', 'top': '0xc00'})


class Verify(unittest.TestCase):
    def setUp(self):
        self.f = parsed()[0]
        text = STUB + bytes.fromhex('8c191664 03200008 00000000') + bytes.fromhex('8c191050 03200008 00000001')
        text += bytes.fromhex('27bdffe0 03e00008 00000000')
        self.imgs = [{'label': 'usr/lib/libx.so', 'copies': ['usr/lib/libx-copy.so'], 'data': b'x'}]
        self.rows = rows_for(('glA', 0x1000, 12), ('glB', 0x100c, 12), ('glC', 0x1018, 12), ('glD', 0x1024, 12),
                             ('other', 0x1000, 12), ('glE', 0x1000, 8))
        self.elf = lambda data: FakeElf(text)

    def run_verify(self, rows=None):
        return fam.verify([self.f], self.imgs, rows or self.rows, self.elf)

    def test_each_candidate_is_checked_on_its_own_bytes(self):
        got = [(r['row']['name'], r['ok'], r['values']) for r in self.run_verify()]
        self.assertEqual(got, [('glA', True, {'slot': '0x1050'}), ('glB', True, {'slot': '0x1664'}),
                               ('glC', False, {}), ('glD', False, {})])

    def test_a_row_outside_the_name_or_size_is_not_a_candidate(self):
        names = {r['row']['name'] for r in self.run_verify()}
        self.assertFalse(names & {'other', 'glE'})

    def test_a_copy_label_is_covered_too(self):
        self.f.binaries = ['usr/lib/libx-copy.so']
        self.assertEqual(len(self.run_verify()), 4)

    def test_a_function_the_image_does_not_hold_fails_with_a_reason(self):
        got = self.run_verify(rows_for(('glA', 0x9000, 12)))
        self.assertEqual([r['ok'] for r in got], [False])
        self.assertIn('does not hold', got[0]['why'])

    def test_a_row_with_no_known_address_fails(self):
        rows = rows_for(('glA', 0x1000, 12))
        rows[0]['_unknown'] = True
        self.assertFalse(self.run_verify(rows)[0]['ok'])

    def test_an_arm_symbol_address_loses_its_thumb_bit(self):
        self.elf = lambda data: FakeElf(STUB, 'EM_ARM')
        got = self.run_verify(rows_for(('glA', 0x1001, 12)))
        self.assertEqual([(r['ok'], r['values']) for r in got], [(True, {'slot': '0x1050'})])

    def test_values_text(self):
        self.assertEqual(fam.values_text({'slot': '0x1050', 'x': '-2'}), 'slot=0x1050;x=-2')


if __name__ == '__main__':
    unittest.main()
