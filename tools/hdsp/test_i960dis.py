#!/usr/bin/env python3
"""Tests of tools/hdsp/i960dis.py.

Run: python3 tools/hdsp/test_i960dis.py   (no third-party packages, no vendor binaries)

Words are assembled here from the instruction-format figures of the i960 Rx I/O Microprocessor
Developer's Manual (272736-002, chapter 6 "Instruction Set Reference", the REG, MEM, CTRL and
COBR format diagrams and the opcode tables), so each test checks the decoder against the
published bit layout, not against its own output.
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import i960dis as d  # noqa: E402

R = {n: i for i, n in enumerate(d.REGS)}


def reg(op12, s1, s2, dst, m1=0, m2=0, m3=0, sf1=0, sf2=0):
    # REG format: opcode[31:24], src/dst[23:19], src2[18:14], mode3 13, mode2 12, mode1 11,
    # opcode ext [10:7], sf2 6, sf1 5, src1 [4:0].
    return ((op12 >> 4) << 24 | dst << 19 | s2 << 14 | m3 << 13 | m2 << 12 | m1 << 11 |
            (op12 & 0xf) << 7 | sf2 << 6 | sf1 << 5 | s1)


def mema(op, sd, ab, off, use_base):
    return op << 24 | sd << 19 | ab << 14 | (1 << 13 if use_base else 0) | off


def memb(op, sd, ab, mode, scale=0, idx=0):
    # bit 12 is the top bit of the mode field's low half (every MEMB mode has it set)
    return op << 24 | sd << 19 | ab << 14 | mode << 10 | scale << 7 | idx


def ctrl(op, disp):
    return op << 24 | (disp & 0x00fffffc)


def cobr(op, s1, s2, disp, m1=0, t=0, sf2=0):
    return op << 24 | s1 << 19 | s2 << 14 | m1 << 13 | (disp & 0x1ffc) | t << 1 | sf2


def dec(words, addr=0x1000):
    buf = b''.join(struct.pack('<I', w) for w in words)
    return d.decode(buf, 0, addr)


class Reg(unittest.TestCase):
    def test_three_operand(self):
        i = dec([reg(0x590, R['g0'], R['g1'], R['g2'])])
        self.assertEqual((i.mnem, i.text.split(None, 1)[1], i.size), ('addo', 'g0,g1,g2', 4))

    def test_literals_and_sfr(self):
        self.assertEqual(dec([reg(0x590, 5, R['g1'], R['g2'], m1=1)]).text.split(None, 1)[1], '5,g1,g2')
        self.assertEqual(dec([reg(0x590, R['g0'], 31, R['g2'], m2=1)]).text.split(None, 1)[1], 'g0,31,g2')
        self.assertEqual(dec([reg(0x5cc, 3, 0, 4, sf1=1)]).text.split(None, 1)[1], 'sf3,r4')

    def test_move_widths(self):
        for op, name in [(0x5cc, 'mov'), (0x5dc, 'movl'), (0x5ec, 'movt'), (0x5fc, 'movq')]:
            self.assertEqual(dec([reg(op, R['g0'], 0, R['g4'])]).text, '%-8sg0,g4' % name)

    def test_two_source_compares_have_no_destination(self):
        self.assertEqual(dec([reg(0x5a0, R['g0'], R['g1'], 0)]).text, 'cmpo    g0,g1')
        self.assertEqual(dec([reg(0x5a1, 1, R['g1'], 0, m1=1)]).text, 'cmpi    1,g1')

    def test_src_dst_third_operand(self):
        # modify and extract read and write the third operand; mode3 must be clear
        self.assertEqual(dec([reg(0x650, R['g0'], R['g1'], R['g2'])]).text, 'modify  g0,g1,g2')
        self.assertFalse(dec([reg(0x650, R['g0'], R['g1'], R['g2'], m3=1)]).known)

    def test_no_operand_and_one_operand(self):
        self.assertEqual(dec([reg(0x66d, 0, 0, 0)]).text, 'flushreg')
        self.assertEqual(dec([reg(0x66f, 0, 0, 0)]).text, 'syncf')
        self.assertEqual(dec([reg(0x660, R['g3'], 0, 0)]).text, 'calls   g3')
        self.assertEqual(dec([reg(0x673, 0, 0, R['g1'])]).text, 'ldtime  g1')

    def test_conditional_add_and_select(self):
        self.assertEqual(dec([reg(0x7a4, 1, 2, 3)]).mnem, 'sele')
        self.assertEqual(dec([reg(0x791, 1, 2, 3)]).mnem, 'addig')
        self.assertEqual(dec([reg(0x7f3, 1, 2, 3)]).mnem, 'subio')
        self.assertEqual(dec([reg(0x780, 1, 2, 3)]).mnem, 'addono')

    def test_unassigned_opcode(self):
        i = dec([reg(0x5bf, 1, 2, 3)])
        self.assertFalse(i.known)
        self.assertTrue(i.text.startswith('.word'))

    def test_table_round_trips_mnemonic_and_operand_count(self):
        # every table entry decodes back to itself with as many operands as its signature has
        for key, (name, sig) in d.REG.items():
            i = dec([reg(key, 1, 2, 3, m3=0)])
            self.assertEqual(i.mnem, name, hex(key))
            self.assertEqual(i.fmt, 'REG')
            ops = i.text.split(None, 1)[1].split(',') if ' ' in i.text.strip() else []
            self.assertEqual(len(ops), len(sig.lstrip('F')), '%s %s' % (name, i.text))

    def test_xnor_has_three_operands(self):
        self.assertEqual(dec([reg(0x589, R['g0'], R['g1'], R['g2'])]).text, 'xnor    g0,g1,g2')

    def test_source_only_third_operand_may_be_a_literal(self):
        self.assertEqual(dec([reg(0x617, R['g1'], R['g2'], 7, m3=1)]).text, 'fill    g1,g2,7')
        for op in (0x603, 0x604, 0x605, 0x630):
            self.assertTrue(dec([reg(op, 1, 2, 9, m3=1)]).known, hex(op))
        self.assertFalse(dec([reg(0x650, 1, 2, 9, m3=1)]).known)    # modify: src/dst, no literal

    def test_fp_literals(self):
        self.assertEqual(dec([reg(0x78f, 16, 22, R['g2'], m1=1, m2=1)]).text, 'addr    0.0,1.0,g2')
        self.assertEqual(dec([reg(0x78f, 2, 1, R['g2'], m1=1, m2=1)]).text, 'addr    fp2,fp1,g2')


class Mem(unittest.TestCase):
    def test_mema_offset(self):
        i = dec([mema(0x90, R['g2'], 0, 0x10, False)])
        self.assertEqual(i.text, 'ld      0x10,g2')

    def test_mema_base_plus_offset(self):
        self.assertEqual(dec([mema(0x92, R['g2'], R['fp'], 0x1b0, True)]).text, 'st      g2,0x1b0(fp)')
        self.assertEqual(dec([mema(0x8c, R['sp'], R['sp'], 0x190, True)]).text, 'lda     0x190(sp),sp')

    def test_memb_abase(self):
        i = dec([memb(0x90, R['g1'], R['g0'], 0b0100)])
        self.assertEqual((i.text, i.size), ('ld      (g0),g1', 4))

    def test_memb_indexed(self):
        i = dec([memb(0x90, R['g1'], R['g0'], 0b0111, scale=2, idx=R['g3'])])
        self.assertEqual(i.text, 'ld      (g0)[g3*4],g1')
        i = dec([memb(0x90, R['g1'], R['g0'], 0b0111, scale=0, idx=R['g3'])])
        self.assertEqual(i.text, 'ld      (g0)[g3],g1')

    def test_memb_displacement_forms_take_a_second_word(self):
        i = dec([memb(0x8c, R['g1'], 0, 0b1100), 0x12345678])
        self.assertEqual((i.text, i.size, i.disp_at), ('lda     0x12345678,g1', 8, 0x1004))
        i = dec([memb(0x90, R['g1'], R['g0'], 0b1101), 0x40])
        self.assertEqual(i.text, 'ld      0x40(g0),g1')
        i = dec([memb(0x90, R['g1'], 0, 0b1110, scale=3, idx=R['g4']), 0x40])
        self.assertEqual(i.text, 'ld      0x40[g4*8],g1')
        i = dec([memb(0x90, R['g1'], R['g0'], 0b1111, scale=1, idx=R['g4']), 0x40])
        self.assertEqual(i.text, 'ld      0x40(g0)[g4*2],g1')

    def test_memb_ip_relative(self):
        # (IP) + displacement + 8, IP being the address of the instruction
        i = dec([memb(0x90, R['g1'], 0, 0b0101), 0x100], addr=0x2000)
        self.assertEqual(i.text, 'ld      0x2108,g1')

    def test_memb_reserved_modes_and_scale(self):
        self.assertFalse(dec([memb(0x90, 1, 0, 0b0110)]).known)
        self.assertFalse(dec([memb(0x90, 1, 0, 0b0111, scale=5)]).known)

    def test_branch_and_call_through_memory(self):
        i = dec([memb(0x86, 0, 0, 0b1100), 0x4000])
        self.assertEqual((i.text, i.target, i.flow), ('callx   0x4000', 0x4000, 'call'))
        self.assertEqual(dec([memb(0x84, 0, R['g4'], 0b0100)]).text, 'bx      (g4)')

    def test_load_store_widths(self):
        names = {0x80: 'ldob', 0x82: 'stob', 0x88: 'ldos', 0x8a: 'stos', 0x90: 'ld', 0x92: 'st', 0x98: 'ldl',
                 0x9a: 'stl', 0xa0: 'ldt', 0xa2: 'stt', 0xb0: 'ldq', 0xb2: 'stq', 0xc0: 'ldib', 0xc2: 'stib',
                 0xc8: 'ldis', 0xca: 'stis'}
        for op, n in names.items():
            self.assertEqual(dec([mema(op, 4, 5, 8, True)]).mnem, n)

    def test_unassigned_mem_opcode(self):
        self.assertFalse(dec([mema(0xd0, 1, 2, 3, True)]).known)


class Ctrl(unittest.TestCase):
    def test_forward_and_backward_displacement(self):
        self.assertEqual(dec([ctrl(0x08, 0x100)], addr=0x1000).text, 'b       0x1100')
        self.assertEqual(dec([ctrl(0x09, -0x20)], addr=0x1000).text, 'call    0xfe0')
        self.assertEqual(dec([ctrl(0x0b, 0x8)], addr=0x1000).text, 'bal     0x1008')

    def test_ret_and_condition_codes(self):
        self.assertEqual(dec([ctrl(0x0a, 0)]).text, 'ret')
        for k, cc in enumerate(['no', 'g', 'e', 'ge', 'l', 'ne', 'le', 'o']):
            self.assertEqual(dec([ctrl(0x10 + k, 4)], addr=0).mnem, 'b' + cc)
            self.assertEqual(dec([ctrl(0x18 + k, 4)], addr=0).mnem, 'fault' + cc)

    def test_prediction_bit(self):
        self.assertEqual(dec([ctrl(0x15, 8) | 2], addr=0).text, 'bne.t   0x8')

    def test_24_bit_displacement_sign_extension(self):
        self.assertEqual(dec([ctrl(0x08, -0x800000)], addr=0x1000000).text, 'b       0x800000')

    def test_fault_takes_no_operand(self):
        self.assertEqual(dec([ctrl(0x1a, 0x40)], addr=0x1000).text, 'faulte')
        self.assertEqual(dec([ctrl(0x1f, 0)], addr=0).text, 'faulto')

    def test_flow_kinds(self):
        self.assertEqual(dec([ctrl(0x09, 0)]).flow, 'call')
        self.assertEqual(dec([ctrl(0x0a, 0)]).flow, 'ret')
        self.assertEqual(dec([ctrl(0x12, 0)]).flow, 'cond')

    def test_reserved_ctrl_opcodes(self):
        self.assertFalse(dec([ctrl(0x0c, 0)]).known)
        self.assertFalse(dec([ctrl(0x01, 0)]).known)


class Cobr(unittest.TestCase):
    def test_register_form(self):
        self.assertEqual(dec([cobr(0x32, R['g0'], R['g1'], 0x40)], addr=0x1000).text,
                         'cmpobe  g0,g1,0x1040')

    def test_literal_and_backward(self):
        self.assertEqual(dec([cobr(0x3c, 7, R['r4'], -0x10, m1=1)], addr=0x1000).text,
                         'cmpibl  7,r4,0xff0')

    def test_bit_branches(self):
        self.assertEqual(dec([cobr(0x30, 3, R['g0'], 8, m1=1)], addr=0).text, 'bbc     3,g0,0x8')
        self.assertEqual(dec([cobr(0x37, R['g1'], R['g0'], 8)], addr=0).text, 'bbs     g1,g0,0x8')

    def test_sfr_src2_and_prediction(self):
        self.assertEqual(dec([cobr(0x35, R['g0'], 2, 4, t=1, sf2=1)], addr=0).text, 'cmpobne.t g0,sf2,0x4')

    def test_every_compare_branch(self):
        names = ['cmpobg', 'cmpobe', 'cmpobge', 'cmpobl', 'cmpobne', 'cmpoble']
        for k, n in enumerate(names):
            self.assertEqual(dec([cobr(0x31 + k, 1, 2, 0)]).mnem, n)
        ib = ['cmpibno', 'cmpibg', 'cmpibe', 'cmpibge', 'cmpibl', 'cmpibne', 'cmpible', 'cmpibo']
        for k, n in enumerate(ib):
            self.assertEqual(dec([cobr(0x38 + k, 1, 2, 0)]).mnem, n)

    def test_test_instructions(self):
        self.assertEqual(dec([0x25 << 24 | R['g5'] << 19]).text, 'testne  g5')

    def test_reserved(self):
        self.assertFalse(dec([0x28 << 24 | 1 << 19]).known)
        self.assertFalse(dec([0x40 << 24 | 1 << 19]).known)


class Data(unittest.TestCase):
    def test_zero_and_ascii_are_data_not_unknown(self):
        self.assertTrue(dec([0]).known)
        i = d.decode(b'@abc', 0, 0)
        self.assertTrue(i.known)
        self.assertEqual(i.fmt, 'str')

    def test_truncated_buffer(self):
        i = d.decode(b'\x01\x02', 0, 0)
        self.assertFalse(i.known)
        self.assertEqual(i.size, 2)
        i = d.decode(struct.pack('<I', memb(0x8c, 1, 0, 0b1100)), 0, 0)
        self.assertFalse(i.known)

    def test_no_word_raises(self):
        # a structured sweep over the opcode byte and the low fields never raises
        for op in range(256):
            for low in (0, 0x1234, 0xffff, 0x3040, 0xffffff):
                d.decode(struct.pack('<II', op << 24 | low, 0x1000), 0, 0)

    def test_jump_table_words_are_recognised_by_the_stream(self):
        buf = struct.pack('<IIII', 0x0000000c, 0x00000004, 0x00000008, 0x0000000c)
        out = list(d.disassemble(buf, 0))
        self.assertTrue(all(i.known and i.fmt == 'jt' for i in out))


def make_coff():
    """A small i960 COFF object: .text with two calls, one relocation, two function symbols."""
    text = struct.pack('<IIII', ctrl(0x09, 0x10), ctrl(0x0a, 0), 0x8c200000 | 0, 0)
    name = lambda s: s.encode().ljust(8, b'\0')
    syms = b''
    for nm, val, scn, cls in [('_main', 0, 1, 2), ('_ext', 0, 0, 2)]:
        syms += name(nm) + struct.pack('<IhHIBBH', val, scn, 0xc016, 0x40, cls, 0, 0)
    strtab = struct.pack('<I', 4)
    scn_hdr_off = 20
    text_off = scn_hdr_off + 44
    reloc_off = text_off + len(text)
    reloc = struct.pack('<IIH', 0, 1, 17) + b'\0\0'
    symptr = reloc_off + len(reloc)
    hdr = struct.pack('<HHIIIHH', 0x160, 1, 0, symptr, 2, 0, 0)
    sh = name('.text') + struct.pack('<IIIIIIHHII', 0, 0, len(text), text_off, reloc_off, 0, 1, 0, 0x20, 16)
    return hdr + sh + text + reloc + syms + strtab


class Coff(unittest.TestCase):
    def test_reader_and_symbols(self):
        c = d.Coff(make_coff())
        s = c.section('.text')
        self.assertEqual((s['size'], s['nreloc']), (16, 1))
        self.assertEqual([x['name'] for x in c.symbols], ['_main', '_ext'])
        self.assertEqual(d.symbol_map(c, s), {0: '_main'})
        self.assertEqual(c.relocs(s), [(0, 1, 17)])
        self.assertEqual(c.sym_by_index(1)['name'], '_ext')

    def test_wrapper_offset(self):
        c = d.Coff(b'\xaa' * 7 + make_coff(), 7)
        self.assertEqual(c.section('.text')['size'], 16)

    def test_long_names_come_from_the_string_table(self):
        blob = bytearray(make_coff())
        c = d.Coff(bytes(blob))
        # rewrite symbol 0 to a string-table name: zero word, then the offset
        symptr = c.symptr
        blob[symptr:symptr + 8] = struct.pack('<II', 0, 4)
        blob += b'long_function_name\0'
        blob[len(blob) - 19 - 4:len(blob) - 19] = struct.pack('<I', 4 + 19)
        c = d.Coff(bytes(blob))
        self.assertEqual(c.symbols[0]['name'], 'long_function_name')

    def test_magic_0x161_is_accepted(self):
        blob = bytearray(make_coff())
        blob[0:2] = struct.pack('<H', 0x161)
        self.assertEqual(d.Coff(bytes(blob)).section('.text')['size'], 16)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            d.Coff(b'\0' * 64)

    def test_listing_names_relocation_and_label(self):
        c = d.Coff(make_coff())
        s = c.section('.text')
        buf = c.section_bytes(s)
        syms = d.symbol_map(c, s)
        txt = d.format_listing(d.disassemble(buf, 0), syms, c.relocs(s), c)
        self.assertIn('_main:', txt)
        self.assertIn('reloc -> _ext', txt)

    def test_check_counts_unknown(self):
        buf = struct.pack('<II', ctrl(0x0a, 0), 0xfe000000 | 1)
        n, fmts, unk = d.check(d.disassemble(buf, 0))
        self.assertEqual((n, len(unk)), (2, 1))


if __name__ == '__main__':
    unittest.main()
