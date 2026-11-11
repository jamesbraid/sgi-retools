#!/usr/bin/env python3
"""Tests of the symbol lookup in facts.py and the branch-likely list in facts.py that do not need root/.

Run from the repository root: python3 tools/test_facts.py
"""
import collections
import os
import struct
import sys
import types
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import facts  # noqa: E402

# the MIPS IV branch-likely set: compare, REGIMM (plain and linking) and coprocessor 0/1/2 branches
MIPS_IV_LIKELY = {'beql', 'bnel', 'blezl', 'bgtzl', 'bltzl', 'bgezl', 'bltzall', 'bgezall',
                  'bc0tl', 'bc0fl', 'bc1tl', 'bc1fl', 'bc2tl', 'bc2fl'}


def image(syms):
    """An Image holding only a symbol table: (address, size, name, section, is_function, source)."""
    img = object.__new__(facts.Image)
    img.flat, img.path, img.kind = False, 'x.o', 'shared-object'
    img.syms = sorted(syms)
    img.byname = collections.defaultdict(list)
    for x in img.syms:
        img.byname[x[2]].append(x)
    img.func_addrs = sorted({x[0] for x in img.syms if x[4]})
    img.section_bounds = lambda sec: None
    return img


def two_got_executable():
    """An o32 big-endian ET_EXEC with two GOTs, each section at its own address.

    Dynamic symbols: 1 alpha, 2 getenv (both undefined functions); gotsym is 1 and local_gotno 2,
    so by position slot 2 of the first GOT is alpha and slot 3 is getenv. The relocations say
    otherwise: slot 2 of the first GOT is getenv, and so is slot 1 of the second GOT. Slot 2 of the
    second GOT has no relocation but holds the same pre-linked word as slot 1.
    """
    got1, got2 = 0x10000, 0x20000
    dynstr = b'\0alpha\0getenv\0'
    sym = lambda n, info, shn: struct.pack('>IIIBBH', n, 0, 0, info, 0, shn)  # noqa: E731
    dynsym = sym(0, 0, 0) + sym(1, 0x12, 0) + sym(7, 0x12, 0)
    dynamic = b''.join(struct.pack('>II', t, v) for t, v in [(3, got1), (0x7000000a, 2), (0x70000013, 1), (0, 0)])
    words1 = [0, 0, 0x0fa00000, 0x0fb00000]
    words2 = [0x1234, 0x0fb00000, 0x0fb00000]
    pack = lambda ws: b''.join(struct.pack('>I', w) for w in ws)  # noqa: E731
    rel = b''.join(struct.pack('>II', a, (2 << 8) | 3) for a in (got1 + 8, got2 + 4))
    shstr = b'\0.dynstr\0.dynsym\0.dynamic\0.got\0.got_2\0.rel.dyn\0.shstrtab\0'
    names = ['.dynstr', '.dynsym', '.dynamic', '.got', '.got_2', '.rel.dyn', '.shstrtab']
    bodies = [dynstr, dynsym, dynamic, pack(words1), pack(words2), rel, shstr]
    # type, flags, address, link, info, entsize
    meta = [(3, 2, 0, 0, 0, 0), (11, 2, 0x4000, 1, 1, 16), (6, 2, 0x5000, 1, 0, 8), (1, 3, got1, 0, 0, 4),
            (1, 3, got2, 0, 0, 4), (9, 2, 0x6000, 2, 0, 8), (3, 0, 0, 0, 0, 0)]
    pos, offs = 52, []
    for b in bodies:
        offs.append(pos)
        pos += len(b)
    pos = (pos + 3) & ~3
    out = b'\x7fELF\x01\x02\x01' + b'\0' * 9 + struct.pack('>HHIIIIIHHHHHH', 2, 8, 1, 0, 0, pos, 0, 52, 0, 0, 40,
                                                                    len(bodies) + 1, len(bodies))
    out += b''.join(bodies) + b'\0' * (pos - 52 - sum(len(b) for b in bodies))
    out += struct.pack('>IIIIIIIIII', *([0] * 10))
    for k, (t, fl, addr, link, info, ent) in enumerate(meta):
        out += struct.pack('>IIIIIIIIII', shstr.index(b'\0' + names[k].encode() + b'\0') + 1, t, fl, addr, offs[k],
                           len(bodies[k]), link, info, 4, ent)
    return out


class MultiGot(unittest.TestCase):
    """A file with several GOTs names a slot from its relocation, not from its position."""

    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'two-got')
            with open(p, 'wb') as f:
                f.write(two_got_executable())
            cls.img = facts.Image(p)

    def info(self, addr):
        return facts.Routine.got_info(types.SimpleNamespace(img=self.img), facts.C(addr))

    def test_the_file_has_two_gots(self):
        self.assertTrue(self.img.gots.multi)

    def test_first_got_slot_follows_its_relocation_not_its_position(self):
        info, word = self.info(0x10008)
        self.assertEqual((info['kind'], info['name'], word), ('global', 'getenv', 0x0fa00000))

    def test_first_got_slot_without_a_relocation_keeps_the_position_rule(self):
        info, _ = self.info(0x1000c)
        self.assertEqual((info['kind'], info['name']), ('global', 'getenv'))

    def test_second_got_slot_is_named_by_its_relocation(self):
        info, _ = self.info(0x20004)
        self.assertEqual((info['kind'], info['name'], info['slot']), ('global', 'getenv', 1))

    def test_second_got_slot_with_the_same_word_is_named_without_one(self):
        info, _ = self.info(0x20008)
        self.assertEqual(info['name'], 'getenv')

    def test_second_got_local_slot_is_its_word(self):
        info, word = self.info(0x20000)
        self.assertEqual((info['kind'], word), ('local', 0x1234))

    def test_address_outside_every_got_is_not_a_slot(self):
        self.assertIsNone(self.info(0x30000))


class BranchLikely(unittest.TestCase):
    def test_every_mips_iv_form_is_known(self):
        self.assertFalse(MIPS_IV_LIKELY - facts.LIKELY)


class AmbiguousSymbol(unittest.TestCase):
    TWO = [(0x100, 0x40, 'helper', '.text', True, 'symtab'), (0x200, 0x80, 'helper', '.text', True, 'symtab')]

    def test_two_routines_are_refused_with_address_and_size(self):
        with self.assertRaises(SystemExit) as c:
            image(self.TWO).find('helper')
        msg = str(c.exception)
        self.assertIn('0x100  size 0x40', msg)
        self.assertIn('0x200  size 0x80', msg)
        self.assertIn('0xADDR --size N', msg)

    def test_address_picks_one(self):
        self.assertEqual(image(self.TWO).find('0x200')[1:3], (0x200, 0x80))

    def test_one_routine_with_aliases_is_not_ambiguous(self):
        syms = [(0x100, 0x40, 'helper', '.text', True, 'symtab'), (0x100, 0, 'helper', '.text', True, 'mdebug')]
        self.assertEqual(image(syms).find('helper')[1], 0x100)


class SectionFromAddress(unittest.TestCase):
    """A name from debug information or the inventory says '.text'; the address decides."""
    SECS = [{'name': '.text', 'address': '0x1000', 'size': 0x100, 'flags': 'AX'},
            {'name': '.MIPS.stubs', 'address': '0x1100', 'size': 0x2ec, 'flags': 'AX'}]

    def img(self, kind='shared-object'):
        img = image([(0x1100, 0x2ec, '_stub', '.text', True, 'inventory'),
                     (0x1000, 0x20, 'real', '.text', True, 'symtab')])
        img.kind, img.sections = kind, self.SECS
        del img.section_bounds
        return img

    def test_stubs_routine_is_read_from_the_stubs_section(self):
        # asked for .text, objdump returns nothing for the run that follows the leading break
        self.assertEqual(self.img().find('_stub')[3], '.MIPS.stubs')

    def test_symbol_table_section_is_kept(self):
        self.assertEqual(self.img().find('real')[3], '.text')

    def test_object_file_keeps_the_given_section(self):
        self.assertEqual(self.img('object').find('_stub')[3], '.text')


class ObjectOffsetSection(unittest.TestCase):
    """In a relocatable object an address is an offset into one section; the object must say which."""
    ONE = [{'name': '.text', 'address': '0x0', 'size': 0x100, 'flags': 'AX'},
           {'name': '.data', 'address': '0x0', 'size': 0x20, 'flags': 'WA'}]
    TWO = ONE + [{'name': '.text.init', 'address': '0x0', 'size': 0x80, 'flags': 'AX'}]

    def obj(self, sections, syms=()):
        img = image(list(syms))
        img.kind, img.sections = 'object', sections
        return img

    def test_offset_without_a_symbol_takes_the_only_code_section(self):
        self.assertEqual(self.obj(self.ONE).find('0x40', 16)[1:4], (0x40, 16, '.text'))

    def test_function_covering_the_offset_names_its_section(self):
        syms = [(0x20, 0x40, 'fn', '.text.init', True, 'symtab')]
        self.assertEqual(self.obj(self.TWO, syms).find('0x40', 16)[1:4], (0x40, 16, '.text.init'))

    def test_offset_in_two_code_sections_with_no_covering_symbol_is_unresolved(self):
        with self.assertRaises(SystemExit) as c:
            self.obj(self.TWO).find('0x40', 16)
        self.assertIn('unresolved', str(c.exception))
        self.assertIn('.text, .text.init', str(c.exception))


class InventoryAddressZero(unittest.TestCase):
    """Offset 0 is a real place in a relocatable object; a row that names no section is not a place."""
    ROWS = ('binary\trole\tabi\telf_section\taddress\tsize\tname\tsource\tcode_sha\trejected\tscope\tstatus\tdoc\tsection\n'
            'usr/cpu/sysgen/IP35boot/pcibr.o\tshared-kernel\tn64\t.text\t0x0\t1188\tfirst_routine\tdwarf\t\t\tin\tundocumented\t\t\n'
            'usr/cpu/sysgen/IP35boot/pcibr.o\tshared-kernel\tn64\t\t0x0\t\tunresolved_name\tdwarf\t\t\tin\tundocumented\t\t\n')

    def test_zero_address_with_a_section_is_named_and_unresolved_row_is_not(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, 'scripts'))
            os.makedirs(os.path.join(td, 'docs', 'inventory'))
            with open(os.path.join(td, 'docs', 'inventory', 'functions.tsv'), 'w') as f:
                f.write(self.ROWS)
            img = image([])
            img.path, img.member, img.kind = 'root/usr/cpu/sysgen/IP35boot/pcibr.o', None, 'object'
            with patch.object(facts, 'find_workspace', lambda: td):
                img.inventory_names(set())
        self.assertEqual(img.syms, [(0, 1188, 'first_routine', '.text', True, 'inventory')])


class RenderTable(unittest.TestCase):
    def test_table_with_a_computed_base_renders(self):
        # a jump table whose base is itself a symbolic value used to raise a TypeError
        r = facts.Render(image([]))
        self.assertEqual(r(('tbl', ('c', 0x1200))), 'table(0x1200)')
        self.assertEqual(r(('tbl', 0x1200)), 'table(0x1200)')
        self.assertEqual(r(('tent', ('in', 'a0'), 4)), 'entry(a0)')


class UnanalysedRoutine(unittest.TestCase):
    def test_empty_routine_has_empty_analysis_state_and_address_facts(self):
        img = image([])
        img.abi, img.isa, img.kind = 'n64', 'mips4', 'object'
        img.gp, img.sections, img.member = None, [], None
        img.disassemble = lambda addr, size, section: []
        r = facts.Routine(img, 'alias', 0x1000, 0, '.text', 'symtab', [])

        fs = r.facts(False)

        self.assertEqual(r.in_states, {})
        self.assertEqual(r.edges, {})
        self.assertEqual(r.tables, [])
        self.assertEqual(fs['routine']['address'], '0x1000')
        self.assertEqual(fs['routine']['size'], 0)
        self.assertEqual(fs['unreached'], [])


if __name__ == '__main__':
    unittest.main()
