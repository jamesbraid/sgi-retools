#!/usr/bin/env python3
"""Tests of the symbol lookup in facts.py and the branch-likely list in check_claims.py that do not need root/.

Run from the repository root: python3 scripts/test_facts.py
"""
import collections
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_claims  # noqa: E402
import facts  # noqa: E402

# the MIPS IV branch-likely set: compare, REGIMM (plain and linking) and coprocessor 0/1/2 branches
MIPS_IV_LIKELY = {'beql', 'bnel', 'blezl', 'bgtzl', 'bltzl', 'bgezl', 'bltzall', 'bgezall',
                  'bc0tl', 'bc0fl', 'bc1tl', 'bc1fl', 'bc2tl', 'bc2fl'}


def image(syms):
    """An Image holding only a symbol table: (address, size, name, section, is_function, source)."""
    img = object.__new__(facts.Image)
    img.flat, img.path = False, 'x.o'
    img.syms = sorted(syms)
    img.byname = collections.defaultdict(list)
    for x in img.syms:
        img.byname[x[2]].append(x)
    img.func_addrs = sorted({x[0] for x in img.syms if x[4]})
    img.section_bounds = lambda sec: None
    return img


class BranchLikely(unittest.TestCase):
    def test_every_mips_iv_form_is_known(self):
        self.assertFalse(MIPS_IV_LIKELY - facts.LIKELY)
        self.assertFalse(MIPS_IV_LIKELY - check_claims.LIKELY_MN)

    def test_claim_text_recognises_the_regimm_forms(self):
        for mn in ('bltzl', 'bgezl', 'bltzall', 'bgezall'):
            self.assertRegex('uses `%s zero` here' % mn, check_claims.LIKELY_RE)

    def test_always_taken_call_counts_as_likely(self):
        self.assertIn('bgezall', check_claims.canon('bgezall zero,0x40'))


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
            with patch.object(facts, 'HERE', os.path.join(td, 'scripts')):
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
