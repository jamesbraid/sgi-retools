#!/usr/bin/env python3
"""Tests of tools/envscan.py on small hand-assembled relocatable objects.

Run: uv run --with capstone --with pyelftools python -I tools/test_envscan.py
(skipped when Capstone or pyelftools is missing). Each object holds a few routines that call an
undefined `getenv` through a relocated `jal`, with the variable name in `.rodata`.
"""
import os
import struct
import sys
import tempfile
import unittest
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import capstone  # noqa: F401
    import elftools  # noqa: F401
except ImportError:
    print('test_envscan: needs capstone and pyelftools; skipped')
    sys.exit(0)

import envscan  # noqa: E402

warnings.simplefilter('ignore', ResourceWarning)    # facts.Image reads its file without closing it

A0, A1, V0, RA, T9, AT, GP, SP = 4, 5, 2, 31, 25, 1, 28, 29
NOP = 0
R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16 = 4, 5, 6


def I(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)


def lui(rt, v):
    return I(0x0f, 0, rt, v)


def addiu(rt, rs, v):
    return I(0x09, rs, rt, v)


def jal():
    return 3 << 26


def jr(rs):
    return (rs << 21) | 8


def addu(rd, rs, rt):
    return (rs << 21) | (rt << 16) | (rd << 11) | 0x21


def move(rd, rs):
    return addu(rd, rs, 0)


def relocatable(routines, rodata, relocs):
    """An ET_REL o32 big-endian object.

    routines: [(name, words)] laid out in order in .text; relocs: [(routine, word index, type,
    symbol name)] with symbol names from the routines, the undefined externals and `.rodata`.
    """
    text, starts = b'', {}
    for name, words in routines:
        starts[name] = len(text)
        text += b''.join(struct.pack('>I', w) for w in words)
    externs = sorted({r[3] for r in relocs} - {n for n, _ in routines} - {'.rodata'})
    names = [n for n, _ in routines] + externs
    strtab, offs = b'\0', {}
    for n in names:
        offs[n] = len(strtab)
        strtab += n.encode() + b'\0'
    sym = lambda n, v, sz, info, shn: struct.pack('>IIIBBH', n, v, sz, info, 0, shn)  # noqa: E731
    symtab = sym(0, 0, 0, 0, 0) + sym(0, 0, 0, 3, 2)                 # null, .rodata section symbol (1)
    index = {'.rodata': 1}
    for n, w in routines:
        index[n] = len(symtab) // 16
        symtab += sym(offs[n], starts[n], 4 * len(dict(routines)[n]), 0x12, 1)
    for n in externs:
        index[n] = len(symtab) // 16
        symtab += sym(offs[n], 0, 0, 0x12, 0)                        # undefined global function
    rel = b''.join(struct.pack('>II', starts[r] + 4 * k, (index[s] << 8) | t) for r, k, t, s in relocs)
    shstr = b'\0.text\0.rodata\0.rel.text\0.symtab\0.strtab\0.shstrtab\0'

    def off(name):
        return shstr.index(b'\0' + name.encode() + b'\0') + 1
    bodies = [b'', text, rodata, rel, symtab, strtab, shstr]
    nm = [0, off('.text'), off('.rodata'), off('.rel.text'), off('.symtab'), off('.strtab'), off('.shstrtab')]
    types = [0, 1, 1, 9, 2, 3, 3]
    flags = [0, 6, 2, 0, 0, 0, 0]
    links = [0, 0, 0, 4, 5, 0, 0]
    infos = [0, 0, 0, 1, 2, 0, 0]
    ents = [0, 0, 0, 8, 16, 0, 0]
    pos, where = 52, []
    for b in bodies:
        where.append(pos)
        pos += len(b)
    pos = (pos + 3) & ~3
    hdr = b'\x7fELF\x01\x02\x01' + b'\0' * 9 + struct.pack('>HHIIIIIHHHHHH', 1, 8, 1, 0, 0, pos, 0x20, 52, 0, 0, 40,
                                                                 len(bodies), 6)
    out = hdr + b''.join(bodies) + b'\0' * (pos - 52 - sum(len(b) for b in bodies))
    for k, b in enumerate(bodies):
        out += struct.pack('>IIIIIIIIII', nm[k], types[k], flags[k], 0, where[k] if k else 0, len(b), links[k],
                           infos[k], 4, ents[k])
    return out


def call_getenv_const(string_offset):
    """A routine that calls getenv with the .rodata string at string_offset."""
    return [lui(A0, 0), jal(), addiu(A0, A0, string_offset), jr(RA), NOP], \
        [(1, R_MIPS_26, 'getenv'), (0, R_MIPS_HI16, '.rodata'), (2, R_MIPS_LO16, '.rodata')]


def run(data, *argv):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'obj.o')
        with open(p, 'wb') as f:
            f.write(data)
        out = os.path.join(d, 'out.tsv')
        envscan.main([p, '--root', d, '--out', out] + list(argv))
        with open(out) as f:
            lines = f.read().splitlines()
    cols = lines[0].split('\t')
    return [dict(zip(cols, ln.split('\t'))) for ln in lines[1:]]


class CallSites(unittest.TestCase):
    RODATA = b'\0\0\0\0HOME_VAR\0OTHER_VAR\0'

    def test_getenv_with_a_constant_name(self):
        words, rel = call_getenv_const(4)
        rows = run(relocatable([('reader', words)], self.RODATA, [('reader',) + r for r in rel]))
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['function'], rows[0]['callee'], rows[0]['string'], rows[0]['kind']),
                         ('reader', 'getenv', 'HOME_VAR', 'env'))
        self.assertEqual(rows[0]['call_site'], '0x4')
        self.assertEqual(rows[0]['install_path'], 'obj.o')
        self.assertEqual(len(rows[0]['sha256']), 64)

    def test_a_routine_that_does_not_call_it_has_no_row(self):
        words = [addiu(V0, 0, 1), jr(RA), NOP]
        rows = run(relocatable([('quiet', words)], self.RODATA, []))
        self.assertEqual(rows, [])

    def test_name_not_a_constant_is_unresolved(self):
        # the argument is a value the routine loads from its own argument's memory
        words = [I(0x23, A0, A0, 8), jal(), NOP, jr(RA), NOP]
        rows = run(relocatable([('indirect', words)], self.RODATA, [('indirect', 1, R_MIPS_26, 'getenv')]))
        self.assertEqual([r['string'] for r in rows], ['?'])

    def test_wrapper_and_its_caller(self):
        wrap = [jal(), NOP, jr(RA), NOP]          # getenv(a0) with the name passed straight through
        words, rel = call_getenv_const(0)
        user = [lui(A0, 0), jal(), addiu(A0, A0, 4), jr(RA), NOP]
        relocs = [('wrap', 0, R_MIPS_26, 'getenv'), ('user', 1, R_MIPS_26, 'wrap'),
                  ('user', 0, R_MIPS_HI16, '.rodata'), ('user', 2, R_MIPS_LO16, '.rodata')]
        data = relocatable([('wrap', wrap), ('user', user)], self.RODATA, relocs)
        rows = {(r['function'], r['callee']): r for r in run(data)}
        self.assertEqual(rows[('wrap', 'getenv')]['string'], '(a0 of wrap)')
        self.assertEqual(rows[('user', 'wrap')]['string'], 'HOME_VAR')
        self.assertEqual(rows[('user', 'wrap')]['kind'], 'wrapper')

    def test_no_auto_wrappers_leaves_the_callers_out(self):
        wrap = [jal(), NOP, jr(RA), NOP]
        user = [lui(A0, 0), jal(), addiu(A0, A0, 4), jr(RA), NOP]
        relocs = [('wrap', 0, R_MIPS_26, 'getenv'), ('user', 1, R_MIPS_26, 'wrap'),
                  ('user', 0, R_MIPS_HI16, '.rodata'), ('user', 2, R_MIPS_LO16, '.rodata')]
        data = relocatable([('wrap', wrap), ('user', user)], self.RODATA, relocs)
        self.assertEqual([r['function'] for r in run(data, '--no-auto-wrappers')], ['wrap'])

    def test_a_named_wrapper_with_its_argument_index(self):
        user = [lui(A1, 0), jal(), addiu(A1, A1, 4), jr(RA), NOP]
        relocs = [('user', 1, R_MIPS_26, 'lookup'), ('user', 0, R_MIPS_HI16, '.rodata'),
                  ('user', 2, R_MIPS_LO16, '.rodata')]
        rows = run(relocatable([('user', user)], self.RODATA, relocs), '--wrapper', 'lookup:1')
        self.assertEqual([(r['callee'], r['string']) for r in rows], [('lookup', 'HOME_VAR')])

    def test_string_match_lists_a_name_no_call_reads(self):
        words, rel = call_getenv_const(4)
        data = relocatable([('reader', words)], self.RODATA, [('reader',) + r for r in rel])
        rows = run(data, '--string-match', r'[A-Z]+_VAR')
        strings = {r['string']: r for r in rows if r['kind'] == 'string'}
        self.assertEqual(list(strings), ['OTHER_VAR'])
        self.assertEqual(strings['OTHER_VAR']['callee'], '(string)')


class Prologue(unittest.TestCase):
    def test_gp_from_the_routine_address(self):
        # lui at,0x11a; addiu sp,sp,-64; addiu at,at,-0x6064; sd gp; addu gp,t9,at
        words = [lui(AT, 0x11a), addiu(SP, SP, -64), addiu(AT, AT, -0x6064), I(0x3f, SP, GP, 0), addu(GP, T9, AT)]
        self.assertEqual(envscan.cpload_gp(words, 0x10af2f90), (0x10af2f90 + 0x11a0000 - 0x6064) & 0xffffffff)

    def test_no_prologue_no_gp(self):
        self.assertIsNone(envscan.cpload_gp([addiu(V0, 0, 1), jr(RA), NOP], 0x1000))

    def test_text_of_rejects_unprintable_and_unterminated(self):
        self.assertEqual(envscan.text_of(b'DL_X\0junk'), 'DL_X')
        self.assertIsNone(envscan.text_of(b'DL_X'))
        self.assertIsNone(envscan.text_of(b'\x01X\0'))
        self.assertIsNone(envscan.text_of(b'\0'))


if __name__ == '__main__':
    unittest.main()
