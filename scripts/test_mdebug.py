#!/usr/bin/env python3
"""Tests of the .mdebug reader in mdebug.py against a hand-built object, plus counts on a real library when root/ has one.

The synthetic object is a big-endian ELF32 file holding one source file with a struct, an enum, a
typedef, bit fields, an array, a pointer chain long enough to need a continued type record, a procedure
with a parameter, a local and a label, packed line numbers and one external symbol. Every number below
is chosen to exercise one piece of the format (see include/coff/sym.h and symconst.h for the layout).

Run from the repository root: python3 scripts/test_mdebug.py
"""
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mdebug  # noqa: E402

NIL = 0xfffff


def tir(bt, tq=(), bitfield=False, cont=False):
    """A type information record: bit field flag, continued flag, basic type, six qualifiers."""
    tq = list(tq) + [0] * (6 - len(tq))
    w = (int(bitfield) << 31) | (int(cont) << 30) | (bt << 24)
    w |= (tq[4] << 20) | (tq[5] << 16) | (tq[0] << 12) | (tq[1] << 8) | (tq[2] << 4) | tq[3]
    return w


def rndx(rfd, index):
    return (rfd << 20) | index


def sym(iss, value, st, sc, index):
    return struct.pack('>iII', iss, value, (st << 26) | (sc << 21) | index)


class Strings:
    def __init__(self):
        self.buf = b'\0'

    def add(self, s):
        at = len(self.buf)
        self.buf += s.encode() + b'\0'
        return at


def build():
    ss = Strings()
    n = {k: ss.add(k) for k in ('t.c', 'pt', 'x', 'y', 'color', 'RED', 'GREEN', 'intp', 'f', 'a', 'b', 'L1',
                                'flags', 'bits', 'arr', 'holder', 'next', 'deep', 'td')}
    ext = Strings()
    ext_name = ext.add('ext_fn')

    aux = [
        tir(mdebug.btInt),                                              # 0  int
        tir(mdebug.btInt, [mdebug.tqPtr]),                              # 1  int *
        tir(mdebug.btStruct), rndx(0, 1),                               # 2  struct pt (symbol 1)
        tir(mdebug.btInt, [mdebug.tqArray]), rndx(0, 0), 0, 3, 128,     # 4  int[4]: index type aux 0, 0..3
        tir(mdebug.btUInt, bitfield=True), 3,                           # 9  unsigned : 3
        15,                                                             # 11 isymMac of the procedure
        tir(mdebug.btInt, [mdebug.tqProc]),                             # 12 function returning int
        tir(mdebug.btTypedef), rndx(0, 9),                              # 13 intp (symbol 9)
        tir(mdebug.btIndirect), rndx(0, 1),                             # 15 -> the type at aux 1
        tir(mdebug.btInt, [1, 1, 1, 1, 1, 1], cont=True),               # 17 six pointers, continued
        tir(mdebug.btNil, [1]),                                         # 18 and one more
    ]
    S = [
        (0, 'File', sym(n['t.c'], 0x1000, mdebug.stFile, mdebug.scText, 25)),
        (1, 'pt', sym(n['pt'], 8, mdebug.stStruct, mdebug.scInfo, 5)),
        (2, 'x', sym(n['x'], 0, mdebug.stMember, mdebug.scNil, 0)),
        (3, 'y', sym(n['y'], 32, mdebug.stMember, mdebug.scNil, 0)),
        (4, 'end', sym(0, 0, mdebug.stEnd, mdebug.scInfo, 1)),
        (5, 'color', sym(n['color'], 4, mdebug.stEnum, mdebug.scInfo, 9)),
        (6, 'RED', sym(n['RED'], 0, mdebug.stMember, mdebug.scNil, NIL)),
        (7, 'GREEN', sym(n['GREEN'], 1, mdebug.stMember, mdebug.scNil, NIL)),
        (8, 'end', sym(0, 0, mdebug.stEnd, mdebug.scInfo, 5)),
        (9, 'intp', sym(n['intp'], 0, mdebug.stTypedef, mdebug.scNil, 1)),
        (10, 'f', sym(n['f'], 0x1000, mdebug.stProc, mdebug.scText, 11)),
        (11, 'a', sym(n['a'], 0, mdebug.stParam, mdebug.scAbs, 2)),
        (12, 'b', sym(n['b'], (-4) & 0xffffffff, mdebug.stLocal, mdebug.scAbs, 0)),
        (13, 'L1', sym(n['L1'], 0x1008, mdebug.stLabel, mdebug.scText, 0)),
        (14, 'end', sym(n['f'], 0x20, mdebug.stEnd, mdebug.scText, 10)),
        (15, 'flags', sym(n['flags'], 20, mdebug.stStruct, mdebug.scInfo, 19)),
        (16, 'bits', sym(n['bits'], 0, mdebug.stMember, mdebug.scBits, 9)),
        (17, 'arr', sym(n['arr'], 32, mdebug.stMember, mdebug.scNil, 4)),
        (18, 'end', sym(0, 0, mdebug.stEnd, mdebug.scInfo, 15)),
        (19, 'holder', sym(n['holder'], 16, mdebug.stStruct, mdebug.scInfo, 24)),
        (20, 'next', sym(n['next'], 0, mdebug.stMember, mdebug.scNil, 2)),
        (21, 'deep', sym(n['deep'], 64, mdebug.stMember, mdebug.scNil, 17)),
        (22, 'td', sym(n['td'], 96, mdebug.stMember, mdebug.scNil, 13)),
        (23, 'end', sym(0, 0, mdebug.stEnd, mdebug.scInfo, 19)),
        (24, 'end', sym(0, 0, mdebug.stEnd, mdebug.scText, 0)),
    ]
    local = b''.join(x[2] for x in S)
    # Packed lines for procedure f at 0x1000, first line 10: (delta, count) with count+1 instructions.
    # 10 x2 | 12 x1 | 11 x3 | 311 x1 (a 16-bit delta)
    # each byte is delta<<4 | (count-1); delta -8 escapes to a signed 16-bit delta in the next two bytes
    lines = bytes([(0 << 4) | 1, (2 << 4) | 0, ((-1 & 15) << 4) | 2, 0x80, 0x01, 0x2c])
    auxb = b''.join(struct.pack('>I', w) for w in aux)
    pdr = struct.pack('>I i i I i i I i i h h i i I', 0x1000, 10, 0, 0, 0, 0, 0, 0, 32, 29, 31, 10, 13, 0)
    pdr += b'\0' * (52 - len(pdr))
    extsym = struct.pack('>H h i I I', 0, 0, ext_name, 0x2000, (mdebug.stGlobal << 26) | (mdebug.scText << 21))

    # layout: header 96, then tables; the header's offsets are file offsets, and the section starts at 52
    base = 52
    off = 96
    pos = {}
    for name, blob in (('line', lines), ('pd', pdr), ('sym', local), ('aux', auxb), ('ss', ss.buf),
                       ('ssext', ext.buf), ('fd', None), ('ext', extsym)):
        if name == 'fd':
            off = (off + 3) & ~3
            pos['fd'] = off
            off += 72
            continue
        off = (off + 3) & ~3
        pos[name] = off
        off += len(blob)
    fd = struct.pack('>I i I I I I I I I I H H I I I I I I I', 0x1000, n['t.c'], 0, len(ss.buf), 0, len(S), 0, 4, 0, 0,
                     0, 1, 0, len(aux), 0, 0, 0, 0, len(lines))
    F = {k: v + base for k, v in pos.items()}
    # glevel field: bits 22-23 hold the compile level; language C is 0
    hdr = struct.pack('>2h23I', 0x7009, 0, 4, len(lines), F['line'], 0, 0, 1, F['pd'], len(S), F['sym'],
                      0, 0, len(aux), F['aux'], len(ss.buf), F['ss'], len(ext.buf), F['ssext'], 1, F['fd'],
                      0, 0, 1, F['ext'])
    body = bytearray(off)
    body[0:96] = hdr
    for name, blob in (('line', lines), ('pd', pdr), ('sym', local), ('aux', auxb), ('ss', ss.buf),
                       ('ssext', ext.buf), ('fd', fd), ('ext', extsym)):
        body[pos[name]:pos[name] + len(blob)] = blob
    # ELF32: header, .mdebug, .shstrtab, three section headers
    shstr = b'\0.mdebug\0.shstrtab\0'
    mdebug_off = 52
    shstr_off = mdebug_off + len(body)
    sh_off = (shstr_off + len(shstr) + 3) & ~3
    e = bytearray(b'\x7fELF\x01\x02\x01' + b'\0' * 9)
    e += struct.pack('>HHIIIIIHHHHHH', 1, 8, 1, 0, 0, sh_off, 0, 52, 0, 0, 40, 3, 2)
    e += body + shstr
    e += b'\0' * (sh_off - len(e))
    e += b'\0' * 40
    e += struct.pack('>10I', 1, 0x70000005, 0, 0, mdebug_off, len(body), 0, 0, 4, 1)
    e += struct.pack('>10I', 9, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(e)


class Synthetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = mdebug.Mdebug(build())

    def test_header_and_tables(self):
        m = self.m
        self.assertEqual(len(m.fds), 1)
        self.assertEqual(m.fds[0].name, 't.c')
        self.assertEqual(len(m.procs), 1)
        self.assertEqual(m.hdr['isymMax'], 25)
        self.assertEqual([e.name for e in m.externals], ['ext_fn'])
        self.assertEqual(m.externals[0].value, 0x2000)
        self.assertEqual((m.externals[0].st, m.externals[0].sc), (mdebug.stGlobal, mdebug.scText))

    def test_procedure_name_and_address(self):
        p = self.m.procs[0]
        self.assertEqual(p.name, 'f')
        self.assertEqual(p.sym.value, 0x1000)
        self.assertEqual(p.sym.st, mdebug.stProc)
        self.assertTrue(p.local)

    def test_label_symbol(self):
        s = self.m.sym(0, 13)
        self.assertEqual((s.name, s.st, s.value), ('L1', mdebug.stLabel, 0x1008))

    def test_struct_with_members(self):
        kind, tag, size, mem = self.m.aggregate((0, 1))
        self.assertEqual((kind, tag, size), ('struct', 'pt', 8))
        self.assertEqual([(x[0], x[1], x[2]) for x in mem],
                         [('x', ('base', 'int', 4), 0), ('y', ('base', 'int', 4), 32)])

    def test_enum_with_values(self):
        kind, tag, size, mem = self.m.aggregate((0, 5))
        self.assertEqual((kind, tag, size), ('enum', 'color', 4))
        self.assertEqual(mem, [('RED', 0), ('GREEN', 1)])

    def test_typedef(self):
        defs = {name: t for _fd, name, t, _i in self.m.typedefs()}
        self.assertEqual(defs['intp'], ('ptr', ('base', 'int', 4)))

    def test_bit_field_and_array_members(self):
        kind, tag, size, mem = self.m.aggregate((0, 15))
        self.assertEqual((kind, tag, size), ('struct', 'flags', 20))
        bits, arr = mem
        self.assertEqual((bits[0], bits[3], bits[4]), ('bits', 3, True))
        self.assertEqual(bits[1], ('base', 'unsigned int', 4))
        self.assertEqual(arr[0], 'arr')
        self.assertEqual(arr[1], ('array', ('base', 'int', 4), 0, 3, 128))

    def test_cross_references_and_continued_qualifiers(self):
        kind, tag, size, mem = self.m.aggregate((0, 19))
        by = {x[0]: x[1] for x in mem}
        self.assertEqual(by['next'], ('struct', 'pt', (0, 1)))
        self.assertEqual(by['td'], ('typedef', 'intp', (0, 9)))
        t = by['deep']
        for _ in range(7):
            self.assertEqual(t[0], 'ptr')
            t = t[1]
        self.assertEqual(t, ('base', 'int', 4))

    def test_indirect_follows_its_target(self):
        t, used = self.m.type_at(0, 15)
        self.assertEqual(t, ('ptr', ('base', 'int', 4)))
        self.assertEqual(used, 2)

    def test_procedure_signature(self):
        ret, params, local = self.m.signature(self.m.procs[0])
        self.assertEqual(ret, ('base', 'int', 4))
        self.assertEqual([(p[0], p[1]) for p in params], [('a', ('struct', 'pt', (0, 1)))])
        self.assertEqual([(p[0], p[3]) for p in local], [('b', -4)])

    def test_line_numbers(self):
        got = self.m.lines(0)
        self.assertEqual(got, [(0x1000, 10, 2), (0x1008, 12, 1), (0x100c, 11, 3), (0x1018, 311, 1)])

    def test_c_declarations(self):
        m = self.m
        self.assertEqual(mdebug.c_type(m, ('array', ('base', 'int', 4), 0, 3, 128), 'v'), 'int v[4]')
        self.assertEqual(mdebug.c_type(m, ('ptr', ('func', ('base', 'int', 4))), 'cb'), 'int (*cb)()')
        self.assertEqual(mdebug.c_type(m, ('ptr', ('base', 'char', 1)), 's'), 'char *s')

    def test_rejects_non_mdebug(self):
        with self.assertRaises(mdebug.Error):
            mdebug.Mdebug(b'\x7fELF\x02\x02\x01' + b'\0' * 100)
        with self.assertRaises(mdebug.Error):
            mdebug.Mdebug(b'not an elf')


LIBRARY = os.path.join(HERE, '..', 'root', 'usr', 'gfx', 'arch', 'IP35ODSY', 'libGLcore.so')


@unittest.skipUnless(os.path.exists(LIBRARY), 'root/ has no IP35ODSY libGLcore.so')
class RealLibrary(unittest.TestCase):
    def test_counts_and_first_procedure(self):
        with open(LIBRARY, 'rb') as f:
            m = mdebug.Mdebug(f.read())
        self.assertEqual((len(m.fds), len(m.procs), len(m.externals)), (267, 5223, 4794))
        first = m.procs[0]
        self.assertEqual(first.name, 'sendBlenderOpTokens')
        self.assertEqual(first.fd.name.rsplit('/', 1)[-1], 'ody_accumop.c')
        self.assertTrue(all(p.name for p in m.procs))
        # compiled without -g: names and lines, no type records
        self.assertEqual(len(m.aggregates()), 0)


if __name__ == '__main__':
    unittest.main()
