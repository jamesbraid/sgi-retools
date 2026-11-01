#!/usr/bin/env python3
"""Reader for the ECOFF-style .mdebug symbol table in 32-bit MIPSpro ELF objects.

o32 and N32 objects built by the MIPSpro compilers carry a `.mdebug` section: a symbolic
header, per-source-file descriptors, procedure descriptors, local and external symbols, an
auxiliary table of type records, string spaces and packed line numbers. The ELF loaders of
common tools ignore it. This module decodes it, written from the public layout in
binutils' include/coff/sym.h, symconst.h and ecoff.h, and the documented behaviour of
gdb's mdebug reader.

    python3 scripts/mdebug.py OBJECT            summary: counts of each decoded piece
    python3 scripts/mdebug.py OBJECT --procs    one line per procedure: address, name, file:lines
    python3 scripts/mdebug.py OBJECT --types    every struct, union, enum and typedef as C
    python3 scripts/mdebug.py OBJECT --signatures
                                                each procedure's return type and parameters

The same decoding is done independently in tools/ghidra-scripts/ReMdebugImport.java, which
applies it to a Ghidra program; this module is its cross-check and carries the format tests
(scripts/test_mdebug.py). Only the 32-bit layout is read: N64 objects carry DWARF instead.
Big-endian files only.
"""
import argparse
import struct
import sys

MAGIC = 0x7009
MAGIC_ALPHA = 0x1992

# Symbol types (st) and storage classes (sc).
ST = {0: 'Nil', 1: 'Global', 2: 'Static', 3: 'Param', 4: 'Local', 5: 'Label', 6: 'Proc', 7: 'Block',
      8: 'End', 9: 'Member', 10: 'Typedef', 11: 'File', 12: 'RegReloc', 13: 'Forward',
      14: 'StaticProc', 15: 'Constant', 16: 'StaParam', 26: 'Struct', 27: 'Union', 28: 'Enum',
      34: 'Indirect', 60: 'Str', 61: 'Number', 62: 'Expr', 63: 'Type'}
stNil, stGlobal, stStatic, stParam, stLocal, stLabel, stProc, stBlock, stEnd, stMember, stTypedef, \
    stFile, stRegReloc, stForward, stStaticProc, stConstant, stStaParam = range(17)
stStruct, stUnion, stEnum, stIndirect = 26, 27, 28, 34
SC = {0: 'Nil', 1: 'Text', 2: 'Data', 3: 'Bss', 4: 'Register', 5: 'Abs', 6: 'Undefined', 7: 'CdbLocal',
      8: 'Bits', 9: 'CdbSystem', 10: 'RegImage', 11: 'Info', 12: 'UserStruct', 13: 'SData', 14: 'SBss',
      15: 'RData', 16: 'Var', 17: 'Common', 18: 'SCommon', 19: 'VarRegister', 20: 'Variant',
      21: 'SUndefined', 22: 'Init', 23: 'BasedVar', 24: 'XData', 25: 'PData', 26: 'Fini', 27: 'RConst'}
scNil, scText, scData, scBss, scRegister, scAbs, scUndefined, scCdbLocal, scBits, scCdbSystem, \
    scRegImage, scInfo = range(12)
scSData, scSBss, scRData = 13, 14, 15

# Type qualifiers and basic types.
tqNil, tqPtr, tqProc, tqArray, tqFar, tqVol, tqConst = range(7)
BT = {0: 'nil', 1: 'adr', 2: 'char', 3: 'unsigned char', 4: 'short', 5: 'unsigned short', 6: 'int',
      7: 'unsigned int', 8: 'long', 9: 'unsigned long', 10: 'float', 11: 'double', 12: 'struct',
      13: 'union', 14: 'enum', 15: 'typedef', 16: 'range', 17: 'set', 18: 'complex',
      19: 'double complex', 20: 'indirect', 26: 'void', 27: 'long long', 28: 'unsigned long long',
      30: 'long', 31: 'unsigned long', 32: 'long long', 33: 'unsigned long long', 34: 'adr64',
      35: 'int', 36: 'unsigned int'}
btNil, btAdr, btChar, btUChar, btShort, btUShort, btInt, btUInt, btLong, btULong, btFloat, \
    btDouble, btStruct, btUnion, btEnum, btTypedef, btRange, btSet, btComplex, btDComplex, \
    btIndirect = range(21)
btVoid, btLongLong, btULongLong = 26, 27, 28
# Byte size of the basic types in the 32-bit (o32 and N32) ABIs. `long` is 4 bytes in both.
BT_SIZE = {btAdr: 4, btChar: 1, btUChar: 1, btShort: 2, btUShort: 2, btInt: 4, btUInt: 4, btLong: 4,
           btULong: 4, btFloat: 4, btDouble: 8, btComplex: 8, btDComplex: 16, btVoid: 0,
           btLongLong: 8, btULongLong: 8, 30: 8, 31: 8, 32: 8, 33: 8, 34: 8, 35: 8, 36: 8}

INDEX_NIL = 0xfffff
ESCAPE_RFD = 0xfff


class Error(Exception):
    pass


def elf_section(data, name):
    """The (offset, size) of a section of a big-endian ELF file, or None."""
    if data[:4] != b'\x7fELF' or data[5] != 2:
        raise Error('not a big-endian ELF file')
    if data[4] == 1:
        shoff, = struct.unpack('>I', data[32:36])
        shentsize, shnum, shstrndx = struct.unpack('>3H', data[46:52])
        secs = [struct.unpack('>10I', data[shoff + i * shentsize:shoff + i * shentsize + 40])
                for i in range(shnum)]
        fields = lambda s: (s[0], s[4], s[5])
    elif data[4] == 2:
        shoff, = struct.unpack('>Q', data[40:48])
        shentsize, shnum, shstrndx = struct.unpack('>3H', data[58:64])
        secs = [struct.unpack('>2I4Q2I2Q', data[shoff + i * shentsize:shoff + i * shentsize + 64])
                for i in range(shnum)]
        fields = lambda s: (s[0], s[4], s[5])
    else:
        raise Error('bad ELF class')
    stroff = fields(secs[shstrndx])[1]
    for s in secs:
        n, off, size = fields(s)
        a = stroff + n
        if data[a:data.index(b'\0', a)] == name.encode():
            return off, size
    return None


def elf_class(data):
    return data[4]


class Sym:
    __slots__ = ('iss', 'value', 'st', 'sc', 'index', 'name', 'fd', 'isym')

    def __repr__(self):
        return 'Sym(%r %s/%s value=%#x index=%#x)' % (self.name, ST.get(self.st, self.st),
                                                      SC.get(self.sc, self.sc), self.value, self.index)


class Proc:
    __slots__ = ('adr', 'isym', 'iline', 'regmask', 'regoffset', 'fregmask', 'fregoffset', 'frameoffset',
                 'framereg', 'pcreg', 'lnLow', 'lnHigh', 'cbLineOffset', 'name', 'fd', 'sym', 'local')


class FileDesc:
    __slots__ = ('adr', 'rss', 'issBase', 'cbSs', 'isymBase', 'csym', 'ilineBase', 'cline', 'ioptBase',
                 'copt', 'ipdFirst', 'cpd', 'iauxBase', 'caux', 'rfdBase', 'crfd', 'lang', 'glevel',
                 'cbLineOffset', 'cbLine', 'name', 'index')


def signed(v, bits=32):
    return v - (1 << bits) if v >= 1 << (bits - 1) else v


class Mdebug:
    """A parsed .mdebug section. `data` is the whole file: the header's offsets are file offsets."""

    def __init__(self, data):
        self.data = data
        if elf_class(data) != 1:
            raise Error('ELF64 object: the 32-bit ECOFF layout does not apply (N64 uses DWARF)')
        found = elf_section(data, '.mdebug')
        if found is None:
            raise Error('no .mdebug section')
        off, size = found
        if size < 96:
            raise Error('.mdebug is too small for its header')
        h = struct.unpack('>2h23I', data[off:off + 96])
        if h[0] not in (MAGIC, MAGIC_ALPHA):
            raise Error('bad symbolic header magic %#x' % (h[0] & 0xffff))
        self.hdr = dict(zip(('magic', 'vstamp', 'ilineMax', 'cbLine', 'cbLineOffset', 'idnMax', 'cbDnOffset',
                             'ipdMax', 'cbPdOffset', 'isymMax', 'cbSymOffset', 'ioptMax', 'cbOptOffset',
                             'iauxMax', 'cbAuxOffset', 'issMax', 'cbSsOffset', 'issExtMax', 'cbSsExtOffset',
                             'ifdMax', 'cbFdOffset', 'crfd', 'cbRfdOffset', 'iextMax', 'cbExtOffset'), h))
        self._syms = {}
        self._types = {}
        self.fds = [self._fd(i) for i in range(self.hdr['ifdMax'])]
        self.procs = []
        for fd in self.fds:
            for p in range(fd.ipdFirst, fd.ipdFirst + fd.cpd):
                self.procs.append(self._pdr(fd, p))
        self.externals = [self._ext(i) for i in range(self.hdr['iextMax'])]

    # -- tables -------------------------------------------------------------------------
    def _cstr(self, off):
        end = self.data.index(b'\0', off)
        return self.data[off:end].decode('latin1')

    def _fd(self, i):
        h = self.hdr
        o = h['cbFdOffset'] + 72 * i
        v = struct.unpack('>I i I I I I I I I I H H I I I I I I I', self.data[o:o + 72])
        f = FileDesc()
        (f.adr, f.rss, f.issBase, f.cbSs, f.isymBase, f.csym, f.ilineBase, f.cline, f.ioptBase, f.copt,
         f.ipdFirst, f.cpd, f.iauxBase, f.caux, f.rfdBase, f.crfd, bits, f.cbLineOffset, f.cbLine) = v
        f.lang = bits >> 27
        f.glevel = (bits >> 22) & 3
        f.cpd = signed(f.cpd, 16)
        f.index = i
        f.name = self._cstr(h['cbSsOffset'] + f.issBase + f.rss) if f.rss != -1 else ''
        return f

    def _pdr(self, fd, ipd):
        o = self.hdr['cbPdOffset'] + 52 * ipd
        v = struct.unpack('>I i i I i i I i i h h i i I', self.data[o:o + 52])
        p = Proc()
        (p.adr, p.isym, p.iline, p.regmask, p.regoffset, _iopt, p.fregmask, p.fregoffset, p.frameoffset,
         p.framereg, p.pcreg, p.lnLow, p.lnHigh, p.cbLineOffset) = v
        p.fd = fd
        p.local = fd.rss != -1 and p.isym != -1
        p.sym = None
        if p.local:
            p.sym = self.sym(fd.index, p.isym)
            p.name = p.sym.name
        elif p.isym != -1:
            p.name = self.ext_name(p.isym)
        else:
            p.name = ''
        return p

    def _ext(self, i):
        o = self.hdr['cbExtOffset'] + 16 * i
        flags, ifd, iss, value, word = struct.unpack('>H h i I I', self.data[o:o + 16])
        s = Sym()
        s.iss, s.value = iss, value
        s.st, s.sc, s.index = word >> 26, (word >> 21) & 31, word & 0xfffff
        s.name = self._cstr(self.hdr['cbSsExtOffset'] + iss)
        s.fd, s.isym = ifd, -1
        return s

    def ext_name(self, i):
        return self.externals[i].name if i < len(self.externals) else ''

    def sym(self, fd, isym):
        """Local symbol number `isym` of file `fd`, with its name resolved."""
        key = (fd, isym)
        s = self._syms.get(key)
        if s is None:
            f = self.fds[fd]
            if not 0 <= isym < f.csym:
                raise Error('symbol %d outside file %d' % (isym, fd))
            o = self.hdr['cbSymOffset'] + 12 * (f.isymBase + isym)
            iss, value, word = struct.unpack('>i I I', self.data[o:o + 12])
            s = Sym()
            s.iss, s.value = iss, value
            s.st, s.sc, s.index = word >> 26, (word >> 21) & 31, word & 0xfffff
            s.name = self._cstr(self.hdr['cbSsOffset'] + f.issBase + iss) if iss >= 0 else ''
            s.fd, s.isym = fd, isym
            self._syms[key] = s
        return s

    def aux(self, fd, i):
        f = self.fds[fd]
        if not 0 <= i < f.caux:
            raise Error('aux %d outside file %d' % (i, fd))
        o = self.hdr['cbAuxOffset'] + 4 * (f.iauxBase + i)
        return struct.unpack('>I', self.data[o:o + 4])[0]

    def rfd(self, fd, r):
        f = self.fds[fd]
        if f.rfdBase == 0:      # object files keep absolute file numbers
            return r
        o = self.hdr['cbRfdOffset'] + 4 * (f.rfdBase + r)
        return struct.unpack('>I', self.data[o:o + 4])[0]

    # -- types --------------------------------------------------------------------------
    def type_at(self, fd, i, depth=0):
        """Decode the type record at aux index `i` of file `fd`.

        Returns (type, aux words consumed). A type is a tuple:
          ('base', C name, size)           char, int, float, void ...
          ('ptr', type)  ('func', return type)  ('array', element, low, high, element bits)
          ('struct'|'union'|'enum', tag, (fd, isym))     tag may be ''
          ('typedef', name, (fd, isym))
          ('const', type)  ('volatile', type)
          ('bitfield', type, bits)         only as a member's type
        """
        if i == INDEX_NIL:
            return ('base', 'int', 4), 0
        if depth > 32:
            raise Error('type nesting too deep')
        w = self.aux(fd, i)
        fBitfield, cont, bt = w >> 31, (w >> 30) & 1, (w >> 24) & 63
        tq = [(w >> 12) & 15, (w >> 8) & 15, (w >> 4) & 15, w & 15, (w >> 20) & 15, (w >> 16) & 15]
        n = 1
        width = None
        if fBitfield:
            width = signed(self.aux(fd, i + n))
            n += 1
        t = None
        if bt == btIndirect:
            rfd_w = self.aux(fd, i + n)
            rf, idx = rfd_w >> 20, rfd_w & 0xfffff
            n += 1
            if rf == ESCAPE_RFD:
                rf = self.aux(fd, i + n)
                n += 1
            if rf == 0xffffffff:
                t = ('base', 'int', 4)
            else:
                xfd = self.rfd(fd, rf)
                t, _ = self.type_at(xfd, idx, depth + 1)
        elif bt in (btStruct, btUnion, btEnum, btSet, btTypedef, btRange):
            rfd_w = self.aux(fd, i + n)
            rf, idx = rfd_w >> 20, rfd_w & 0xfffff
            n += 1
            if rf == ESCAPE_RFD:
                rf = self.aux(fd, i + n)
                n += 1
            ref = self._reference(fd, rf, idx, bt)
            if bt == btRange:
                lo, hi = signed(self.aux(fd, i + n)), signed(self.aux(fd, i + n + 1))
                n += 2
                t = ('range', ref[1] if ref else '', lo, hi)
            else:
                t = ref
        elif bt in BT_SIZE or bt == btNil:
            name = BT.get(bt, 'int')
            t = ('base', {'adr': 'void *', 'adr64': 'void *'}.get(name, name),
                 BT_SIZE.get(bt, 4))
        else:
            t = ('base', 'int', 4)
        # Qualifiers apply innermost first; tq0 is the one next to the basic type.
        while True:
            for q in tq:
                if q == tqNil:
                    break
                if q == tqPtr:
                    t = ('ptr', t)
                elif q == tqProc:
                    t = ('func', t)
                elif q == tqArray:
                    rw = self.aux(fd, i + n)
                    rf, idx = rw >> 20, rw & 0xfffff
                    n += 1
                    if rf == ESCAPE_RFD:
                        rf = self.aux(fd, i + n)
                        n += 1
                    lo, hi = signed(self.aux(fd, i + n)), signed(self.aux(fd, i + n + 1))
                    bits = self.aux(fd, i + n + 2)
                    n += 3
                    t = ('array', t, lo, hi, bits)
                elif q == tqVol:
                    t = ('volatile', t)
                elif q == tqConst:
                    t = ('const', t)
            if not cont:
                break
            w = self.aux(fd, i + n)
            n += 1
            cont = (w >> 30) & 1
            tq = [(w >> 12) & 15, (w >> 8) & 15, (w >> 4) & 15, w & 15, (w >> 20) & 15, (w >> 16) & 15]
        if width is not None:
            t = ('bitfield', t, width)
        return t, n

    def _reference(self, fd, rf, idx, bt):
        """The aggregate or typedef a cross reference names, as a type tuple."""
        kind = {btStruct: 'struct', btUnion: 'union', btEnum: 'enum', btSet: 'set',
                btTypedef: 'typedef', btRange: 'range'}[bt]
        if rf == 0xffffffff or (rf == ESCAPE_RFD and idx == 0):
            return (kind, '', None)           # opaque or undefined
        xfd = self.rfd(fd, rf)
        if not 0 <= xfd < len(self.fds) or idx >= self.fds[xfd].csym:
            return (kind, '', None)
        s = self.sym(xfd, idx)
        if s.st == stIndirect or (s.st == stTypedef and s.iss == 0):
            # A forward declaration: its aux record points at the real definition.
            t, _ = self.type_at(xfd, s.index, 1)
            if t[0] in ('struct', 'union', 'enum') and t[2] is None:
                return t
            if bt == btTypedef:
                return t
            return t if t[0] in ('struct', 'union', 'enum') else (kind, '', None)
        return (kind, s.name, (xfd, idx))

    # -- aggregates ---------------------------------------------------------------------
    def aggregate(self, key):
        """Definition of the aggregate at key=(fd, isym).

        Returns (kind, tag, size, members), where members are (name, type, byte offset or
        bit offset, bitwidth or None) for struct and union, and (name, value) for enum.
        The kind comes from the symbol type when the compiler recorded one, and is guessed
        from the members otherwise (as other readers do); `type_kind` overrides the guess
        for aggregates a variable or field refers to by kind.
        """
        if key in self._types:
            return self._types[key]
        fd, isym = key
        s = self.sym(fd, isym)
        end = s.index
        f = self.fds[fd]
        members = []
        kind = {stStruct: 'struct', stUnion: 'union', stEnum: 'enum'}.get(s.st)
        j = isym + 1
        enum_members = []
        while j < min(end, f.csym):
            m = self.sym(fd, j)
            if m.st == stMember:
                enum_members.append(m)
            elif m.st in (stBlock, stUnion, stEnum, stStruct) and m.index != 0:
                j = m.index - 1
            elif m.st == stEnd:
                break
            j += 1
        types_ok = []
        for m in enum_members:
            if m.index == INDEX_NIL or (m.index == 0 and m.value == 0):
                types_ok.append('enum')
                continue
            try:
                t, _ = self.type_at(fd, m.index)
            except Error:
                types_ok.append('struct')
                continue
            w = self.aux(fd, m.index)
            if (((w >> 24) & 63) in (btNil, btVoid) or (((w >> 24) & 63) == btEnum and m.value == 0)) \
                    and (w >> 12) & 15 == 0:
                types_ok.append('enum')
            else:
                types_ok.append('struct')
        if kind is None:
            if types_ok and types_ok[0] == 'enum':
                kind = 'enum'
            elif len(enum_members) > 1 and all(m.value == 0 for m in enum_members):
                kind = 'union'
            else:
                kind = 'struct'
        out = []
        if kind == 'enum':
            out = [(m.name, signed(m.value)) for m in enum_members]
        else:
            for m in enum_members:
                try:
                    t, _ = self.type_at(fd, m.index)
                except Error:
                    t = ('base', 'int', 4)
                width = t[2] if t[0] == 'bitfield' else None
                out.append((m.name, t[1] if width is not None else t, m.value, width, m.sc == scBits))
        size = s.value
        if kind == 'enum' and (size == len(enum_members) or size == 0):
            size = 4
        res = (kind, s.name, size, out)
        self._types[key] = res
        return res

    def typedefs(self):
        """Named type definitions: (file, name, type) for every stTypedef with a name."""
        out = []
        for fd in self.fds:
            for i in range(fd.csym):
                s = self.sym(fd.index, i)
                if s.st == stTypedef and s.iss != 0 and s.name:
                    try:
                        t, _ = self.type_at(fd.index, s.index)
                    except Error:
                        continue
                    out.append((fd.index, s.name, t, i))
        return out

    def aggregates(self):
        """Every struct, union and enum definition (not forward references) of every file."""
        out = []
        for fd in self.fds:
            for i in range(fd.csym):
                s = self.sym(fd.index, i)
                if s.st in (stStruct, stUnion, stEnum) or (s.st == stBlock and s.sc in (scInfo, scNil)
                                                            and s.index > i + 1):
                    out.append(((fd.index, i), s))
        return out

    # -- procedures ---------------------------------------------------------------------
    def signature(self, p):
        """(return type, [(param name, type, sc, value)], [(local name, type, sc, value)]) of a local
        procedure, from the symbols between its stProc and the matching stEnd."""
        if not p.local or p.sym.st not in (stProc, stStaticProc):
            return None
        fd = p.fd.index
        s = p.sym
        ret = ('base', 'int', 4)
        aux_at = s.index
        if aux_at != INDEX_NIL and aux_at < p.fd.caux:
            try:
                # The first aux word is the symbol after the procedure's end; the type follows.
                t, _ = self.type_at(fd, aux_at + 1)
                ret = t[1] if t[0] == 'func' else t
            except Error:
                pass
        end = p.fd.csym
        try:
            end = min(end, self.aux(fd, aux_at))
        except Error:
            pass
        params, local = [], []
        j = p.isym + 1
        while j < end:
            m = self.sym(fd, j)
            if m.st == stEnd:
                break
            if m.st in (stParam, stLocal, stStatic) and m.name:
                try:
                    t, _ = self.type_at(fd, m.index)
                except Error:
                    t = ('base', 'int', 4)
                (params if m.st == stParam else local).append((m.name, t, m.sc, signed(m.value), m.st))
            elif m.st in (stBlock,) and m.sc == scText:
                pass
            j += 1
        return ret, params, local

    def lines(self, fd):
        """(address, line) for every instruction run of file `fd`: one entry per run, from the packed
        line table. Addresses are the procedure's own, in the object's address space."""
        f = self.fds[fd]
        out = []
        if f.cbLine == 0:
            return out
        base = self.hdr['cbLineOffset'] + f.cbLineOffset
        procs = [p for p in self.procs if p.fd is f]
        for j, p in enumerate(procs):
            if p.iline == -1 or p.lnLow == -1 or p.lnHigh == -1:
                continue
            halt = base + (procs[j + 1].cbLineOffset if j + 1 < len(procs) else f.cbLine)
            o = base + p.cbLineOffset
            line, adr = p.lnLow, p.adr
            while o < halt:
                b = self.data[o]
                o += 1
                count, delta = b & 15, b >> 4
                if delta >= 8:
                    delta -= 16
                if delta == -8:
                    delta = signed((self.data[o] << 8) | self.data[o + 1], 16)
                    o += 2
                line += delta
                out.append((adr, line, count + 1))
                adr += 4 * (count + 1)
        return out


# -- C text -------------------------------------------------------------------------------
def c_type(m, t, name=''):
    """C declaration of `name` having type tuple `t`."""
    k = t[0]
    if k == 'base':
        return (t[1] + (' ' + name if name and not t[1].endswith('*') else name)).strip()
    if k in ('struct', 'union', 'enum'):
        return ('%s %s' % (k, t[1] or '/*anonymous*/')) + (' ' + name if name else '')
    if k in ('typedef', 'range', 'set'):
        return (t[1] or 'int') + (' ' + name if name else '')
    if k in ('const', 'volatile'):
        return '%s %s' % (k, c_type(m, t[1], name))
    if k == 'ptr':
        inner = t[1]
        if inner[0] in ('array', 'func'):
            return c_type(m, inner, '(*%s)' % name)
        return c_type(m, inner, '*' + name)
    if k == 'func':
        return c_type(m, t[1], '%s()' % name)
    if k == 'array':
        return c_type(m, t[1], '%s[%d]' % (name, t[3] - t[2] + 1))
    if k == 'bitfield':
        return c_type(m, t[1], name) + ' : %d' % t[2]
    return 'int ' + name


def format_types(m):
    lines = []
    for key, s in m.aggregates():
        kind, tag, size, members = m.aggregate(key)
        head = '%s %s' % (kind, tag or '/*anonymous*/')
        lines.append('%s { /* %d bytes, %s:%d */' % (head, size, m.fds[key[0]].name.rsplit('/', 1)[-1], key[1]))
        for mem in members:
            if kind == 'enum':
                lines.append('    %s = %d,' % mem)
            else:
                name, t, off, width, is_bits = mem
                lines.append('    %s; /* +%s%s */' % (c_type(m, t, name) + (' : %d' % width if width else ''),
                                                      '%d bits' % off if is_bits or width else '%d' % (off // 8),
                                                      ''))
        lines.append('};')
    for fd, name, t, i in m.typedefs():
        lines.append('typedef %s;' % c_type(m, t, name))
    return lines


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('object')
    ap.add_argument('--procs', action='store_true')
    ap.add_argument('--types', action='store_true')
    ap.add_argument('--signatures', action='store_true')
    a = ap.parse_args(argv)
    data = open(a.object, 'rb').read()
    try:
        m = Mdebug(data)
    except Error as e:
        sys.exit('mdebug: %s: %s' % (a.object, e))
    if a.procs:
        for p in m.procs:
            print('%08x\t%s\t%s\t%d-%d' % (p.adr, p.name, p.fd.name.rsplit('/', 1)[-1], p.lnLow, p.lnHigh))
    elif a.types:
        print('\n'.join(format_types(m)))
    elif a.signatures:
        for p in m.procs:
            sig = m.signature(p)
            if sig:
                ret, params, _ = sig
                print('%s(%s);' % (c_type(m, ret, p.name), ', '.join(c_type(m, t, n) for n, t, *_ in params)))
    else:
        by = {}
        for fd in m.fds:
            for i in range(fd.csym):
                s = m.sym(fd.index, i)
                by[s.st] = by.get(s.st, 0) + 1
        print('files %d  procedures %d  local symbols %d  externals %d  aux words %d'
              % (len(m.fds), len(m.procs), sum(by.values()), len(m.externals), m.hdr['iauxMax']))
        print('symbols by type: ' + ', '.join('%s %d' % (ST.get(k, k), v) for k, v in sorted(by.items())))
        print('aggregates %d  typedefs %d' % (len(m.aggregates()), len(m.typedefs())))


if __name__ == '__main__':
    main(sys.argv[1:])
