#!/usr/bin/env python3
"""Intel i960 disassembler (Jx/Rx core, little-endian) with an i960 COFF reader.

Usage:
  python3 -I tools/hdsp/i960dis.py FILE [--coff-offset N] [--section .text] [--from ADDR] [--to ADDR]
                                    [--base ADDR] [--raw] [--no-syms] [--check] [--strict]

FILE is either an i960 COFF object (magic 0x0160 or 0x0161; the section data, relocations and symbols are
read, call and displacement targets are named from the relocations) or, with --raw, a flat binary
decoded linearly from --base (default 0). --coff-offset says where the COFF header sits when the
file carries a wrapper in front of it (the offsets inside the COFF are then relative to that
point). Output is one instruction per line: address, raw words, mnemonic and operands, then a
`;` comment holding the symbol or relocation the instruction refers to.

--check decodes the whole section and reports instruction counts per format and every word that
did not decode (printed as `.word`). It exits 0 unless --strict is given and unknown words exist.

The instruction set tables come from the Intel i960 Rx I/O Microprocessor Developer's Manual
(272736-002, chapters 6 and 7: the instruction formats, the opcode map and the per-instruction
pages) and the i960 Jx Microprocessor User's Manual. The opcode map was cross-checked against
MAME's BSD-3-Clause i960 disassembler (src/devices/cpu/i960/i960dis.cpp, Farfetch'd and
R. Belmont); the decoder here is written independently. Floating point opcodes (Kx/Sx class) are
named but the Jx/Rx parts have no FPU; they decode with the same operand rules.

Syntax: Intel mnemonics, `src1,src2,dst` operand order, literals as decimal, special function
registers as sfN, memory as `disp(abase)[index*scale]`. Branch and call targets are absolute
addresses (the instruction address plus the displacement).
"""
import argparse
import struct
import sys

REGS = ['pfp', 'sp', 'rip', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
        'g0', 'g1', 'g2', 'g3', 'g4', 'g5', 'g6', 'g7', 'g8', 'g9', 'g10', 'g11', 'g12', 'g13', 'g14', 'fp']
# Floating-point operand literals in REG format (Kx/Sx; none on Jx/Rx). Table from MAME's disassembler:
# the Intel Rx manual has no FP chapter and the KB manual appendix was not at hand.
FPLIT = {0: 'fp0', 1: 'fp1', 2: 'fp2', 3: 'fp3', 16: '0.0', 22: '1.0'}

# CTRL format: opcode -> mnemonic (bits 24-31); 24-bit word displacement in bits 2-23.
CTRL = {0x08: 'b', 0x09: 'call', 0x0a: 'ret', 0x0b: 'bal'}
CC = ['no', 'g', 'e', 'ge', 'l', 'ne', 'le', 'o']
for _i, _c in enumerate(CC):
    CTRL[0x10 + _i] = 'b' + _c
    CTRL[0x18 + _i] = 'fault' + _c
# TEST<cc> use the COBR slot but name a single destination in the src1 field.
TEST = {0x20 + _i: 'test' + _c for _i, _c in enumerate(CC)}
# COBR format: compare-and-branch.
COBR = {0x30: 'bbc', 0x37: 'bbs'}
for _i, _c in enumerate(CC[1:7], 1):
    COBR[0x30 + _i] = 'cmpob' + _c
for _i, _c in enumerate(CC):
    COBR[0x38 + _i] = 'cmpib' + _c

# MEM format: opcode -> (mnemonic, kind). kind: ld (load), st (store), ea (effective address only).
MEM = {
    0x80: ('ldob', 'ld'), 0x82: ('stob', 'st'), 0x84: ('bx', 'ea'), 0x85: ('balx', 'ldea'), 0x86: ('callx', 'ea'),
    0x88: ('ldos', 'ld'), 0x8a: ('stos', 'st'), 0x8c: ('lda', 'ld'),
    0x90: ('ld', 'ld'), 0x92: ('st', 'st'), 0x98: ('ldl', 'ld'), 0x9a: ('stl', 'st'),
    0xa0: ('ldt', 'ld'), 0xa2: ('stt', 'st'), 0xad: ('dcinva', 'ea'),
    0xb0: ('ldq', 'ld'), 0xb2: ('stq', 'st'),
    0xc0: ('ldib', 'ld'), 0xc2: ('stib', 'st'), 0xc8: ('ldis', 'ld'), 0xca: ('stis', 'st'),
}

# REG format: 12-bit opcode (bits 24-31 then bits 7-10) -> (mnemonic, signature).
# Signature letters: 1 src1, 2 src2, d destination (written), m src/dst (read and written),
# D destination used as a source (third source operand).
# Float variants (F prefix letters) use fpN names for register-literal forms.
_R = {}


def _reg(base, rows, sig):
    for off, name in rows:
        _R[base + off] = (name, sig)


for op, name, sig in [
    (0x580, 'notbit', '12d'), (0x581, 'and', '12d'), (0x582, 'andnot', '12d'), (0x583, 'setbit', '12d'),
    (0x584, 'notand', '12d'), (0x586, 'xor', '12d'), (0x587, 'or', '12d'), (0x588, 'nor', '12d'),
    (0x589, 'xnor', '12d'), (0x58a, 'not', '1d'), (0x58b, 'ornot', '12d'), (0x58c, 'clrbit', '12d'),
    (0x58d, 'notor', '12d'), (0x58e, 'nand', '12d'), (0x58f, 'alterbit', '12d'),
    (0x590, 'addo', '12d'), (0x591, 'addi', '12d'), (0x592, 'subo', '12d'), (0x593, 'subi', '12d'),
    (0x594, 'cmpob', '12'), (0x595, 'cmpib', '12'), (0x596, 'cmpos', '12'), (0x597, 'cmpis', '12'),
    (0x598, 'shro', '12d'), (0x59a, 'shrdi', '12d'), (0x59b, 'shri', '12d'), (0x59c, 'shlo', '12d'),
    (0x59d, 'rotate', '12d'), (0x59e, 'shli', '12d'),
    (0x5a0, 'cmpo', '12'), (0x5a1, 'cmpi', '12'), (0x5a2, 'concmpo', '12'), (0x5a3, 'concmpi', '12'),
    (0x5a4, 'cmpinco', '12d'), (0x5a5, 'cmpinci', '12d'), (0x5a6, 'cmpdeco', '12d'), (0x5a7, 'cmpdeci', '12d'),
    (0x5ac, 'scanbyte', '12'), (0x5ad, 'bswap', '1d'), (0x5ae, 'chkbit', '12'),
    (0x5b0, 'addc', '12d'), (0x5b2, 'subc', '12d'), (0x5b4, 'intdis', ''), (0x5b5, 'inten', ''),
    (0x5cc, 'mov', '1d'), (0x5d8, 'eshro', '12d'), (0x5dc, 'movl', '1d'), (0x5ec, 'movt', '1d'), (0x5fc, 'movq', '1d'),
    (0x600, 'synmov', '12'), (0x601, 'synmovl', '12'), (0x602, 'synmovq', '12'), (0x603, 'cmpstr', '12D'),
    (0x604, 'movqstr', '12D'), (0x605, 'movstr', '12D'),
    (0x610, 'atmod', '12m'), (0x612, 'atadd', '12d'), (0x613, 'inspacc', '1d'), (0x614, 'ldphy', '1d'),
    (0x615, 'synld', '1d'), (0x617, 'fill', '12D'),
    (0x630, 'sdma', '12D'), (0x631, 'udma', ''),
    (0x640, 'spanbit', '1d'), (0x641, 'scanbit', '1d'), (0x642, 'daddc', '12d'), (0x643, 'dsubc', '12d'),
    (0x644, 'dmovt', '1d'), (0x645, 'modac', '12m'),
    (0x650, 'modify', '12m'), (0x651, 'extract', '12m'), (0x654, 'modtc', '12m'), (0x655, 'modpc', '12m'),
    (0x656, 'receive', '1d'), (0x658, 'intctl', '1d'), (0x659, 'sysctl', '12m'), (0x65b, 'icctl', '12m'),
    (0x65c, 'dcctl', '12m'), (0x65d, 'halt', '1'),
    (0x660, 'calls', '1'), (0x662, 'send', '12d'), (0x663, 'sendserv', '1'), (0x664, 'resumprcs', '1'),
    (0x665, 'schedprcs', '1'), (0x666, 'saveprcs', ''), (0x668, 'condwait', '1'), (0x669, 'wait', '1'),
    (0x66a, 'signal', '1'), (0x66b, 'mark', ''), (0x66c, 'fmark', ''), (0x66d, 'flushreg', ''), (0x66f, 'syncf', ''),
    (0x670, 'emul', '12d'), (0x671, 'ediv', '12d'), (0x673, 'ldtime', 'd'),
    (0x674, 'cvtir', 'F1d'), (0x675, 'cvtilr', 'F1d'), (0x676, 'scalerl', 'F12d'), (0x677, 'scaler', 'F12d'),
    (0x680, 'atanr', 'F12d'), (0x681, 'logepr', 'F12d'), (0x682, 'logr', 'F12d'), (0x683, 'remr', 'F12d'),
    (0x684, 'cmpor', 'F12'), (0x685, 'cmpr', 'F12'), (0x688, 'sqrtr', 'F1d'), (0x689, 'expr', 'F1d'),
    (0x68a, 'logbnr', 'F1d'), (0x68b, 'roundr', 'F1d'), (0x68c, 'sinr', 'F1d'), (0x68d, 'cosr', 'F1d'),
    (0x68e, 'tanr', 'F1d'), (0x68f, 'classr', 'F1'),
    (0x690, 'atanrl', 'F12d'), (0x691, 'logeprl', 'F12d'), (0x692, 'logrl', 'F12d'), (0x693, 'remrl', 'F12d'),
    (0x694, 'cmporl', 'F12'), (0x695, 'cmprl', 'F12'), (0x698, 'sqrtrl', 'F1d'), (0x699, 'exprl', 'F1d'),
    (0x69a, 'logbnrl', 'F1d'), (0x69b, 'roundrl', 'F1d'), (0x69c, 'sinrl', 'F1d'), (0x69d, 'cosrl', 'F1d'),
    (0x69e, 'tanrl', 'F1d'), (0x69f, 'classrl', 'F1'),
    (0x6c0, 'cvtri', 'F1d'), (0x6c1, 'cvtril', 'F1d'), (0x6c2, 'cvtzri', 'F1d'), (0x6c3, 'cvtzril', 'F1d'),
    (0x6c9, 'movr', 'F1d'), (0x6d9, 'movrl', 'F1d'), (0x6e1, 'movre', 'F1d'), (0x6e2, 'cpysre', 'F12d'),
    (0x6e3, 'cpyrsre', 'F12d'),
    (0x701, 'mulo', '12d'), (0x708, 'remo', '12d'), (0x70b, 'divo', '12d'),
    (0x741, 'muli', '12d'), (0x748, 'remi', '12d'), (0x749, 'modi', '12d'), (0x74b, 'divi', '12d'),
    (0x78b, 'divr', 'F12d'), (0x78c, 'mulr', 'F12d'), (0x78d, 'subr', 'F12d'), (0x78f, 'addr', 'F12d'),
    (0x79b, 'divrl', 'F12d'), (0x79c, 'mulrl', 'F12d'), (0x79d, 'subrl', 'F12d'), (0x79f, 'addrl', 'F12d'),
]:
    _R[op] = (name, sig)
# Conditional add/sub/select: 0x78x..0x7fx, one row per condition (no, g, e, ge, l, ne, le, o).
for _i, _c in enumerate(CC):
    _b = 0x780 + 0x10 * _i
    for _o, _n in [(0, 'addo'), (1, 'addi'), (2, 'subo'), (3, 'subi'), (4, 'sel')]:
        _R[_b + _o] = (_n + _c, '12d')
REG = _R


class Insn:
    __slots__ = ('addr', 'size', 'raw', 'text', 'mnem', 'known', 'target', 'fmt', 'disp_at', 'flow')

    def __init__(self, addr, size, raw, text, mnem, known, fmt, target=None, disp_at=None, flow=None):
        self.addr, self.size, self.raw, self.text, self.mnem = addr, size, raw, text, mnem
        self.known, self.fmt, self.target, self.disp_at, self.flow = known, fmt, target, disp_at, flow


def _fmt(name, ops):
    return name.ljust(8) + ' ' * (len(name) >= 8) + ops


def _m(name):
    return name.ljust(8) if len(name) < 8 else name + ' '


def _sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def _reg_operand(n, mode, fp=False):
    if mode == 'lit':
        return FPLIT.get(n, '?%d' % n) if fp else str(n)
    if mode == 'sf':
        return 'sf%d' % n
    return REGS[n]


def decode(buf, off, addr, relocs=()):
    """Decode one instruction at buf[off:]; returns an Insn. Never raises on bad opcodes.

    The reserved low bit of a CTRL word is accepted: the GNU toolchain sets it on calls and
    branches in compiled objects and the target is the displacement without it. relocs is unused
    here and kept for callers that pass it."""
    if off + 4 > len(buf):
        return Insn(addr, len(buf) - off, bytes(buf[off:]), '.byte ...', '.byte', False, 'trunc')
    w = struct.unpack_from('<I', buf, off)[0]
    op = w >> 24
    raw = bytes(buf[off:off + 4])

    def bad(why='word'):
        if w == 0:
            return Insn(addr, 4, raw, '.word   0x00000000', '.word', True, 'pad')
        if all(0x20 <= c < 0x7f or c == 0 for c in raw) and raw[0] and not raw[0] == 0:
            return Insn(addr, 4, raw, '.ascii  %r' % raw.rstrip(b'\0').decode('latin-1'), '.ascii', True, 'str')
        return Insn(addr, 4, raw, '.word   0x%08x' % w, '.word', False, why)

    if op < 0x20:
        if op in CTRL:
            name = CTRL[op]
            t = (w >> 1) & 1
            if op == 0x0a:
                return Insn(addr, 4, raw, 'ret', 'ret', True, 'CTRL', flow='ret')
            if 0x18 <= op < 0x20:          # fault<cc> takes no operand
                return Insn(addr, 4, raw, CTRL[op], CTRL[op], True, 'CTRL')
            tgt = (addr + _sx(w & 0x00fffffc, 24)) & 0xffffffff
            if 0x10 <= op < 0x18 and t:
                name += '.t'
            flow = {0x08: 'jmp', 0x09: 'call', 0x0b: 'call'}.get(op, 'cond' if 0x10 <= op < 0x18 else None)
            return Insn(addr, 4, raw, '%s0x%x' % (_m(name), tgt), CTRL[op], True, 'CTRL', tgt, flow=flow)
        return bad()
    if op < 0x30:
        if op in TEST:
            return Insn(addr, 4, raw, '%s%s' % (_m(TEST[op]), REGS[(w >> 19) & 31]), TEST[op], True, 'COBR')
        return bad()
    if op < 0x40:
        if op not in COBR:
            return bad()
        s1, s2 = (w >> 19) & 31, (w >> 14) & 31
        m1, sf2 = (w >> 13) & 1, w & 1
        t = (w >> 1) & 1
        tgt = (addr + _sx(w & 0x1ffc, 13)) & 0xffffffff
        name = COBR[op] + ('.t' if t else '')
        o1 = _reg_operand(s1, 'lit' if m1 else 'reg')
        o2 = _reg_operand(s2, 'sf' if sf2 else 'reg')
        return Insn(addr, 4, raw, '%s%s,%s,0x%x' % (_m(name), o1, o2, tgt), COBR[op], True, 'COBR', tgt, flow='cond')
    if op < 0x58:
        return bad()
    if 0x58 <= op < 0x80:
        key = ((w >> 20) & 0xff0) | ((w >> 7) & 0xf)
        ent = REG.get(key)
        if ent is None:
            return bad()
        name, sig = ent
        s1, s2, dd = w & 31, (w >> 14) & 31, (w >> 19) & 31
        m1, m2, m3 = (w >> 11) & 1, (w >> 12) & 1, (w >> 13) & 1
        sf1, sf2 = (w >> 5) & 1, (w >> 6) & 1
        if (m1 and sf1) or (m2 and sf2):
            return bad()
        fp = sig.startswith('F')
        o1 = _reg_operand(s1, 'sf' if sf1 else 'lit' if m1 else 'reg', fp and m1)
        o2 = _reg_operand(s2, 'sf' if sf2 else 'lit' if m2 else 'reg', fp and m2)
        if sig.endswith('m'):          # source and destination: a literal makes no sense
            if m3:
                return bad()
            o3 = REGS[dd]
        elif sig.endswith('D'):        # third operand is only read: M3 selects a literal
            o3 = str(dd) if m3 else REGS[dd]
        else:
            o3 = _reg_operand(dd, 'sf' if m3 else 'reg') if not fp else (FPLIT.get(dd, '?%d' % dd) if m3 else REGS[dd])
        ops = []
        for ch in sig.lstrip('F'):
            ops.append({'1': o1, '2': o2, 'd': o3, 'm': o3, 'D': o3}[ch])
        text = '%s%s' % (_m(name), ','.join(ops)) if ops else name
        flow = 'call' if name in ('calls',) else None
        return Insn(addr, 4, raw, text, name, True, 'REG', flow=flow)
    if op >= 0x80:
        ent = MEM.get(op)
        if ent is None:
            return bad()
        name, kind = ent
        sd, ab = (w >> 19) & 31, (w >> 14) & 31
        size = 4
        disp_at = None
        if not (w >> 12) & 1:      # MEMA
            off12 = w & 0xfff
            if (w >> 13) & 1:
                ea = '0x%x(%s)' % (off12, REGS[ab]) if off12 else '(%s)' % REGS[ab]
            else:
                ea = '0x%x' % off12
        else:                       # MEMB
            mode, scale, idx = (w >> 10) & 0xf, (w >> 7) & 7, w & 31
            if mode not in (4, 5, 7, 12, 13, 14, 15) or scale > 4:
                return bad()
            sc = '' if scale == 0 else '*%d' % (1 << scale)
            ix = '[%s%s]' % (REGS[idx], sc)
            d32 = None
            if mode in (5, 12, 13, 14, 15):
                if off + 8 > len(buf):
                    return Insn(addr, 4, raw, '.word   0x%08x' % w, '.word', False, 'trunc')
                d32 = struct.unpack_from('<I', buf, off + 4)[0]
                size = 8
                disp_at = addr + 4
                raw = bytes(buf[off:off + 8])
            if mode == 4:
                ea = '(%s)' % REGS[ab]
            elif mode == 5:
                ea = '0x%x' % ((addr + d32 + 8) & 0xffffffff)     # (IP) + displacement + 8
            elif mode == 7:
                ea = '(%s)%s' % (REGS[ab], ix)
            elif mode == 12:
                ea = '0x%x' % d32
            elif mode == 13:
                ea = '0x%x(%s)' % (d32, REGS[ab])
            elif mode == 14:
                ea = '0x%x%s' % (d32, ix)
            else:
                ea = '0x%x(%s)%s' % (d32, REGS[ab], ix)
        if kind == 'ld':
            text = '%s%s,%s' % (_m(name), ea, REGS[sd])
        elif kind == 'st':
            text = '%s%s,%s' % (_m(name), REGS[sd], ea)
        elif kind == 'ldea':
            text = '%s%s,%s' % (_m(name), ea, REGS[sd])
        else:
            text = '%s%s' % (_m(name), ea)
        flow = {'bx': 'jmp', 'balx': 'call', 'callx': 'call'}.get(name)
        # Absolute target of a call/branch through a plain displacement.
        target = None
        if name in ('callx', 'bx', 'balx') and (w >> 12) & 1 and ((w >> 10) & 0xf) == 12:
            target = d32
        return Insn(addr, size, raw, text, name, True, 'MEM', target, disp_at, flow)
    return bad()


class Coff:
    """Reader for the 32-bit i960 COFF object (little-endian, magic 0x0160)."""

    def __init__(self, data, base=0):
        self.data, self.base = data, base
        (self.magic, self.nscns, self.timdat, self.symptr, self.nsyms, self.opthdr,
         self.flags) = struct.unpack_from('<HHIIIHH', data, base)
        if self.magic not in (0x160, 0x161):
            raise ValueError('not an i960 COFF object (magic 0x%04x at 0x%x)' % (self.magic, base))
        o = base + 20 + self.opthdr
        self.sections = []
        for i in range(self.nscns):
            name = data[o:o + 8].split(b'\0')[0].decode('latin-1')
            (paddr, vaddr, size, scnptr, relptr, lnnoptr, nreloc, nlnno, sflags,
             salign) = struct.unpack_from('<IIIIIIHHII', data, o + 8)
            self.sections.append(dict(name=name, vaddr=vaddr, size=size, scnptr=scnptr, relptr=relptr,
                                      nreloc=nreloc, flags=sflags, align=salign, index=i + 1))
            o += 44
        self._read_symbols()

    def section(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        raise KeyError(name)

    def section_bytes(self, s):
        a = self.base + s['scnptr']
        return self.data[a:a + s['size']]

    SYMESZ = 24     # name 8, value 4, scnum 2, flags 2, type 4, sclass 1, numaux 1, pad 2

    def _read_symbols(self):
        d, b, z = self.data, self.base, self.SYMESZ
        st = b + self.symptr + z * self.nsyms
        strtab = d[st:st + struct.unpack_from('<I', d, st)[0]] if st + 4 <= len(d) else b''
        self.symbols = []
        i = 0
        while i < self.nsyms:
            e = b + self.symptr + z * i
            if d[e:e + 4] == b'\0\0\0\0':
                so = struct.unpack_from('<I', d, e + 4)[0]
                name = strtab[so:strtab.index(b'\0', so)].decode('latin-1')
            else:
                name = d[e:e + 8].split(b'\0')[0].decode('latin-1')
            value, scnum, flags, typ, sclass, naux = struct.unpack_from('<IhHIBB', d, e + 8)
            self.symbols.append(dict(name=name, value=value, scnum=scnum, flags=flags, type=typ,
                                     sclass=sclass, naux=naux, index=i))
            i += 1 + naux

    def sym_by_index(self, idx):
        for s in self.symbols:
            if s['index'] == idx:
                return s
        return None

    def relocs(self, s):
        """Relocations of a section as (address, symbol index, type), 12-byte entries."""
        out = []
        for k in range(s['nreloc']):
            a = self.base + s['relptr'] + 12 * k
            vaddr, symndx, rtype = struct.unpack_from('<IIH', self.data, a)
            out.append((vaddr, symndx, rtype))
        return out


def symbol_map(coff, section):
    """Address -> name for function and label symbols defined in the section."""
    m = {}
    for s in coff.symbols:
        if s['scnum'] == section['index'] and s['sclass'] in (2, 3, 6, 108, 113) and not s['name'].startswith('.'):
            m.setdefault(s['value'], s['name'])
    return m


def disassemble(buf, base, start=None, end=None, syms=None, relocs=None, coff=None):
    """Yield Insn for buf (loaded at base) between start and end addresses."""
    start = base if start is None else start
    end = base + len(buf) if end is None else end
    pc = start
    while pc < end:
        i = decode(buf, pc - base, pc, relocs or ())
        if not i.known and i.fmt == 'word':
            v = struct.unpack_from('<I', i.raw, 0)[0]
            if base <= v < base + len(buf) and v % 4 == 0:     # switch tables hold section addresses
                i.known, i.fmt, i.mnem = True, 'jt', '.word'
                i.text = '.word   0x%08x' % v
        yield i
        pc += i.size if i.size else 4


def format_listing(insns, syms, relocs, coff):
    rel_by_addr = {}
    for vaddr, symndx, rtype in relocs:
        rel_by_addr[vaddr] = (symndx, rtype)
    lines = []
    for i in insns:
        if syms and i.addr in syms:
            lines.append('\n%s:' % syms[i.addr])
        note = ''
        for a in range(i.addr, i.addr + i.size):
            if a in rel_by_addr and coff is not None:
                sy = coff.sym_by_index(rel_by_addr[a][0])
                note = '; reloc -> %s' % (sy['name'] if sy else '#%d' % rel_by_addr[a][0])
        if not note and i.target is not None and syms and i.target in syms:
            note = '; -> %s' % syms[i.target]
        words = ' '.join('%08x' % struct.unpack_from('<I', i.raw, k)[0] for k in range(0, len(i.raw) - 3, 4))
        lines.append('%08x: %-17s %-34s %s' % (i.addr, words, i.text, note))
    return '\n'.join(lines)


def check(insns):
    n, unk = 0, []
    fmts = {}
    for i in insns:
        n += 1
        fmts[i.fmt] = fmts.get(i.fmt, 0) + 1
        if not i.known:
            unk.append(i)
    return n, fmts, unk


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file')
    ap.add_argument('--coff-offset', type=lambda x: int(x, 0), default=0)
    ap.add_argument('--section', default='.text')
    ap.add_argument('--raw', action='store_true')
    ap.add_argument('--base', type=lambda x: int(x, 0), default=0)
    ap.add_argument('--from', dest='start', type=lambda x: int(x, 0))
    ap.add_argument('--to', dest='end', type=lambda x: int(x, 0))
    ap.add_argument('--no-syms', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--strict', action='store_true')
    a = ap.parse_args(argv)
    data = open(a.file, 'rb').read()
    coff = None
    if a.raw:
        buf, base, syms, relocs = data, a.base, {}, []
    else:
        coff = Coff(data, a.coff_offset)
        s = coff.section(a.section)
        buf, base = coff.section_bytes(s), s['vaddr']
        syms = {} if a.no_syms else symbol_map(coff, s)
        relocs = coff.relocs(s)
    insns = list(disassemble(buf, base, a.start, a.end, relocs=frozenset(r[0] for r in relocs)))
    if a.check:
        n, fmts, unk = check(insns)
        print('instructions %d  formats %s  unknown %d' % (n, dict(sorted(fmts.items())), len(unk)))
        for i in unk:
            print('  %08x  %s' % (i.addr, i.text))
        return 1 if (unk and a.strict) else 0
    print(format_listing(insns, syms, relocs, coff))
    return 0


if __name__ == '__main__':
    sys.exit(main())
