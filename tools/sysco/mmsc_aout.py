#!/usr/bin/env python3
"""Load the MMSC firmware image: segment map, nlist symbols, byte self-check.

mmscfw.bin is a little-endian 486 a.out (magic 0407, a single image with no
page padding) followed by a BSD symbol table. This module is the one parser;
the Ghidra import script reads the table it writes, so the two cannot disagree
about where anything lands.

    mmsc_aout.py IMAGE --segments          segment map
    mmsc_aout.py IMAGE --check             byte-level self-check, exit 1 on a failure
    mmsc_aout.py IMAGE --tsv OUT           segments and symbols for MmscAoutImport.java
    mmsc_aout.py IMAGE --disasm NAME|0xADDR [--count N]
                                           capstone linear disassembly of one routine
    mmsc_aout.py IMAGE --symbols           every nlist entry, one line each

Layout, from the 32-byte header (eight little-endian words: magic, text size,
data size, bss size, symbol bytes, entry, relocation sizes) and from the table:

  text   file offset 32,                  loads at the entry address
  data   file offset 32 + text size,      loads at the end of text, unpadded
  bss    no file bytes,                   follows data
  nlist  12-byte records after the data,  7,907 of them in the 2.3 image
  names  after the records, led by a four-byte length that counts itself

The loader needs no relocation: the two relocation-size words are not sizes
(the first holds the constant 0x5aa5a55a, the second is zero) and the image is
linked at its load address. The self-check measures the claims that follow
from that; it does not take them on the header's word.

Python 3, standard library only; --disasm needs capstone.
"""

import argparse
import struct
import sys
from dataclasses import dataclass

HEADER = struct.Struct('<8I')
NLIST = struct.Struct('<IBbhI')
OMAGIC = 0o407

# Debug records (stab types, the high three bits of the type byte) by number.
STABS = {0x20: 'gsym', 0x24: 'fun', 0x26: 'stsym', 0x28: 'lcsym', 0x40: 'stab40',
         0x44: 'sline', 0x64: 'so', 0x80: 'lsym', 0xa0: 'psym', 0xc0: 'lbrac',
         0xe0: 'rbrac'}
# Names the compiler and assembler plant at the start of each object, and the
# object file's own path; they label a position, not a routine or a variable.
MARKERS = ('gcc2_compiled.', '___gnu_compiled_c', '.text', '.data', '.bss')


class ImageError(Exception):
    pass


@dataclass
class Symbol:
    index: int
    name: str
    kind: str          # text data bss abs stab
    glob: bool
    value: int
    stab: str = ''
    marker: bool = False
    size: int = 0      # distance to the next symbol of the same segment; inferred


@dataclass
class Segment:
    name: str
    addr: int
    size: int
    fileoff: int       # -1 for bss


class Image:
    def __init__(self, blob):
        if len(blob) < HEADER.size:
            raise ImageError('shorter than the 32-byte header')
        self.blob = blob
        (self.magic, self.text, self.data, self.bss, self.syms, self.entry,
         self.trsize, self.drsize) = HEADER.unpack_from(blob)
        if self.magic != OMAGIC:
            raise ImageError('magic %#o, not an OMAGIC a.out' % self.magic)
        self.symoff = HEADER.size + self.text + self.data
        self.stroff = self.symoff + self.syms
        if self.syms % NLIST.size or self.stroff + 4 > len(blob):
            raise ImageError('symbol table does not fit the file')
        self.strsize = struct.unpack_from('<I', blob, self.stroff)[0]
        self.segments = [
            Segment('text', self.entry, self.text, HEADER.size),
            Segment('data', self.entry + self.text, self.data,
                    HEADER.size + self.text),
            Segment('bss', self.entry + self.text + self.data, self.bss, -1),
        ]
        self.symbols = self._read_symbols()

    def _name(self, strx):
        base = self.stroff + strx
        end = self.blob.find(b'\0', base)
        if strx >= self.strsize or end < 0 or end >= self.stroff + self.strsize:
            raise ImageError('name offset %#x outside the string table' % strx)
        return self.blob[base:end].decode('latin1')

    def _read_symbols(self):
        out = []
        for i in range(self.syms // NLIST.size):
            strx, typ, _other, _desc, value = NLIST.unpack_from(
                self.blob, self.symoff + i * NLIST.size)
            name = self._name(strx)
            if typ & 0xe0:
                out.append(Symbol(i, name, 'stab', False, value,
                                  STABS.get(typ & 0xfe, 'stab%02x' % typ)))
                continue
            kind = {2: 'abs', 4: 'text', 6: 'data', 8: 'bss'}.get(typ & 0x1e)
            if kind is None:
                raise ImageError('entry %d: type %#x' % (i, typ))
            out.append(Symbol(i, name, kind, bool(typ & 1), value,
                              marker=name in MARKERS or name.endswith('.o')))
        for kind in ('text', 'data', 'bss'):
            seg = self.segment(kind)
            addrs = sorted({s.value for s in out if s.kind == kind})
            addrs.append(seg.addr + seg.size)
            nxt = {a: b for a, b in zip(addrs, addrs[1:])}
            for s in out:
                if s.kind == kind and s.value in nxt:
                    s.size = max(nxt[s.value] - s.value, 0)
        return out

    def segment(self, name):
        return next(s for s in self.segments if s.name == name)

    def offset(self, addr):
        """File offset of a text or data address, or None (bss, outside)."""
        for s in self.segments:
            if s.fileoff >= 0 and s.addr <= addr < s.addr + s.size:
                return s.fileoff + addr - s.addr
        return None

    def read(self, addr, n):
        off = self.offset(addr)
        if off is None:
            raise ImageError('%#x is not in a loaded segment' % addr)
        return self.blob[off:off + n]

    def find(self, name):
        hits = [s for s in self.symbols if s.name == name and s.kind != 'stab']
        return hits


def check(img):
    """Byte-level checks. Returns (list of (name, ok, detail))."""
    res = []

    def add(name, ok, detail):
        res.append((name, bool(ok), detail))

    text, data, bss = img.segments
    add('file size',
        img.stroff + img.strsize == len(img.blob),
        'symbols end at %#x + string table %#x = %#x, file is %#x'
        % (img.stroff, img.strsize, img.stroff + img.strsize, len(img.blob)))
    add('relocation words are not sizes',
        img.drsize == 0 and img.trsize == 0x5aa5a55a,
        'header words %#x and %#x' % (img.trsize, img.drsize))
    add('entry is the first routine',
        any(s.name == '_sysInit' and s.value == img.entry for s in img.symbols),
        'entry %#x' % img.entry)

    ends = {'_etext': text.addr + text.size, '_edata': data.addr + data.size,
            '_end': bss.addr + bss.size}
    for n, want in ends.items():
        got = [s.value for s in img.find(n)]
        add('%s closes its segment' % n, got == [want],
            '%s = %s, segment ends at %#x' % (n, [hex(g) for g in got], want))

    stray = {}
    for s in img.symbols:
        if s.kind in ('text', 'data', 'bss'):
            seg = img.segment(s.kind)
            lo, hi = seg.addr, seg.addr + seg.size
            # _etext, _edata and _end sit one past their segment, and a bss
            # symbol may follow data's end address, so allow the end itself.
            if not lo <= s.value <= hi:
                stray.setdefault(s.kind, []).append(s.name)
    add('symbols lie inside their segment', not stray,
        'outside: %s' % {k: v[:3] for k, v in stray.items()} if stray
        else 'text, data and bss symbols all inside')

    # A text symbol that begins a compiled routine starts with the frame
    # prologue; count it as evidence the text base is right, not as a rule.
    pro = tot = 0
    for s in img.symbols:
        if s.kind == 'text' and s.glob and s.name.startswith('_') \
                and text.addr <= s.value < text.addr + text.size:
            tot += 1
            pro += img.read(s.value, 3) == b'\x55\x89\xe5'
    add('exported text symbols start a routine', pro * 2 > tot,
        '%d of %d begin push ebp; mov ebp,esp' % (pro, tot))

    # Data placement. Three independent measurements agree on a base only if
    # the data bytes sit where the symbols say.
    # Both are pointers kept in data that lead to a string held in data, so one
    # check covers the symbol's own bytes and the address it names.
    for n, want in (('_vxWorksVersion', b'5.3\0'), ('_creationDate', None)):
        for s in img.find(n):
            ptr = struct.unpack('<I', img.read(s.value, 4))[0]
            got = img.read(ptr, 24).split(b'\0')[0] + b'\0'
            ok = got == want if want else (
                got[3:4] == b' ' and got[:3].isalpha() and len(got) > 12)
            add('%s points at its string' % n, ok,
                'word at %#x is %#x, which reads %r' % (s.value, ptr, got[:-1]))
    for s in img.find('_sysRomSignature'):
        got = img.read(s.value, 2)
        add('_sysRomSignature holds the 55 aa ROM mark', got == b'\x55\xaa',
            'at %#x reads %s' % (s.value, got.hex()))

    best = {}
    dend = data.addr + data.size
    dbytes = img.blob[data.fileoff:data.fileoff + data.size]
    for k in range(-4, 5):
        base = data.addr + 4 * k
        best[base] = _string_pointers(dbytes, base)
    best[0x1000 * -(-data.addr // 0x1000)] = _string_pointers(
        dbytes, 0x1000 * -(-data.addr // 0x1000))
    rival = max(v for b, v in best.items() if b != data.addr)
    add('data base fits its own string pointers',
        best[data.addr] >= 10 and best[data.addr] >= 3 * rival,
        'aligned data words that point at a string, by assumed base: %s'
        % ', '.join('%#x:%d' % (b, v) for b, v in sorted(best.items())
                    if v or b == data.addr))

    # Immediate operands in text that equal a data or bss symbol exactly; the
    # symbol values and the code agree on the layout when many do.
    want = {s.value for s in img.symbols
            if s.kind in ('data', 'bss') and s.value < dend + bss.size}
    hits = 0
    tb = img.blob[text.fileoff:text.fileoff + text.size]
    for i in range(len(tb) - 4):
        if tb[i] in (0x68, 0xa1, 0xa3) or 0xb8 <= tb[i] <= 0xbf:
            hits += struct.unpack_from('<I', tb, i + 1)[0] in want
    add('code addresses data symbols exactly', hits > 1000,
        '%d operands after push, mov or moffs opcodes equal a data or bss symbol'
        % hits)
    return res


def _string_pointers(dbytes, base):
    n = 0
    for i in range(0, len(dbytes) - 3, 4):
        v = struct.unpack_from('<I', dbytes, i)[0]
        o = v - base
        if 0 < o < len(dbytes) - 4 and dbytes[o - 1] == 0 \
                and all(32 <= c < 127 for c in dbytes[o:o + 4]):
            n += 1
    return n


def write_tsv(img, out):
    out.write('# mmscfw a.out load map. SEG name address fileoffset size;\n'
              '# SYM address size name kind scope. Size is the gap to the next\n'
              '# symbol of the segment: inferred, not recorded in the table.\n')
    for s in img.segments:
        out.write('SEG\t%s\t%#x\t%d\t%d\n' % (s.name, s.addr, s.fileoff, s.size))
    for s in sorted((s for s in img.symbols if s.kind in ('text', 'data', 'bss')
                     and not s.marker), key=lambda s: (s.value, s.index)):
        out.write('SYM\t%#x\t%d\t%s\t%s\t%s\n'
                  % (s.value, s.size, s.name, s.kind,
                     'global' if s.glob else 'local'))


def disasm(img, target, count):
    try:
        import capstone
    except ImportError:
        raise ImageError('capstone is not installed (run in the toolchain image)')
    if target.lower().startswith('0x'):
        addr, name = int(target, 16), target
        size = 0
        for s in img.symbols:
            if s.kind == 'text' and s.value == addr and not s.marker:
                size, name = s.size, s.name
                break
    else:
        hits = [s for s in img.find(target) if s.kind == 'text']
        if not hits:
            raise ImageError('no text symbol %s' % target)
        addr, size, name = hits[0].value, hits[0].size, hits[0].name
    size = size or 64
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lines = ['; %s at %#x, %d bytes (size inferred from the next symbol)'
             % (name, addr, size)]
    for n, i in enumerate(md.disasm(img.read(addr, size), addr)):
        if count and n >= count:
            break
        lines.append('%08x  %-24s %s %s' % (i.address, i.bytes.hex(),
                                            i.mnemonic, i.op_str))
    return '\n'.join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('image')
    ap.add_argument('--segments', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--symbols', action='store_true')
    ap.add_argument('--tsv', metavar='OUT')
    ap.add_argument('--disasm', metavar='NAME|0xADDR')
    ap.add_argument('--count', type=int, default=0)
    a = ap.parse_args(argv)
    try:
        with open(a.image, 'rb') as f:
            img = Image(f.read())
        if a.segments:
            for s in img.segments:
                print('%-5s %#08x-%#08x  %7d bytes  file offset %s' % (
                    s.name, s.addr, s.addr + s.size, s.size,
                    s.fileoff if s.fileoff >= 0 else '-'))
            print('%d nlist records at file offset %#x' % (
                img.syms // NLIST.size, img.symoff))
        if a.symbols:
            for s in img.symbols:
                print('%5d %-5s %-6s %08x %s' % (s.index, s.kind,
                      s.stab or ('G' if s.glob else 'L'), s.value, s.name))
        if a.tsv:
            with open(a.tsv, 'w') as out:
                write_tsv(img, out)
        if a.disasm:
            print(disasm(img, a.disasm, a.count))
        if a.check:
            bad = 0
            for name, ok, detail in check(img):
                print('%s  %s: %s' % ('ok  ' if ok else 'FAIL', name, detail))
                bad += not ok
            return 1 if bad else 0
    except ImageError as e:
        print('mmsc_aout: %s' % e, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
