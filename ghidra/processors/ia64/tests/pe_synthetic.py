#!/usr/bin/env python3
"""A synthetic IA-64 PE32+ image and the symbols IA64Pe.java must give it.

  pe_synthetic.py write DIR      write DIR/synthetic.efi
  pe_synthetic.py check SYMS BASE   check DumpSymbols.java's output for it, loaded or moved to BASE
  pe_synthetic.py            build the image and check its own layout (no Ghidra)

The image has an entry point and one export that are function descriptors ({entry, gp}),
a function only .pdata names, DIR64 base relocations for each descriptor word, and a gp
past the end of the image, as the real EFI drivers have. No firmware bytes.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import synthetic as syn  # noqa: E402

PREFERRED = 0x10000000
TEXT, RDATA, PDATA, RELOC = 0x1000, 0x2000, 0x3000, 0x4000
GP = 0x8000          # an RVA past SizeOfImage
SIZE_OF_IMAGE = 0x5000
EXPORT = 'fn'


def code():
    """A at 0 (returns 5), B at 0x20 (the status function), C at 0x40 (a bare return)."""
    a = [syn.bundle(0x11, syn.NOP_M, syn.adds(8, 5), syn.BR_RET)]
    a += [syn.bundle(0x01, syn.NOP_M, syn.NOP_I, syn.NOP_I)]
    b = syn.status_function()
    c = [syn.bundle(0x17, syn.BR_RET, syn.NOP_B, syn.NOP_B)]
    return b''.join(a + b + c)


def pad(b, n):
    return b + bytes(n - len(b))


def rdata():
    d = bytearray(0x200)
    # entry descriptor at 0, export descriptor at 0x10
    struct.pack_into('<QQ', d, 0, PREFERRED + TEXT, PREFERRED + GP)
    struct.pack_into('<QQ', d, 0x10, PREFERRED + TEXT + 0x20, PREFERRED + GP)
    # export directory at 0x20: one function, one name
    struct.pack_into('<IIHHIIIIIII', d, 0x20, 0, 0, 0, 0, RDATA + 0x80, 1, 1, 1,
                     RDATA + 0x60, RDATA + 0x64, RDATA + 0x68)
    struct.pack_into('<I', d, 0x60, RDATA + 0x10)       # function RVA: the descriptor
    struct.pack_into('<I', d, 0x64, RDATA + 0x70)       # name RVA
    struct.pack_into('<H', d, 0x68, 0)                  # ordinal index
    d[0x70:0x70 + len(EXPORT) + 1] = EXPORT.encode() + b'\0'
    d[0x80:0x84] = b'syn\0'
    return bytes(d)


def pdata():
    d = b''
    for begin, end in ((0, 0x20), (0x20, 0x40), (0x40, 0x50)):
        d += struct.pack('<III', TEXT + begin, TEXT + end, RDATA)
    return pad(d, 0x200)


def reloc():
    ents = b''.join(struct.pack('<H', (10 << 12) | o) for o in (0, 8, 0x10, 0x18))
    blk = struct.pack('<II', RDATA, 8 + len(ents)) + ents
    return pad(blk, 0x200)


def image():
    sections = [(b'.text', TEXT, pad(code(), 0x200), 0x60000020),
                (b'.rdata', RDATA, rdata(), 0x40000040),
                (b'.pdata', PDATA, pdata(), 0x40000040),
                (b'.reloc', RELOC, reloc(), 0x42000040)]
    hdr_size = 0x200
    dirs = [(0, 0)] * 16
    dirs[0] = (RDATA + 0x20, 0x40)
    dirs[3] = (PDATA, 36)
    dirs[5] = (RELOC, 8 + 8)
    dirs[8] = (GP, 0)
    opt = struct.pack('<HBBIIIIIQIIHHHHHHIIIIHHQQQQII', 0x20b, 2, 0, 0x200, 0x600, 0, RDATA, TEXT,
                      PREFERRED, 0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, SIZE_OF_IMAGE, hdr_size, 0,
                      12, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b''.join(struct.pack('<II', *x) for x in dirs)
    assert len(opt) == 240, len(opt)
    coff = struct.pack('<HHIIIHH', 0x200, len(sections), 0, 0, 0, 240, 0x2022)
    out = bytearray(b'MZ' + bytes(0x3a) + struct.pack('<I', 0x40) + b'PE\0\0' + coff + opt)
    off = hdr_size
    body = b''
    for name, rva, data, ch in sections:
        out += struct.pack('<8sIIIIIIHHI', name, len(data), rva, len(data), off, 0, 0, 0, 0, ch)
        body += data
        off += len(data)
    return pad(bytes(out), hdr_size) + body


def expect(base):
    """(kind, address, name) lines that must appear, for the image at BASE."""
    return [('function', base + TEXT, 'entry'), ('function', base + TEXT + 0x20, EXPORT),
            ('function', base + TEXT + 0x40, None),
            ('label', base + RDATA, 'entry_descriptor'), ('label', base + RDATA + 0x10, EXPORT + '_descriptor')]


def check(path, base):
    seen, r1 = set(), []
    for line in open(path):
        f = line.rstrip('\n').split('\t')
        if f[0] in ('function', 'label'):
            seen.add((f[0], int(f[1].split(':')[-1], 16), f[2]))
        elif f[0] == 'r1':
            r1.append((int(f[1].split(':')[-1], 16), int(f[2].split(':')[-1], 16), f[3]))
    bad = []
    for kind, a, name in expect(base):
        if not any(k == kind and x == a and (name is None or n == name) for k, x, n in seen):
            bad.append('%s %#x %s missing' % (kind, a, name or ''))
    want = '%x' % (base + GP)
    if not r1 or any(v != want for _, _, v in r1) or not any(lo <= base + TEXT <= hi for lo, hi, _ in r1):
        bad.append('r1 over the code is not %s: %s' % (want, r1))
    for b in bad:
        print('FAIL pe: ' + b)
    print('%s: PE entry and export resolved through their descriptors at base %#x, gp %s'
          % ('ok' if not bad else 'FAIL', base, want))
    return 1 if bad else 0


def main():
    if len(sys.argv) == 1:
        d = image()
        assert d[:2] == b'MZ' and d[0x44:0x46] == b'\x00\x02' and len(d) % 0x200 == 0
        print('ok: pe image builds, %d bytes' % len(d))
        return 0
    if sys.argv[1] == 'write':
        os.makedirs(sys.argv[2], exist_ok=True)
        with open(os.path.join(sys.argv[2], 'synthetic.efi'), 'wb') as f:
            f.write(image())
        return 0
    if sys.argv[1] == 'check':
        return check(sys.argv[2], int(sys.argv[3], 0))
    sys.exit(__doc__)


if __name__ == '__main__':
    sys.exit(main())
