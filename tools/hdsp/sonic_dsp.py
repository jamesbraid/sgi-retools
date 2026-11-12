#!/usr/bin/env python3
"""Reader for the Sonic Solutions DSP program resource file (a Macintosh resource fork).

Usage: python3 -I tools/hdsp/sonic_dsp.py FILE list [TYPE]
       python3 -I tools/hdsp/sonic_dsp.py FILE image NAME            # segments and symbol counts
       python3 -I tools/hdsp/sonic_dsp.py FILE dis NAME [--space P] [--check]
       python3 -I tools/hdsp/sonic_dsp.py FILE syms NAME [--space X]

The file holds four resource types of interest:
  UCDE  an image: be16 version, be16 count, then 72-byte entries {type[4], zero padding, id be16
        at entry offset 70} naming the USYM tables and UPGM segments that make up the image; the
        resource name is the image name (img_p0 and so on).
  UPGM  a segment: be16 space (1 X, 2 Y, 3 P), be16 word count, be32 start address, then the
        words as be32 values holding 24-bit DSP words.
  USYM  the symbols of one space: be16 space, be16 count, then 36-byte entries {name[32], be32
        value}.
Every segment is length-checked (8 + 4 n bytes); a mismatch raises ValueError.

`dis` decodes the P-space segments with tools/hdsp/dsp56300dis.py (it has to exist next to this
file) and, with --check, reports the words that did not decode. The decoder is told where each
segment starts, so a segment is decoded on its own.
"""
import argparse
import os
import struct
import sys

SPACES = {1: 'X', 2: 'Y', 3: 'P'}


def parse_fork(data):
    """Return a list of (type, id, name, offset, length) for every resource in the fork."""
    do, mo, dl, ml = struct.unpack('>IIII', data[:16])
    m = data[mo:mo + ml]
    tloff, nloff = struct.unpack('>HH', m[24:28])
    nt = struct.unpack('>H', m[tloff:tloff + 2])[0] + 1
    out = []
    for i in range(nt):
        t = m[tloff + 2 + 8 * i:tloff + 2 + 8 * i + 8]
        typ = t[:4].decode('latin-1')
        cnt = struct.unpack('>H', t[4:6])[0] + 1
        ro = struct.unpack('>H', t[6:8])[0]
        for j in range(cnt):
            r = m[tloff + ro + 12 * j:tloff + ro + 12 * j + 12]
            rid, noff = struct.unpack('>hH', r[:4])
            aoff = struct.unpack('>I', b'\0' + r[5:8])[0]
            name = ''
            if noff != 0xffff:
                n = m[nloff + noff]
                name = m[nloff + noff + 1:nloff + noff + 1 + n].decode('latin-1')
            pos = do + aoff
            ln = struct.unpack('>I', data[pos:pos + 4])[0]
            out.append((typ, rid, name, pos + 4, ln))
    return out


class Resources:
    def __init__(self, data):
        self.data = data
        self.list = parse_fork(data)
        self.by_key = {(t, i): (n, o, l) for t, i, n, o, l in self.list}

    def body(self, typ, rid):
        n, o, l = self.by_key[(typ, rid)]
        return self.data[o:o + l]

    def images(self):
        return {n: i for t, i, n, o, l in self.list if t == 'UCDE'}

    def image_parts(self, name):
        """The (type, id) members of an image, in the order its UCDE lists them."""
        rid = self.images()[name]
        b = self.body('UCDE', rid)
        _ver, cnt = struct.unpack('>HH', b[:4])
        parts = []
        for k in range(cnt):
            e = b[4 + 72 * k:4 + 72 * (k + 1)]
            parts.append((e[:4].decode('latin-1'), struct.unpack('>h', e[70:72])[0]))
        return parts

    def segment(self, rid):
        b = self.body('UPGM', rid)
        space, n, start = struct.unpack('>HHI', b[:8])
        if len(b) != 8 + 4 * n:
            raise ValueError('UPGM %d: length %d, expected %d' % (rid, len(b), 8 + 4 * n))
        words = [w & 0xffffff for w in struct.unpack('>%dI' % n, b[8:])]
        return space, start, words

    def symbols(self, rid):
        b = self.body('USYM', rid)
        space, n = struct.unpack('>HH', b[:4])
        out = []
        for k in range(n):
            e = b[4 + 36 * k:4 + 36 * (k + 1)]
            out.append((e[:32].split(b'\0')[0].decode('latin-1'), struct.unpack('>I', e[32:36])[0]))
        return space, out

    def image(self, name):
        """(segments, symbols) of an image: segments [(space, start, words)], symbols {space: [(name, value)]}."""
        segs, syms = [], {}
        for typ, rid in self.image_parts(name):
            if typ == 'UPGM':
                segs.append(self.segment(rid))
            elif typ == 'USYM':
                sp, s = self.symbols(rid)
                syms.setdefault(sp, []).extend(s)
        return segs, syms


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file')
    ap.add_argument('cmd', choices=['list', 'image', 'dis', 'syms'])
    ap.add_argument('name', nargs='?')
    ap.add_argument('--space', default=None)
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args(argv)
    with open(a.file, 'rb') as f:
        r = Resources(f.read())
    if a.cmd == 'list':
        for t, i, n, o, l in r.list:
            if a.name is None or t == a.name:
                print(t, i, repr(n), o, l)
        return 0
    if a.name is None:
        ap.error('%s needs an image NAME' % a.cmd)
    if a.name not in r.images():
        ap.error('no image named %r (try the list command with type UCDE)' % a.name)
    segs, syms = r.image(a.name)
    if a.cmd == 'image':
        for sp, st, w in segs:
            print('%s start 0x%06x words %d' % (SPACES.get(sp, sp), st, len(w)))
        for sp, s in sorted(syms.items()):
            print('symbols %s: %d' % (SPACES.get(sp, sp), len(s)))
    elif a.cmd == 'syms':
        for sp, s in sorted(syms.items()):
            if a.space and SPACES.get(sp) != a.space.upper():
                continue
            for n, v in sorted(s, key=lambda x: x[1]):
                print('%s:%06x %s' % (SPACES.get(sp, sp), v, n))
    else:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import dsp56300dis as dd
        names = {}
        for n, v in syms.get(3, []):
            names.setdefault(v, n)
        bad = []
        for sp, st, w in segs:
            if SPACES.get(sp) != (a.space or 'P').upper():
                continue
            for ins in dd.decode_stream(w, st):
                if not ins.valid:
                    bad.append((ins.address, ins.words))
                if not a.check:
                    print('%06x: %-20s %s%s' % (ins.address, ' '.join('%06x' % x for x in ins.words), ins.text,
                                                '   ; ' + names[ins.address] if ins.address in names else ''))
        if a.check:
            print('undecoded words: %d' % len(bad))
            for addr, raw in bad[:50]:
                print('  %06x %06x' % (addr, raw[0]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
