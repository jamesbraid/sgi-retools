#!/usr/bin/env python3
"""Unpack a promgen64 PROM container into one flat file per segment.

Usage: promgen64.py IMAGE OUTDIR LABEL

Layout (read from the image itself
decoder): the container header fills the first 0x1000 bytes; the eight-byte magic is at 0x40;
the segment count is the word at 0x7c; segment records start at 0x80, 0x80 bytes apart, each a
16-byte name then big-endian 64-bit flags, file offset, entry, load address, unpacked length,
packed length, two checksums and the length with bss. A segment whose packed length is below
its unpacked length is gzip. Writes OUTDIR/LABEL.<segment>.bin and prints one line per segment:
name, load address, entry, length, whether it checksummed (additive byte sum against the header).
"""
import gzip
import struct
import sys


def main():
    img, out, label = sys.argv[1:4]
    d = open(img, 'rb').read()
    (nseg,) = struct.unpack_from('>I', d, 0x7c)
    for i in range(min(nseg, 8)):
        b = 0x80 + i * 0x80
        name = d[b:b + 16].split(b'\0')[0].decode('latin-1')
        flags, off, entry, load, length, packed, tsum, csum, withbss = struct.unpack_from('>9Q', d, b + 16)
        gz = 0 < packed < length
        raw = d[off:off + (packed if gz else length)]
        data = gzip.decompress(raw) if gz else raw
        ok = len(data) == length and (sum(data) & 0xffffffff) == (tsum & 0xffffffff)
        path = '%s/%s.%s.bin' % (out, label, name)
        open(path, 'wb').write(data)
        print('%s load=%#x entry=%#x length=%#x packed=%#x checksum=%s -> %s' % (name, load, entry, length, packed, 'ok' if ok else 'MISMATCH', path))


if __name__ == '__main__':
    main()
