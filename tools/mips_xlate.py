#!/usr/bin/env python3
"""Decode the `.MIPS.Xlate` section of a linked MIPS ELF image.

A library that was reordered after its debug information was written (the IRIX linker's procedure
reordering) carries `.MIPS.Xlate`, a table that maps each routine's address before the reorder, the one
DWARF still gives, to its address in the image. The section type is SHT_MIPS_XLATE (0x7000000e). No
published layout was found, so this decode comes from the sections themselves and is checked against the
dynamic symbol tables (see test_mips_xlate.py and the figures in the commit that added it).

Layout, all fields big-endian:

  header   0x48 bytes in an ELF32 image, 0x80 in an ELF64 image. Words are 4 bytes in ELF32 and the
           address fields are 8 bytes in ELF64:
             ELF32 offset  ELF64 offset  content
             0x00          0x00          a small version number (5 in ELF32, 6 in ELF64 images)
             0x14          0x1c          range count (4 bytes), also stored whole at 0x3c / 0x68
             0x18, 0x1c    0x20, 0x28    LO, HI: the first and the last-plus-one address of the new layout
             0x20, 0x24    0x30, 0x38    LO, EXT: EXT is HI in some images and later than HI in others
             0x34, 0x38    0x58, 0x60    LO twice
             0x3c          0x68          range count
             0x40, 0x44    0x70, 0x78    LO, EXT again
  records  `count` pairs of LEB128 integers, then zero padding to the end of the section:
             A  unsigned, the length of range j in the new layout, in 4-byte words
             B  signed, the move of range j's old start from the previous range's old start, in words

Range j therefore spans new [LO + 4 * sum(A[:j]), + 4 * A[j]) and starts at old LO + 4 * sum(B[:j + 1]).
Range 0 is the lazy-binding stub area, which did not move (B[0] is 0). The ranges tile the new layout
exactly: the last range ends at HI. A routine's old address is the start of a range, or inside one if
the debug information puts it there; the distance from the range start is kept.
"""
import bisect
import struct

SHT_MIPS_XLATE = 0x7000000e


class Xlate:
    def __init__(self, lo, hi, ranges):
        self.lo, self.hi = lo, hi
        # (old_start, new_start, length in bytes) in old-address order
        self.ranges = sorted(ranges)
        self._olds = [r[0] for r in self.ranges]

    def translate(self, old, size=0):
        """The address in the image of the code DWARF puts at `old`, or None when no range holds it. With a
        `size`, the whole of [old, old + size) has to lie in that one range, or the result is None."""
        i = bisect.bisect_right(self._olds, old) - 1
        if i < 0:
            return None
        o, n, length = self.ranges[i]
        return n + (old - o) if old - o + size <= length and old - o < length else None


def _leb(data, i, signed):
    v = shift = 0
    while True:
        if i >= len(data):
            raise ValueError('truncated')
        c = data[i]
        i += 1
        v |= (c & 0x7f) << shift
        shift += 7
        if not c & 0x80:
            if signed and c & 0x40:
                v -= 1 << shift
            return v, i


def parse(data, bits):
    """The Xlate of the section's bytes in an image of `bits` (32 or 64) bits, or None when the bytes are
    not a table of the layout above: every header copy must agree and the ranges must tile LO..HI."""
    if bits == 32:
        hdr, addr = 0x48, '>I'
        lo_at, hi_at, ext_at = (0x18, 0x20, 0x34, 0x38, 0x40), (0x1c,), (0x24, 0x44)
        count_at = (0x3c,)
    elif bits == 64:
        hdr, addr = 0x80, '>Q'
        lo_at, hi_at, ext_at = (0x20, 0x30, 0x58, 0x60, 0x70), (0x28,), (0x38, 0x78)
        count_at = (0x68,)
    else:
        return None
    if len(data) < hdr:
        return None

    def at(o, fmt=addr):
        return struct.unpack_from(fmt, data, o)[0]
    los, his, exts = {at(o) for o in lo_at}, {at(o) for o in hi_at}, {at(o) for o in ext_at}
    counts = {at(o) for o in count_at}
    counts.add(at(0x14 if bits == 32 else 0x1c, '>I'))
    if len(los) != 1 or len(his) != 1 or len(exts) != 1 or len(counts) != 1:
        return None
    lo, hi, count = los.pop(), his.pop(), counts.pop()
    body = data[hdr:]
    new = lo
    old = lo
    ranges = []
    i = 0
    try:
        for _ in range(count):
            a, i = _leb(body, i, False)
            b, i = _leb(body, i, True)
            old += 4 * b
            ranges.append((old, new, 4 * a))
            new += 4 * a
    except ValueError:
        return None
    if body[i:].strip(b'\0') or new != hi:
        return None
    return Xlate(lo, hi, ranges)


def of_elf(elf):
    """The Xlate of a pyelftools ELFFile, or None when it has no `.MIPS.Xlate` or it does not decode."""
    sec = elf.get_section_by_name('.MIPS.Xlate')
    if sec is None:
        return None
    return parse(sec.data(), elf.elfclass)
