#!/usr/bin/env python3
"""Level-descriptor pitch, slice count and slice stride, as the N32 libGLcore computes them.

Usage: texlevel_layout.py [--check] [WIDTH HEIGHT DEPTH BORDER SIZECODE [--icc]]

A re-statement of two routines of libGLcore (IRIX 6.5.30m, IP30 N32): the texture
activation loop (0x0d9d20b0 to 0x0d9d2254, which writes the pitch in level word 1
bits 11:0 and the slice exponent in word 2) and the texture memory allocator
(0x0d9d03b0, which sizes the object and records the origin offset), plus the
upload loop of the host-texture loader (0x0d9d08a0) that places each slice. The
code in each case was read in full; this file is the arithmetic only, checked
against the three captured level descriptors it lists (the 4x4x4 stored-border volume,
the 2x2x2 zero-border volume and the 128x128x64 volume). It is software evidence of the library, not of the board.
Sizes are the level's stored size, border included, as the library keeps them.
"""
import sys


def ceil_log2(v):
    """__glOdysseyImageLogBase2: smallest k with 2**k >= v (0 for v of 0 or 1)."""
    return 0 if v < 2 else (v - 1).bit_length()


def even_up(v):
    return v + (v & 1)


def pitch_tiles(width, border, icc=False):
    """Activation, primary levels: row length in 16-texel tiles (word 1 bits 11:0)."""
    if icc:                       # internal formats 0x8466 and 0x8467
        w = (width + 1) // 2      # half the full width, border not subtracted
        t = (w + 15) >> 4
    else:
        t = (width - 2 * border + 15) >> 4
    return even_up(t + (2 if border else 0))


def height_tiles(height, border):
    return ((height - 2 * border + 15) >> 4) + (2 if border else 0)


def slice_exponent(width, height, border, icc=False):
    """Activation, 3D only: level word 2 bits 11:0."""
    t = pitch_tiles(width, border, icc) * height_tiles(height, border)
    return ceil_log2(t) if t >= 2 else 0


def slice_tiles(width, height, depth, border):
    """Allocator: tile count of one slice, rounded to a power of two for depth >= 2."""
    # the allocator adds 2*border after rounding the interior row to even; same value
    p = 2 * border + even_up((width - 2 * border + 15) >> 4)
    t = p * height_tiles(height, border)
    return 1 << ceil_log2(t) if depth >= 2 else t


def origin_offset(border):
    """Allocator: the image starts (16 - border) & 15 texels in on each axis."""
    return (16 - border) & 15


def slice_stride_units(width, height, depth, border, sizecode):
    """Loader: address-unit step between slices; (2 << sizecode) bytes a texel."""
    return slice_tiles(width, height, depth, border) * (2 << sizecode) * 256 // 16


def slice_origin_units(z, width, height, depth, border, sizecode):
    """Loader: destination offset of slice z (z counts from the first stored slice)."""
    return (z + origin_offset(border)) * slice_stride_units(width, height, depth, border, sizecode)


CASES = [
    # name, (w, h, d, border, sizecode), icc, pitch, word 2, stride, first slice index
    ("stored 4x4x4 border 1, RGBA8", (4, 4, 4, 1, 1), False, 4, 4, 0x400, 15),
    ("zero-border 2x2x2, RGBA8", (2, 2, 2, 0, 1), False, 2, 1, 0x80, 0),
    ("pfCity 128x128x64, RGBA8", (128, 128, 64, 0, 1), False, 8, 6, 0x1000, 0),
]


def check():
    bad = 0
    for name, (w, h, d, b, c), icc, pitch, w2, stride, first in CASES:
        got = (pitch_tiles(w, b, icc),
               slice_exponent(w, h, b, icc) if d > 1 else None,
               slice_stride_units(w, h, d, b, c) if d > 1 else None,
               origin_offset(b) if d > 1 else None)
        want = (pitch, w2 if d > 1 else None, stride if d > 1 else None, first if d > 1 else None)
        ok = got == want
        print("%-44s %s  pitch %s word2 %s stride %s first %s" % (
            name, "ok " if ok else "BAD", *got))
        bad += not ok
    return bad


if __name__ == "__main__":
    if "--check" in sys.argv or len(sys.argv) == 1:
        sys.exit(1 if check() else 0)
    a = [x for x in sys.argv[1:] if not x.startswith("--")]
    w, h, d, b, c = map(int, a[:5])
    icc = "--icc" in sys.argv
    print("pitch", pitch_tiles(w, b, icc), "word2", slice_exponent(w, h, b, icc),
          "slice tiles", slice_tiles(w, h, d, b), "stride", hex(slice_stride_units(w, h, d, b, c)),
          "origin", origin_offset(b))
