"""The PROM's 1-bit bitmap formats: glyph entries, stipple rows, the run-length logo, and BDF output."""
import struct
from collections import namedtuple

Entry = namedtuple('Entry', 'off width height xoffset yoffset advance')


def stride(width):
    """Halfwords per row."""
    return (width + 15) // 16


def parse_entries(data, count):
    """count 8-byte big-endian entries: off s16 (halfwords from the bitmap base), width u8, height u8, xoffset s8,
    yoffset s8, advance u16."""
    return [Entry(*struct.unpack_from('>hBBbbH', data, 8 * i)) for i in range(count)]


def entry_span(e):
    """(first, end) byte offsets of the entry's rows from its bitmap base."""
    return e.off * 2, e.off * 2 + e.height * stride(e.width) * 2


def unpack_rows(data, width, height):
    """height rows of width pixels, bottom row first, as lists of 0/1. Each row is big-endian halfwords with the
    leftmost pixel in the most significant bit."""
    rb = stride(width) * 2
    if len(data) != rb * height:
        raise ValueError('%d bytes for a %dx%d bitmap' % (len(data), width, height))
    return [[(data[r * rb + (x >> 3)] >> (7 - (x & 7))) & 1 for x in range(width)] for r in range(height)]


def decode_rle(data, width, height):
    """(rows bottom first as bytearrays of 0/1, bytes used). A row is byte lengths alternating gap, run, gap, run,
    from a gap, until the total reaches the width; a length over 255 is 255, 0, rest, which alternation covers."""
    rows, pos = [], 0
    for _ in range(height):
        row, x, ink = bytearray(width), 0, False
        while x < width:
            if pos >= len(data):
                raise ValueError('run-length data ends inside row %d' % len(rows))
            n = data[pos]
            pos += 1
            if ink:
                row[x:min(x + n, width)] = b'\1' * (min(x + n, width) - x)
            x += n
            ink = not ink
        rows.append(row)
    return rows, pos


def bdf(name, height, descent, glyphs):
    """A BDF 2.1 font. glyphs: dicts with encoding, name, width, height, xoffset, yoffset, advance, rows (bottom
    row first). The bitmap origin and offsets are the PROM's: the glyph's bottom-left is at pen + (xoffset, yoffset)."""
    left = min(g['xoffset'] for g in glyphs)
    bottom = min(g['yoffset'] for g in glyphs)
    right = max(g['xoffset'] + g['width'] for g in glyphs)
    top = max(g['yoffset'] + g['height'] for g in glyphs)
    out = ['STARTFONT 2.1', 'FONT %s' % name, 'SIZE %d 75 75' % height,
           'FONTBOUNDINGBOX %d %d %d %d' % (right - left, top - bottom, left, bottom),
           'STARTPROPERTIES 2', 'FONT_ASCENT %d' % (height - descent), 'FONT_DESCENT %d' % descent, 'ENDPROPERTIES',
           'CHARS %d' % len(glyphs)]
    for g in glyphs:
        out += ['STARTCHAR %s' % g['name'], 'ENCODING %d' % g['encoding'], 'SWIDTH 0 0', 'DWIDTH %d 0' % g['advance'],
                'BBX %d %d %d %d' % (g['width'], g['height'], g['xoffset'], g['yoffset']), 'BITMAP']
        for row in reversed(g['rows']):
            bits = ''.join('1' if v else '0' for v in row).ljust((g['width'] + 7) // 8 * 8, '0')
            out.append('%0*X' % (len(bits) // 4, int(bits, 2)))
        out.append('ENDCHAR')
    return '\n'.join(out + ['ENDFONT', ''])
