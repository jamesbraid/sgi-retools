"""A minimal PNG writer (8-bit, unfiltered, fixed zlib level) so the same image always gives the same bytes."""
import struct
import zlib

GRAY_ALPHA, RGBA = 4, 6
_BYTES = {GRAY_ALPHA: 2, RGBA: 4}


def _chunk(kind, body):
    return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body))


def png(width, height, pixels, color_type):
    """pixels: the rows top to bottom, each width * bytes-per-pixel long, as one bytes object."""
    bpp = _BYTES[color_type]
    if width < 1 or height < 1 or len(pixels) != width * height * bpp:
        raise ValueError('pixel data is %d bytes, %dx%d needs %d' % (len(pixels), width, height, width * height * bpp))
    raw = b''.join(b'\0' + pixels[y * width * bpp:(y + 1) * width * bpp] for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' + _chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, color_type, 0, 0, 0)) +
            _chunk(b'IDAT', zlib.compress(raw, 9)) + _chunk(b'IEND', b''))


def mask_png(rows):
    """A 1-bit bitmap (rows top to bottom, lists of 0/1) as opaque white ink on a transparent background."""
    height, width = len(rows), len(rows[0])
    px = b''.join(b'\xff\xff' if v else b'\0\0' for row in rows for v in row)
    return png(width, height, px, GRAY_ALPHA)


def decode(data):
    """(width, height, color_type, pixels) of a PNG this module wrote; used by the tests."""
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    pos, idat = 8, b''
    while pos < len(data):
        n, kind = struct.unpack_from('>I4s', data, pos)
        body = data[pos + 8:pos + 8 + n]
        if zlib.crc32(kind + body) != struct.unpack_from('>I', data, pos + 8 + n)[0]:
            raise ValueError('bad chunk crc')
        if kind == b'IHDR':
            width, height, depth, color_type = struct.unpack_from('>IIBB', body)
        elif kind == b'IDAT':
            idat += body
        pos += 12 + n
    raw, bpp = zlib.decompress(idat), _BYTES[color_type]
    stride = width * bpp + 1
    assert all(raw[y * stride] == 0 for y in range(height))
    return width, height, color_type, b''.join(raw[y * stride + 1:(y + 1) * stride] for y in range(height))
