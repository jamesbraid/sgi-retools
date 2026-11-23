"""The O2 flash: five `SHDR` segments at 0x100-aligned offsets (in the held images, 0x200), from the chips O2 PROM page."""
import struct

from ..model import Check, ContainerError, Segment, word_sum

NAME = 'ip32-flash'
FLASH = 0xbfc00000          # where the flash executes, so a segment at offset N runs from FLASH + N
FIRMWARE_TYPE = 3


def probe(data):
    return 'SHDR at 0x8' if len(data) >= 0x40 and data[8:12] == b'SHDR' else None


def _firmware(s, seg):
    """Walk the load map: {address, length} records, the first at +0x40 inside the text chunk (which starts at 0), each
    later one right after the previous chunk and followed by its chunk's bytes, then a zero-length record whose
    address is the entry. The chunks must tile the segment up to that record, which sits before the balance word."""
    def w(o):
        return struct.unpack_from('>I', seg, o)[0] if 0 <= o <= len(seg) - 4 else None
    chunks, rec, data = [], 0x40, 0
    while w(rec + 4) and data + w(rec + 4) <= len(seg):
        chunks.append((w(rec), data, w(rec + 4)))
        rec = data + w(rec + 4)
        data = rec + 8
    closed = bool(chunks) and w(rec + 4) == 0 and rec == len(seg) - 12
    s.checks.append(Check('ip32-load-map-tiles', closed, '' if closed else 'chunk records do not tile the segment'))
    if closed:
        s.load, s.entry = chunks[0][0], w(rec)
    names = (('text', 'code'), ('rodata', 'readonly'), ('data', 'data'))
    for i, (addr, off, length) in enumerate(chunks if closed else []):
        name, kind = names[i] if i < len(names) else ('chunk%d' % i, 'data')
        s.regions.append({'name': name, 'address': addr, 'offset': off, 'length': length, 'kind': kind})


def unpack(data):
    out, off = [], 0
    while off + 0x40 <= len(data) and data[off + 8:off + 12] == b'SHDR':
        length = struct.unpack_from('>I', data, off + 0x0c)[0]
        nlen, vlen, kind = data[off + 0x10], data[off + 0x11], data[off + 0x12]
        if length < 0x44 or off + length > len(data) or nlen > 32 or vlen > 8:
            raise ContainerError('bad SHDR segment at %#x' % off)
        seg = data[off:off + length]
        s = Segment(seg[0x14:0x14 + nlen].decode('latin-1'), seg, off, length, load=FLASH + off)
        s.extra['version'] = seg[0x34:0x34 + vlen].decode('latin-1')
        s.checks.append(Check('shdr-header-zero-sum', word_sum(seg[:0x40]) == 0))
        s.checks.append(Check('shdr-body-balance', word_sum(seg[0x40:]) == 0))
        if kind == FIRMWARE_TYPE:
            _firmware(s, seg)
        out.append(s)
        off = (off + length + 0xff) & ~0xff
        if data[off + 8:off + 12] != b'SHDR':       # both held images place a segment at the next 0x200 boundary
            off += 0x100
    if not out:
        raise ContainerError('no SHDR segment')
    return out, None
