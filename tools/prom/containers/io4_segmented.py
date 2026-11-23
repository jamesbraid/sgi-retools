"""The Challenge/Onyx IO4 segmented image (`JKSW`, `SEG2`, `_LZW`), from the chips IO4 payload page."""
import struct

from ..model import ContainerError, Segment, halfword_sum, sum_check
from ..payloads import lzw

NAME = 'io4-segmented'
BIAS = 0xce0                # the table writes every file offset this much too large
IDS = {0xff01: 'loader', 0x105: 'ip19', 0x205: 'ip21', 0x305: 'graphics', 0x405: 'ip25'}


def probe(data):
    return 'magic JKSW' if data[:4] == b'JKSW' else None


def unpack(data):
    _, hdr_sum, _load, _length, _entry, _build = struct.unpack_from('>4sIIIII', data, 0)
    if data[0x18:0x1c] != b'SEG2':
        raise ContainerError('JKSW header without a SEG2 table')
    (count,) = struct.unpack_from('>I', data, 0x1c)
    out = []
    for i in range(count):
        r = 0x20 + 48 * i
        if r + 48 > len(data):
            raise ContainerError('SEG2 record %d is past the end of the file' % i)
        sid, table_off, entry, load, length, cksum = struct.unpack_from('>IIQQII', data, r)
        off = table_off - BIAS
        if off < 0 or off + length > len(data):
            raise ContainerError('segment %#x lies outside the file (offset %#x, length %#x)' % (sid, off, length))
        stored = data[off:off + length]
        name = IDS.get(sid, 'seg-%#x' % sid)
        checks = [sum_check('record-halfword-sum', cksum, halfword_sum(stored))]
        if stored[:4] == b'_LZW':
            ulen, bsum, flag = struct.unpack_from('>III', stored, 4)
            body = lzw.decompress(stored[16:])
            trimmed = len(body) - ulen
            if trimmed > 0 and not any(body[ulen:]):        # the 1998 IP19 payload decodes with one extra zero byte
                body = body[:ulen]
            else:
                trimmed = 0
            checks += [sum_check('lzw-length', ulen, len(body)), sum_check('lzw-byte-sum', bsum, sum(body) & 0xffffffff)]
            s = Segment(name, body, off, length, 'compress', 'elf' if body[:4] == b'\x7fELF' else 'flat', sid,
                        load=load, entry=entry, checks=checks)
            s.extra['lzw_flag'] = flag
            if trimmed:
                s.extra['lzw_trimmed'] = trimmed
        else:
            s = Segment(name, stored, off, length, id=sid, load=load, entry=entry, checks=checks)
        s.extra['table_offset'] = '0x%x' % table_off
        out.append(s)
        if i == 0:
            out[0].checks.append(sum_check('header-halfword-sum', hdr_sum, halfword_sum(stored)))
    return out, None
