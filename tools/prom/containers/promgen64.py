"""The 64-bit promgen container (IP27, IO6, IP35, IP30): magic `JFKSWCSM` at 0x40, 0x80-byte segment records from 0x80."""
import gzip
import struct

from ..model import Check, ContainerError, Segment

NAME = 'promgen64'
MAGIC = b'JFKSWCSM'
MAX_SEGMENTS = (0x1000 - 0x80) // 0x80


def probe(data):
    return 'magic JFKSWCSM at 0x40' if data[0x40:0x48] == MAGIC else None


def unpack(data):
    (count,) = struct.unpack_from('>I', data, 0x7c)
    if count > MAX_SEGMENTS:
        raise ContainerError('promgen64 header claims %d segments' % count)
    out = []
    for i in range(count):
        b = 0x80 + i * 0x80
        name = data[b:b + 16].split(b'\0')[0].decode('latin-1')
        flags, off, entry, load, length, packed, tsum, csum, with_bss = struct.unpack_from('>9Q', data, b + 16)
        gz = 0 < packed < length
        stored = data[off:off + (packed if gz else length)]
        if len(stored) != (packed if gz else length):
            raise ContainerError('segment %s runs past the end of the file' % name)
        body = gzip.decompress(stored) if gz else stored
        ok = len(body) == length and sum(body) & 0xffffffff == tsum & 0xffffffff
        s = Segment(name, body, off, len(stored), 'gzip' if gz else 'none', load=load, entry=entry,
                    checks=[Check('promgen64-byte-sum', ok, '' if ok else 'length %#x, header %#x' % (len(body), length))])
        s.extra['flags'] = '0x%x' % flags
        out.append(s)
    return out, None
