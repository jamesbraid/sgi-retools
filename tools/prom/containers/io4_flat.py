"""The Challenge/Onyx IO4 flat image: a 24-byte `JFK4` header and one IP19 monitor, from the chips IO4 payload page."""
import struct

from ..model import ContainerError, Segment, halfword_sum, sum_check

NAME = 'io4-flat'


def probe(data):
    return 'magic JFK4' if data[:4] == b'JFK4' else None


def unpack(data):
    _, cksum, load, length, entry, build = struct.unpack_from('>4sIIIII', data, 0)
    if 24 + length != len(data):
        raise ContainerError('JFK4 header says %#x payload bytes, the file holds %#x' % (length, len(data) - 24))
    body = data[24:]
    s = Segment('ip19', body, 24, length, load=load, entry=entry)
    s.extra['build'] = build
    s.checks.append(sum_check('halfword-sum', cksum, halfword_sum(body)))
    return [s], None
