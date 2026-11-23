"""The 0x100-byte `PROM` header the O2's installer images carry before the flash contents."""
import struct

from ..model import ContainerError

NAME = 'installer'
HEADER = 0x100


def probe(data):
    return 'magic PROM' if data[:4] == b'PROM' and len(data) >= HEADER else None


def unpack(data):
    (flash,) = struct.unpack_from('>I', data, 0x0c)
    if HEADER + flash != len(data):
        raise ContainerError('installer header says %#x flash bytes, the file holds %#x' % (flash, len(data) - HEADER))
    return [], (HEADER, data[HEADER:])
