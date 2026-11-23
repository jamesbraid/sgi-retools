"""Byte swap inside each 16-bit pair: the form of a PROM dump read through a 16-bit-wide path."""
from ..model import JR_RA

NAME = 'swap16'


def _count(data):
    return sum(1 for i in range(0, len(data) - 3, 4) if data[i:i + 4] == JR_RA)


def apply(data):
    n = len(data) & ~1
    out = bytearray(data)
    out[0:n:2], out[1:n:2] = data[1:n:2], data[0:n:2]
    return bytes(out)


def probe(data):
    """Evidence when only the swapped reading has big-endian `jr ra` words, else None."""
    straight, swapped = _count(data), _count(apply(data))
    if swapped >= 8 and straight == 0:
        return 'jr ra words: %d straight, %d pair-swapped' % (straight, swapped)
    return None
