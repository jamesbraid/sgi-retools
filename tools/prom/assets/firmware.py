"""A firmware segment seen by run-time address: the load map says where each chunk's bytes run."""
import struct

from . import AssetError
from .mips import decode_all


class Firmware:
    def __init__(self, segment):
        self.segment = segment
        self.data = segment.data
        self.regions = {r['name']: r for r in segment.regions}
        if not {'text', 'rodata', 'data'} <= self.regions.keys():
            raise AssetError('segment %s has no text, rodata and data chunks in its load map' % segment.name)

    def region(self, name):
        r = self.regions[name]
        return r['address'], r['address'] + r['length']

    def offset(self, addr, n=1):
        """Segment offset of the n bytes at addr, or None when they are not all inside one chunk."""
        for r in self.regions.values():
            if r['offset'] is not None and r['address'] <= addr and addr + n <= r['address'] + r['length']:
                return r['offset'] + addr - r['address']
        return None

    def read(self, addr, n):
        off = self.offset(addr, n)
        if off is None:
            raise AssetError('%d bytes at %#x are outside the firmware chunks' % (n, addr))
        return self.data[off:off + n]

    def u32(self, addr):
        return struct.unpack('>I', self.read(addr, 4))[0]

    def in_data(self, addr, n=1):
        lo, hi = self.region('data')
        return lo <= addr and addr + n <= hi

    def code(self):
        lo, hi = self.region('text')
        return decode_all(self.read(lo, hi - lo), lo), lo

    def place(self, addr):
        """The schema's address object for a run-time address."""
        return {'segment': self.segment.name, 'address': '0x%x' % addr, 'offset': '0x%x' % self.offset(addr)}
