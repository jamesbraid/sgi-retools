"""Segments, checks and the sgi-prom document (`<image>.prom.json`) the unpack step writes."""
import hashlib
import struct
import subprocess
from dataclasses import dataclass, field

JR_RA, JR_RA_LE = bytes.fromhex('03e00008'), bytes.fromhex('0800e003')


def hexs(n):
    return None if n is None else '0x%x' % n


def word_sum(data):
    """Sum of the big-endian 32-bit words of data, modulo 2**32."""
    n = len(data) // 4
    return sum(struct.unpack('>%dI' % n, data[:n * 4])) & 0xffffffff


def halfword_sum(data):
    """Sum of the big-endian 16-bit halfwords of data (a last odd byte counts as the high half)."""
    if len(data) & 1:
        data += b'\0'
    return sum(struct.unpack('>%dH' % (len(data) // 2), data)) & 0xffffffff


class ContainerError(Exception):
    """A container recognised its magic but its structure is wrong."""


def sum_check(rule, want, got):
    return Check(rule, want == got, '' if want == got else 'header %#x, computed %#x' % (want, got))


@dataclass
class Check:
    rule: str
    ok: bool
    detail: str = ''


@dataclass
class Segment:
    name: str
    data: bytes
    offset: int = 0
    stored_length: int = 0
    compression: str = 'none'
    format: str = 'flat'
    id: int = None
    parent: str = None
    load: int = None
    entry: int = None
    regions: list = field(default_factory=list)
    checks: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_json(self, file):
        out = {
            'name': self.name, 'id': hexs(self.id), 'parent': self.parent, 'offset': hexs(self.offset),
            'stored_length': hexs(self.stored_length), 'compression': self.compression,
            'length': hexs(len(self.data)), 'sha256': hashlib.sha256(self.data).hexdigest(),
            'format': self.format, 'load': hexs(self.load), 'entry': hexs(self.entry),
            'regions': [dict(r, address=hexs(r['address']), offset=hexs(r.get('offset')), length=hexs(r['length']))
                        for r in self.regions],
            'checks': [dict(rule=c.rule, ok=c.ok, **({'detail': c.detail} if c.detail else {})) for c in self.checks],
        }
        out.update(self.extra)
        out['file'] = file
        return out


@dataclass
class Analysis:
    sha256: str
    size: int
    data: bytes             # after the transforms
    transforms: list
    containers: list
    segments: list
    byte_order: str
    byte_order_evidence: dict

    @property
    def ok(self):
        return all(c.ok for s in self.segments for c in s.checks)


def tool_revision(here):
    try:
        out = subprocess.run(['git', '-C', here, 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True)
        return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else 'unknown'
    except OSError:
        return 'unknown'


def document(an, name, files, catalog_row, revision):
    """The sgi-prom file for one image. files maps a segment's index to its output file name; the tables, strings
    and assets sections are defined by the schema and stay empty until promkit produces them."""
    names = [s.name for s in an.segments]
    if len(set(names)) != len(names):
        raise ContainerError('duplicate segment names: %s' % sorted({n for n in names if names.count(n) > 1}))
    return {
        'schema': 'sgi-prom', 'version': 1, 'kind': 'prom',
        'tool': {'name': 'promkit', 'revision': revision},
        'identity': {'file': name, 'sha256': an.sha256, 'size': an.size, 'catalog': catalog_row,
                     'family': catalog_row['board'] if catalog_row else None, 'byte_order': an.byte_order,
                     'transforms': [t['name'] for t in an.transforms], 'container': '>'.join(an.containers)},
        'segments': [s.to_json(files[i]) for i, s in enumerate(an.segments)],
        'tables': [], 'strings': [], 'assets': [],
    }
