"""promkit: identify and unpack SGI PROM images. Plug-ins register in transforms/ and containers/."""
import gzip
import hashlib
import struct
import zlib

from .containers import CONTAINERS
from .model import JR_RA, JR_RA_LE, Analysis, ContainerError
from .transforms import TRANSFORMS


def byte_order(segments):
    """Count `jr ra` words in each byte order over the unpacked segments."""
    be = le = 0
    for s in segments:
        be += sum(1 for i in range(0, len(s.data) - 3, 4) if s.data[i:i + 4] == JR_RA)
        le += sum(1 for i in range(0, len(s.data) - 3, 4) if s.data[i:i + 4] == JR_RA_LE)
    return ('big' if be > le else 'little' if le > be else 'unknown'), {'jr_ra_big': be, 'jr_ra_little': le}


def analyze(data):
    """Run the pipeline: transforms, then containers (an installer header hands its contents to the next one)."""
    sha = hashlib.sha256(data).hexdigest()
    size = len(data)
    transforms = []
    for t in TRANSFORMS:
        evidence = t.probe(data)
        if evidence:
            data = t.apply(data)
            transforms.append({'name': t.NAME, 'evidence': evidence})
    names, segments, base = [], [], 0
    while True:
        c = next(c for c in CONTAINERS if c.probe(data))
        names.append(c.NAME)
        try:
            found, inner = c.unpack(data)
        except (struct.error, zlib.error, EOFError, gzip.BadGzipFile, ValueError, IndexError) as e:
            raise ContainerError('%s: truncated or corrupt (%s)' % (c.NAME, e))
        for s in found:
            s.offset += base
        segments += found
        if inner is None:
            break
        base, data = base + inner[0], inner[1]
    for s in segments:      # names become output file names
        if not s.name or '/' in s.name or '\\' in s.name or '\0' in s.name or '..' in s.name:
            raise ContainerError('segment name %r cannot be a file name' % s.name)
    order, evidence = byte_order(segments)
    return Analysis(sha, size, data, transforms, names, segments, order, evidence)
