"""Cut a firmware container into the segments a controller runs, and find one again from its key.

inventory.py writes one row per routine of a segment, keyed `<path>(<member>)` (`l1.bin(l1#2)`,
`l2.bin(flash)`, `l2.bin(kernel)`; a flat layout has the empty member, `fw.bin()`). The readings tools
need the same bytes and load address back from such a key, so both use this module and the layout code
exists once.
"""
import fnmatch
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _num(s):
    return s if isinstance(s, int) else int(str(s).strip(), 0)


def firmware_segments(g, rel, data):
    """[(member, body, load address)] for one file of a group that names a `layout`: the code a controller
    runs, cut out of its container. `flat` is a file mapped at the group's `load` from its `offset`; the
    sysco layouts split the controllers' ESTFBINR images the way sysco's firmware tables do."""
    layout = g['layout']
    if layout == 'flat':
        off = _num(g.get('offset', 0))
        return [('', data[off:], _num(g['load']))] if off < len(data) else []
    if data[:8] != b'ESTFBINR':
        return []
    import zlib
    from sysco import sysco_tables as st
    if layout == 'sysco-l1':
        if st.FW in rel and not st._old_layout(data):
            pkgs = [p for p in st.l1_packages(data) if not p['linux']]
        else:       # the base product's single image, and the sysco images that predate the container
            pkgs = [st.pre_container_package(data)]
        return [('l1#%d' % p['index'], p['body'], p['load']) for p in pkgs]
    if layout == 'sysco-l2':
        # the flash starts at the header's load address from file offset 0x2c; the kernel follows as a gzip
        # stream and runs inflated at its own link address
        gz = data.find(b'\x1f\x8b\x08')
        out = [('flash', data[0x2c:gz if gz > 0x2c else len(data)], struct.unpack('>I', data[8:12])[0])]
        if gz > 0 and g.get('kernel_load') is not None:
            try:
                out.append(('kernel', zlib.decompressobj(31).decompress(data[gz:]), _num(g['kernel_load'])))
            except zlib.error:
                pass
        return out
    sys.exit('firmware layout: unknown firmware layout %r' % layout)


def layout_group(cfg, rel):
    """The binaries group of the config with a `layout` whose paths match rel (a path under root/), or None."""
    for g in cfg.get('binaries', []):
        if g.get('layout') and any(fnmatch.fnmatch(rel, p) for p in g['paths']):
            return g
    return None


def split_segment_key(key):
    """(path, member) of `path(member)` or `path:member`; a bare path has the empty member."""
    m = re.fullmatch(r'(.+)\(([^()]*)\)', key) or re.fullmatch(r'(.+?):([^:]*)', key)
    return m.groups() if m else (key, '')


_cache = {}


def _segments(g, rel, path):
    """firmware_segments of a file, kept for the next row: inflating an L2 kernel for each of hundreds of
    routines would dominate a round."""
    key = (path, json.dumps(g, sort_keys=True))
    if key not in _cache:
        with open(path, 'rb') as handle:
            _cache[key] = firmware_segments(g, rel, handle.read())
    return _cache[key]


def segment_at(cfg, root, key):
    """(arch, body, load address, group) of the segment a row key names, or None when the path is in
    no layout group of the config (an ordinary file or archive member). LookupError when the file's
    group has no such segment, since the key then names something the inventory did not write."""
    rel, member = split_segment_key(key)
    g = layout_group(cfg, rel)
    if g is None:
        return None
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        raise LookupError('%s is not under %s' % (rel, root))
    for name, body, load in _segments(g, rel, path):
        if name == member:
            return g['arch'], body, load, g
    raise LookupError('%s has no segment %r' % (rel, member))


def read_config(workspace):
    """The inventory config of a workspace, or {} when it has none."""
    path = os.path.join(workspace, 'scripts', 'inventory-config.json')
    if not os.path.isfile(path):
        return {}
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def segment_routine(cfg, root, key, address, size=None):
    """The hostfacts routine at address in the segment a row key names, or None when the key names an
    ordinary file. The file's name is only a label: the bytes are the segment's."""
    found = segment_at(cfg, root, key)
    if found is None:
        return None
    import hostfacts
    arch, body, load, _group = found
    return hostfacts.routine_for(os.path.join(root, split_segment_key(key)[0]), address, size=size,
                                 arch=arch, load=load, data=body)
