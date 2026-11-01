#!/usr/bin/env python3
"""Measure the firmware side of the workspace: images, packages, functions, request codes,
I/O registers and protocols.

Usage: scripts/sysco_tables.py [--out docs/inventory]

Run from the repository root with root/ populated (IRIX_FILES.md), inside the toolchain
container (tools/re-run python3 scripts/sysco_tables.py). scripts/inventory.py, the same
file in every workspace, measures ELF images and cannot read the controller firmware, so
the tables for it are written here. The output is deterministic.

Inputs besides root/:
  docs/l1/functions.tsv      names and roles assigned to routine addresses
  docs/l1/request-codes.tsv  the request catalogue
  docs/l1/io-registers.tsv   register and device accesses read from the code
  docs/l1/protocols.tsv      descriptors, framing and routing, with optional byte checks
  docs/l1/packages.tsv       one layout row per Linux L1 package, graded and located
A curated row that names a package is checked against the bytes: handler addresses must lie in
the body, and a `check` cell (bytes:OFFSET:HEX or sum32:OFFSET:LENGTH, body offsets) must hold.

Statuses, from weakest: undocumented, located (the address, hash or offset is cited in a
document under docs/), understood (a curated row carries a grade, a role and a locator and its
checks pass). docs/inventory/README.md has the column definitions.
"""
import collections
import glob
import hashlib
import os
import re
import struct
import sys
import zlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, 'root')
OUT = os.path.join(REPO, 'docs', 'inventory')
if '--out' in sys.argv:
    OUT = os.path.abspath(sys.argv[sys.argv.index('--out') + 1])

RELEASES = ['6.5.20', '6.5.21', '6.5.22', '6.5.23', '6.5.24', '6.5.25', '6.5.26', '6.5.27', '6.5.28', '6.5.29', '6.5.30', 'patches/SG0005762', 'patches/SG0007149']
FW = 'usr/cpu/firmware/sysco/'
CRAMFS_LE, CRAMFS_BE = b'\x45\x3d\xcd\x28', b'\x28\xcd\x3d\x45'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def tsv_read(path):
    if not os.path.exists(path):
        return []
    lines = open(path, encoding='utf-8').read().split('\n')
    head = lines[0].split('\t')
    return [dict(zip(head, ln.split('\t'))) for ln in lines[1:] if ln.strip()]


def tsv_write(name, cols, rows):
    with open(os.path.join(OUT, name + '.tsv'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\t'.join(cols) + '\n')
        for r in rows:
            f.write('\t'.join(str(r.get(c, '')).replace('\t', ' ').replace('\n', ' ') for c in cols) + '\n')


# ------------------------------------------------------------------ documents
def doc_text():
    text = []
    for p in sorted(glob.glob(os.path.join(REPO, 'docs', '**', '*'), recursive=True)):
        rel = os.path.relpath(p, REPO)
        if not os.path.isfile(p) or rel.startswith('docs/inventory/') or '/disasm/' in rel:
            continue
        if p.endswith(('.md', '.tsv')):
            text.append((rel, open(p, encoding='utf-8', errors='replace').read().lower()))
    return text


DOCS = doc_text()


def cited(token, kind='plain'):
    """First document that cites token (lower case hex without 0x)."""
    t = token.lower()
    for rel, txt in sorted(DOCS, key=lambda x: x[0] != 'docs/firmware-versions.md'):
        if rel.endswith('/functions.tsv') or rel.endswith('/request-codes.tsv') or rel.endswith('/io-registers.tsv') \
                or rel.endswith('/protocols.tsv'):
            continue
        if t in txt:
            return rel
    return ''


def hexform(a):
    return '0x%08x' % a


# ------------------------------------------------------------------ images
def find_images():
    files = []
    for rel in RELEASES:
        base = os.path.join(ROOT, rel)
        for dp, dn, fn in os.walk(base):
            dn.sort()
            for f in sorted(fn):
                p = os.path.join(dp, f)
                r = os.path.relpath(p, ROOT)
                if r.startswith(tuple(x + '/' + FW for x in RELEASES)) or '/usr/sbin/' in '/' + r:
                    files.append(r)
    return sorted(files)


def version_of(data):
    c = collections.Counter(re.findall(rb'(?<![\d.])1\.\d{1,2}\.\d{1,2}(?![\d.])', data))
    return c.most_common(1)[0][0].decode() if c else ''


def find_cramfs(pk, start):
    """Offset of the CramFS superblock at or after start; the signature sits 16 bytes in."""
    for m in range(start, len(pk) - 32):
        if pk[m:m + 4] == CRAMFS_LE and pk[m + 16:m + 32] == b'Compressed ROMFS':
            return m
    raise ValueError('no CramFS superblock after 0x%x' % start)


def _cramfs_inode(img, pos):
    mode_uid, size_gid, name_off = struct.unpack('<III', img[pos:pos + 12])
    namelen = (name_off & 0x3f) * 4
    return {'mode': mode_uid & 0xffff, 'size': size_gid & 0xffffff, 'offset': (name_off >> 6) * 4,
            'name': img[pos + 12:pos + 12 + namelen].rstrip(b'\0').decode('latin-1'), 'next': pos + 12 + namelen}


def _cramfs_file(img, base, ino):
    """Decompressed bytes of a regular file or symlink; each block's end pointer closes it."""
    nblk = (ino['size'] + 4095) // 4096
    ptrs = struct.unpack('<%dI' % nblk, img[base + ino['offset']:base + ino['offset'] + 4 * nblk]) if nblk else ()
    start, out = base + ino['offset'] + 4 * nblk, bytearray()
    for p in ptrs:
        end = base + (p & 0x3fffffff)
        if p & (1 << 31):
            out += img[start:end]
        else:
            out += zlib.decompressobj().decompress(img[start:end])
        start = end
    if len(out) < ino['size']:
        raise ValueError('CramFS file short by %d bytes' % (ino['size'] - len(out)))
    return bytes(out[:ino['size']])


KINDS = {0o040000: 'dir', 0o100000: 'file', 0o120000: 'symlink', 0o020000: 'chardev', 0o060000: 'blockdev',
         0o010000: 'fifo', 0o140000: 'socket'}


def cramfs_entries(img, base):
    """Every entry of the CramFS at base, as dicts with path, type, mode, bytes, sha256 and symlink target."""
    rows = []

    def visit(ino, path):
        kind = KINDS.get(ino['mode'] & 0o170000, 'other')
        row = {'path': path, 'type': kind, 'mode': '%o' % (ino['mode'] & 0o7777), 'bytes': ino['size'],
               'sha256': '', 'target': ''}
        rows.append(row)
        if kind == 'dir':
            pos, end = base + ino['offset'], base + ino['offset'] + ino['size']
            while pos < end:
                child = _cramfs_inode(img, pos)
                visit(child, path.rstrip('/') + '/' + child['name'])
                pos = child['next']
        elif kind in ('file', 'symlink'):
            data = _cramfs_file(img, base, ino)
            row['bytes'] = len(data)
            row['sha256'] = sha(data)
            if kind == 'symlink':
                row['target'] = data.rstrip(b'\0').decode('latin-1')
        elif kind in ('chardev', 'blockdev'):
            # the size field holds a classic 16-bit device number (major in the high byte)
            row['bytes'] = 0
            row['target'] = '%d:%d' % (ino['size'] >> 8, ino['size'] & 0xff)

    visit(_cramfs_inode(img, base + 64), '/')
    return rows


def l1_packages(data):
    n = struct.unpack('>I', data[0x2c:0x30])[0]
    out = []
    for i in range(n):
        off, ln = struct.unpack('>II', data[0x30 + 8 * i:0x38 + 8 * i])
        pk = data[off:off + ln]
        linux = CRAMFS_LE in pk
        e = {'index': i, 'offset': off, 'length': ln, 'data': pk, 'sha': sha(pk), 'linux': linux}
        e['version'] = version_of(pk)
        m = re.findall(rb'(?:Legacy Linux L1 image|Linux L1 image|[A-Za-z0-9/]+ \dMB image|\dMB image)', pk)
        lab = m[0].decode() if m else ''
        if lab.startswith('Nu'):
            lab = lab[2:]
        e['label'] = lab
        stamps = collections.Counter(re.findall(rb'(?<!\d)20\d{12}(?!\d)', pk))
        e['stamp'] = stamps.most_common(1)[0][0].decode() if stamps else ''
        if linux:
            e['family'] = 'ARM S3C2410 Linux'
            gz = pk.find(b'\x1f\x8b\x08')
            try:
                z = zlib.decompressobj(31)
                k = z.decompress(pk[gz:])
                gz_len = len(pk) - gz - len(z.unused_data)
                e['kernel'] = '%d bytes sha256 %s' % (len(k), sha(k)[:16])
                mm = re.search(rb'Linux version (\S+)', k)
                e['kernel_release'] = mm.group(1).decode() if mm else ''
                bm = re.search(rb'#\d+ (?:PREEMPT )?([A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]+ [A-Z]{3,4} \d{4})', k)
                e['kernel_built'] = bm.group(1).decode() if bm else ''
                e['gzip'] = (gz, gz_len)
                cf = find_cramfs(pk, gz + gz_len)
                e['cramfs'] = (cf, struct.unpack('<I', pk[cf + 4:cf + 8])[0])
                e['files'] = cramfs_entries(pk, cf)
                e['crc'] = '0x%08x' % struct.unpack('<I', pk[cf + 32:cf + 36])[0]
            except (zlib.error, ValueError):
                e['kernel'] = ''
                e['kernel_release'] = ''
                e['kernel_built'] = ''
                e['files'] = []
        else:
            e['family'] = 'ColdFire MCF5206e'
            e['load'], e['last'] = struct.unpack('>II', pk[8:16])
            # the container's package table (count at 0x2c, pairs from 0x30) overlays the first
            # package's header, so that package's body starts after the table
            body = pk[(0x30 + 8 * n) if off == 0 else 44:]
            e['body'] = body
            e['body_sha'] = sha(body)
            e['reset'] = '0x%08x 0x%08x' % struct.unpack('>II', body[:8])
        out.append(e)
    return out


def l2_info(data):
    e = {}
    gz = data.find(b'\x1f\x8b\x08')
    z = zlib.decompressobj(31)
    k = z.decompress(data[gz:])
    mm = re.search(rb'Linux version (\S+)[^\n\x00]*?# ?\d+ ([^\n\x00]+)', k)
    e['kernel'] = '%d bytes sha256 %s' % (len(k), sha(k)[:16])
    e['kernel_build'] = mm.group(2).decode() if mm else ''
    c = data.find(CRAMFS_BE)
    if c >= 0:
        size, flags = struct.unpack('>II', data[c + 4:c + 12])
        e['cramfs'] = 'offset 0x%x size %d sha256 %s' % (c, size, sha(data[c:c + size])[:16])
    e['load'], e['last'] = struct.unpack('>II', data[8:16])
    return e


def build():
    rels = find_images()
    by_sha = collections.OrderedDict()
    for r in rels:
        d = open(os.path.join(ROOT, r), 'rb').read()
        by_sha.setdefault(sha(d), {'paths': [], 'data': d})['paths'].append(r)
    images, pkgs, funcs, files = [], [], [], []
    seen_body = {}
    for h, v in by_sha.items():
        d, paths = v['data'], v['paths']
        p0 = paths[0]
        name = os.path.basename(p0)
        rec = {'sha256': h, 'bytes': len(d), 'path': p0, 'copies': ';'.join(paths[1:])}
        rel = p0.split('/usr/')[0]
        rec['release'] = rel
        if name == 'l1.bin' and d[:8] == b'ESTFBINR':
            rec['kind'] = 'L1 firmware container'
            ps = l1_packages(d)
            rec['arch'] = 'ColdFire MCF5206e x%d, ARM S3C2410 Linux x%d' % (
                sum(1 for p in ps if not p['linux']), sum(1 for p in ps if p['linux']))
            rec['version'] = ','.join(sorted({p['version'] for p in ps if p['version']}))
            rec['detail'] = '%d packages' % len(ps)
            for p in ps:
                row = {'image': p0, 'release': rel, 'index': p['index'], 'offset': '0x%x' % p['offset'],
                       'length': p['length'], 'sha256': p['sha'], 'family': p['family'], 'label': p['label'],
                       'version': p['version'], 'build_stamp': p['stamp']}
                key = '%s:l1#%d' % (rel, p['index'])
                if p['linux']:
                    row['detail'] = ('kernel %s built %s, %s; gzip at package offset 0x%x length %d; '
                                     'CramFS at 0x%x length %d crc %s, %d entries' % (
                                         p['kernel_release'], p['kernel_built'], p['kernel'], p['gzip'][0], p['gzip'][1],
                                         p['cramfs'][0], p['cramfs'][1], p['crc'], len(p['files'])))
                    files += [dict(f, package=key) for f in p['files']]
                else:
                    row['detail'] = 'load 0x%08x last 0x%08x, reset sp/pc %s, body sha256 %s' % (
                        p['load'], p['last'], p['reset'], p['body_sha'])
                row['key'] = key
                row['copies'] = ''
                pkgs.append(row)
                if not p['linux']:
                    body = p['body']
                    if p['body_sha'] in seen_body:
                        continue
                    seen_body[p['body_sha']] = key
                    funcs += function_rows(key, p, rel)
        elif name == 'l2.bin' and d[:8] == b'ESTFBINR':
            rec['kind'] = 'L2 firmware image'
            rec['arch'] = 'PowerPC MPC860 Linux 2.4.7'
            rec['version'] = version_of(d)
            i = l2_info(d)
            rec['detail'] = 'load 0x%08x last 0x%08x, kernel %s, built %s; cramfs %s' % (
                i['load'], i['last'], i['kernel'], i['kernel_build'], i.get('cramfs', ''))
        elif name == 'pbay.bin':
            rec.update(kind='power-bay controller image', arch='unknown', version='', detail='')
        elif name.endswith('.svf'):
            rec.update(kind='CPLD JTAG vectors', arch='-', version='', detail='')
        elif d[:4] == b'\x7fELF':
            rec.update(kind='IRIX host tool', arch='MIPS N32 big-endian', version='', detail='')
        else:
            rec.update(kind='other', arch='', version='', detail='')
        images.append(rec)
    # folding: identical package bodies across releases are listed once in `functions`
    return images, pkgs, funcs, files


def function_rows(key, p, rel):
    body, base = p['body'], p['load']
    cands = {}
    for off in range(0, len(body) - 1, 2):
        if body[off:off + 2] == b'\x4e\x56':
            cands.setdefault(base + off, set()).add('prologue')
    for m in re.finditer(b'\x4e\xb9', body):
        o = m.start()
        if o % 2 or o + 6 > len(body):
            continue
        t = struct.unpack('>I', body[o + 2:o + 6])[0]
        if base <= t < base + len(body) and t % 2 == 0:
            cands.setdefault(t, set()).add('call-target')
    cur = {r['address'].lower(): r for r in tsv_read(os.path.join(REPO, 'docs/l1/functions.tsv'))
           if r['package'] == key}
    rows = []
    for a in sorted(cands):
        h = '%08x' % a
        r = {'image': key, 'address': hexform(a), 'evidence': '+'.join(sorted(cands[a])), 'name': '', 'grade': '',
             'status': 'undocumented', 'doc': ''}
        c = cur.get(h)
        if c:
            r['name'] = c['name']
            r['grade'] = c['grade']
            r['status'] = 'understood' if c['grade'] in ('established', 'inferred') and len(c['note'].split()) >= 4 else 'located'
            r['doc'] = 'docs/l1/functions.tsv'
        else:
            d = cited(h)
            if d:
                r['status'] = 'located'
                r['doc'] = d
        rows.append(r)
    return rows


def check_cell(check, body):
    if not check:
        return ''
    kind, off, arg = check.split(':', 2)
    off = int(off, 16)
    if kind == 'bytes':
        want = bytes.fromhex(arg)
        return 'ok' if body[off:off + len(want)] == want else 'MISMATCH'
    if kind == 'sum32':
        n = int(arg)
        w = struct.unpack('>%dI' % (n // 4), body[off:off + n])
        return 'ok' if sum(w) % (1 << 32) == 0 else 'MISMATCH'
    return 'unknown-check'


def bodies(pkgs_rows):
    """package key -> (load, body) for the curated package keys."""
    out = {}
    for rel in RELEASES:
        p = os.path.join(ROOT, rel, FW, 'l1.bin')
        if not os.path.exists(p):
            continue
        for e in l1_packages(open(p, 'rb').read()):
            if not e['linux']:
                out['%s:l1#%d' % (rel, e['index'])] = (e['load'], e['body'])
    return out


class _Same(dict):
    def __missing__(self, k):
        return k


KEYMAP = _Same()


def curated(bodymap):
    reqs, ios, prots = [], [], []
    for r in tsv_read(os.path.join(REPO, 'docs/l1/request-codes.tsv')):
        key = KEYMAP[r['package']]
        load, body = bodymap[key]
        a = int(r['handler'], 16)
        inside = load <= a < load + len(body) and a % 2 == 0
        st = 'understood' if inside and r['grade'] in ('established', 'inferred') and len(r['note'].split()) >= 4 else 'located'
        reqs.append({'image': key, 'task': r['task'], 'code': r['code'], 'handler': '0x%08x' % a,
                     'name': r['name'], 'grade': r['grade'], 'handler_in_body': 'yes' if inside else 'NO',
                     'note': r['note'], 'status': st, 'doc': 'docs/l1/request-codes.tsv'})
    for r in tsv_read(os.path.join(REPO, 'docs/l1/io-registers.tsv')):
        ok = r['grade'] in ('established', 'inferred') and len(r['evidence'].split()) >= 4
        ios.append({'image': KEYMAP[r['package']], 'device': r['device'], 'window_base': r['window_base'],
                    'offset': r['offset'], 'width_bits': r['width_bits'], 'name': r['name'], 'access': r['access'],
                    'grade': r['grade'], 'evidence': r['evidence'], 'status': 'understood' if ok else 'located',
                    'doc': 'docs/l1/io-registers.tsv'})
    for r in tsv_read(os.path.join(REPO, 'docs/l1/protocols.tsv')):
        key = KEYMAP[r['package']]
        chk = check_cell(r['check'], bodymap[key][1])
        ok = r['grade'] in ('established', 'inferred') and chk != 'MISMATCH' and len(r['evidence'].split()) >= 2
        prots.append({'image': key, 'protocol': r['protocol'], 'element': r['element'], 'value': r['value'],
                      'grade': r['grade'], 'evidence': r['evidence'], 'byte_check': chk,
                      'status': 'understood' if ok else 'located', 'doc': 'docs/l1/protocols.tsv'})
    return reqs, ios, prots


def status_of_image(rec):
    for k in (rec['sha256'], rec['sha256'][:16]):
        d = cited(k)
        if d:
            # a container whose version, size, hash and layout are tabulated in the versions note is understood
            if rec.get('kind') in ('L1 firmware container', 'L2 firmware image') and rec.get('version') \
                    and d == 'docs/firmware-versions.md':
                return 'understood', d
            return 'located', d
    return 'undocumented', ''


def update_coverage(summary, images, pkgs):
    path = os.path.join(REPO, 'docs', 'coverage.md')
    if not os.path.exists(path):
        return
    text = open(path, encoding='utf-8').read()
    b, e = '<!-- firmware:begin -->', '<!-- firmware:end -->'
    if b not in text or e not in text:
        return
    sets = collections.OrderedDict()
    for r in images:
        if r['kind'] in ('L1 firmware container', 'L2 firmware image'):
            sets.setdefault(r['release'], []).append('%s %s' % (r['kind'].split()[0], r['version']))
    lines = [b, '## Measured firmware coverage', '',
             'Generated by `scripts/sysco_tables.py` from %d distinct files and %d L1 packages under `root/`. '
             'Rows are in [docs/inventory/](inventory/README.md). Understood means a curated entry gives the row a grade, '
             'a role and a locator and its byte checks pass; located means a note cites its address, offset or hash.' % (
                 len(images), len(pkgs)), '',
             'Sets read: ' + '; '.join('%s (%s)' % (k, ', '.join(v)) for k, v in sets.items()) + '.', '',
             '| Table | Rows | Understood | Located | Undocumented | % understood | % located or better |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for s in summary:
        lines.append('| [%s](inventory/%s.tsv) | %d | %d | %d | %d | %s | %s |' % (
            s['table'], s['table'], s['rows'], s['understood'], s['located'], s['undocumented'],
            s['pct_understood'], s['pct_located_or_better']))
    lines += ['', 'All understood rows are for L1 1.44.0 package 1 (Origin 300). The function table lists candidate entries '
              'of every distinct ColdFire body, found by byte pattern; it is a worklist, not a function count.', e]
    i, j = text.index(b), text.index(e) + len(e)
    open(path, 'w', encoding='utf-8', newline='\n').write(text[:i] + '\n'.join(lines) + text[j:])


def main():
    os.makedirs(OUT, exist_ok=True)
    images, pkgs, funcs, files = build()
    for r in images:
        r['status'], r['doc'] = status_of_image(r)
    for r in pkgs:
        s, d = status_of_image({'sha256': r['sha256']})
        r['status'], r['doc'] = s, d
    # a Linux package is understood once a curated row grades its layout
    linux_rows = {r['package']: r for r in tsv_read(os.path.join(REPO, 'docs/l1/packages.tsv'))}
    for r in pkgs:
        c = linux_rows.get(r['key'])
        if c and c['grade'] in ('established', 'inferred') and len(c['role'].split()) >= 4 and c['locator']:
            r['status'], r['doc'] = 'understood', 'docs/l1/packages.tsv'
    bodymap = bodies(pkgs)
    reqs, ios, prots = curated(bodymap)
    tsv_write('images', ['path', 'release', 'kind', 'arch', 'version', 'bytes', 'sha256', 'copies', 'detail', 'status', 'doc'], images)
    tsv_write('packages', ['key', 'release', 'index', 'offset', 'length', 'sha256', 'family', 'label', 'version', 'build_stamp',
                           'detail', 'status', 'doc'], pkgs)
    tsv_write('firmware-functions', ['image', 'address', 'evidence', 'name', 'grade', 'status', 'doc'], funcs)
    tsv_write('arm-linux-files', ['package', 'path', 'type', 'mode', 'bytes', 'sha256', 'target'], files)
    tsv_write('request-codes', ['image', 'task', 'code', 'handler', 'name', 'grade', 'handler_in_body', 'note', 'status', 'doc'], reqs)
    tsv_write('io-registers', ['image', 'device', 'window_base', 'offset', 'width_bits', 'name', 'access', 'grade', 'evidence',
                               'status', 'doc'], ios)
    tsv_write('protocols', ['image', 'protocol', 'element', 'value', 'grade', 'evidence', 'byte_check', 'status', 'doc'], prots)
    summary = []
    for name, rows in (('images', images), ('packages', pkgs), ('firmware-functions', funcs), ('request-codes', reqs),
                       ('io-registers', ios), ('protocols', prots)):
        c = collections.Counter(r['status'] for r in rows)
        n = len(rows)
        summary.append({'table': name, 'rows': n, 'understood': c['understood'], 'located': c['located'],
                        'undocumented': c['undocumented'],
                        'pct_understood': '%.1f' % (100.0 * c['understood'] / n) if n else '0.0',
                        'pct_located_or_better': '%.1f' % (100.0 * (c['understood'] + c['located']) / n) if n else '0.0'})
    tsv_write('firmware-summary', ['table', 'rows', 'understood', 'located', 'undocumented', 'pct_understood',
                                   'pct_located_or_better'], summary)
    update_coverage(summary, images, pkgs)
    for r in reqs:
        if r['handler_in_body'] != 'yes':
            print('handler outside body:', r['code'], r['handler'], file=sys.stderr)
    for r in prots:
        if r['byte_check'] == 'MISMATCH':
            print('byte check failed:', r['element'], file=sys.stderr)
    bad = [r for r in reqs if r['handler_in_body'] != 'yes'] + [r for r in prots if r['byte_check'] == 'MISMATCH']
    for s in summary:
        print('%-14s %6d rows  understood %5d  located %5d  undocumented %6d  (%s%% understood, %s%% located or better)' % (
            s['table'], s['rows'], s['understood'], s['located'], s['undocumented'], s['pct_understood'], s['pct_located_or_better']))
    if bad:
        print('FAIL: %d curated rows do not match the images' % len(bad), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
