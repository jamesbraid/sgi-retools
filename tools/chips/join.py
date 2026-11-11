#!/usr/bin/env python3
"""Stage 4: join scanned accesses with the datasheet, the spec and the model.

Usage: join.py CONFIG.json --sites sites.tsv --ref ref.json --out PREFIX
                [--unresolved unresolved.tsv] [--stats scan-stats.json]

Writes PREFIX-census.tsv (one row per variant and register slot), PREFIX-census-sites.tsv
(every access site with its row's classes), and PREFIX-census.summary.json, which
the report stage turns into prose.

Classes
  datasheet   listed | absent
  spec        present | absent | conflict-access | n/a (no published specification)
  model        handled-specified: the model has the register and the datasheet lists it
              handled-guessed:   the model has it but the datasheet does not, or the model
                                 says it chose the value, stores the word whole, or logs
                                 LOG_UNIMP for it
              unhandled:         the model has no entry (an undefined-address error)

Address spaces: a site's scan window can name a space other than the register space (a config's
"address_spaces", for example the local boot space reached through its own window). The space is part of the
row key, so an access there never merges with a register row at the same offset; those rows carry the space
name, are not compared with any datasheet or model, and fold to their own slot size.

Variants come from the scan: the discriminator compare on the path to the access. A site
whose path names several variants counts once for each; a site whose path names none is
variant "?", classified against every variant and listed as such.
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
import slots  # noqa: E402


def norm_access(a):
    a = (a or '').lower()
    if 'read/write' in a or 'readable and writable' in a:
        return 'rw'
    if 'write only' in a or a.strip() in ('writable', 'write-only'):
        return 'wo'
    if 'read only' in a or a.strip() in ('readable', 'read-only'):
        return 'ro'
    return ''


def covers(e, slot):
    if e['kind'] == 'region':
        return slot >= 0x10000 and e['lo'] <= slot <= e['hi']
    if slot >= 0x10000:
        return e['lo'] <= slot <= e['hi']
    if not e['lo'] <= slot <= e['hi']:
        return False
    # a family ("0x108 + 64xn") covers only the offsets one stride apart, not every slot between its ends
    stride = e.get('stride', 8)
    if stride > 8 and e['hi'] > e['lo']:
        return (slot - e['lo']) % stride == 0
    return True


def find(entries, slot):
    return [e for e in entries if covers(e, slot)]


def ref_str(es):
    if not es:
        return ''
    e = es[0]
    return '%s:%s %s' % (e['source'], e['line'], e['section'][:40])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('config')
    ap.add_argument('--sites', required=True)
    ap.add_argument('--ref', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--unresolved')
    ap.add_argument('--stats')
    a = ap.parse_args()
    cfg = json.load(open(a.config))
    ref = json.load(open(a.ref))
    model = cfg.get('variant_model', {})
    slot_of, part_of = slots.make(cfg)
    space_of = slots.space_of(cfg)
    big = cfg.get('collapse_above', 0x10000)
    sites = list(csv.DictReader(open(a.sites), delimiter='\t'))

    rows = collections.OrderedDict()
    windows = collections.OrderedDict()
    buckets = cfg.get('buckets', [])
    site_rows = []
    for s in sites:
        off = int(s['offset'], 16)
        space = space_of(s['window'])
        s = dict(s, space=space)
        slot = slot_of(off, space)
        if off >= big and not space:
            # array regions (translation entries, write-request RAM, configuration windows): a loop's
            # unrolled iterations are one row per 0x800-byte bucket, flagged as indexed
            slot, s = off & ~0x7ff, dict(s, idx='1')
        bk = None if space else next((b for b in buckets if b['lo'] <= off < b['lo'] + b['size']), None)
        if bk:
            # an access through a PCI device window or the flash window: not this ASIC's register,
            # so it is handed to the census of whatever sits behind it
            wk = (bk['name'], off - bk['lo'], s['rw'], int(s['width']))
            w = windows.setdefault(wk, {'sites': 0, 'funcs': set(), 'images': set(), 'example': ''})
            w['sites'] += 1
            w['funcs'].add(s['function'])
            w['images'].add(s['image'])
            w['example'] = w['example'] or '%s@%s' % (s['function'], s['addr'][-6:])
            continue
        vs = s['variant'].split('|')
        for v in vs:
            key = (v, space, slot, s['idx'])
            r = rows.setdefault(key, {'rw': set(), 'widths': set(), 'halves': set(), 'sites': 0,
                                      'funcs': set(), 'images': set(), 'example': '', 'insns': set(),
                                      'flags': set(), 'bases': set(), 'window': s['window']})
            r['rw'].add(s['rw'])
            r['widths'].add(int(s['width']))
            r['halves'].add(part_of(off, space))
            r['sites'] += 1
            r['funcs'].add(s['function'])
            r['images'].add(s['image'])
            r['bases'].add(s['basis'])
            r['insns'].add(s['insn'])
            if not r['example']:
                r['example'] = '%s@%s' % (s['function'], s['addr'][-6:])
            m = model.get(v, model.get('default', {}))
            w = int(s['width'])
            if space:
                pass
            elif slot < 0x10000 and m.get('access') == 'half32' and w:
                if w == 8:
                    r['flags'].add('64-bit access to a 32-bit register')
                if w == 4 and part_of(off) == 0:
                    r['flags'].add('32-bit access to the high half')
            if not space and slot < 0x10000 and m.get('access') == 'dw64' and w == 4:
                r['flags'].add('32-bit access to a 64-bit register')
            if int(s['partial']):
                r['flags'].add('partial-word access')

    out_rows = []
    for (v, space, slot, idx), r in rows.items():
        vs = [v] if v in ref else ([x for x in ref] if v == '?' else [])
        if v == 'probe?' or space:
            vs = []
        ds, sp, qm = [], [], []
        for x in vs:
            ds += find(ref[x]['datasheet'], slot)
            sp += find(ref[x]['spec'], slot)
            qm += find(ref[x]['model'], slot)
        spec_exists = any(ref[x]['spec_present'] for x in vs)
        dsc = 'listed' if ds else 'absent'
        if not vs:
            dsc = 'no-datasheet'
        if not vs:
            spc = 'n/a'
        elif not spec_exists:
            spc = 'n/a'
        elif slot >= big:
            spc = 'not-transcribed'
        elif not sp:
            spc = 'absent'
        else:
            spc = 'present'
            for d in ds:
                for e in sp:
                    da, ea = norm_access(d.get('access')), norm_access(e.get('access'))
                    if da and ea and da != ea:
                        spc = 'conflict-access'
        if space:
            dsc, qc, qd = 'n/a', 'out-of-scope', 'access through the %s window: not a register of this ASIC' % space
        elif cfg.get('mode') == 'no-spec' and vs and not ds and not qm:
            dsc, qc, qd = 'n/a', 'n/a', 'no-spec mode: no datasheet or model compared'
        elif not vs:
            qc, qd = 'out-of-scope', 'variant has no emulator datasheet or model here (hand off to its own census)'
        elif not qm:
            qc, qd = 'unhandled', 'no model entry; undefined-address path'
        else:
            unimp = [e for e in qm if e.get('unimp')]
            guessed = [e for e in qm if e.get('guessed')]
            if unimp:
                qc, qd = 'handled-guessed', unimp[0]['note']
            elif guessed:
                qc, qd = 'handled-guessed', guessed[0].get('note', '')
            elif not ds:
                qc, qd = 'handled-guessed', 'model handles it; datasheet does not list it'
            else:
                qc, qd = 'handled-specified', qm[0]['name']
        tasks = []
        if space:
            tasks.append('identify what the %s holds' % space)
        elif dsc == 'n/a':
            tasks.append('no-spec: inventory from the binaries')
        elif not vs:
            tasks.append('variant out of scope')
        if space:
            pass
        elif dsc == 'absent' and spc in ('present', 'conflict-access'):
            tasks.append('datasheet omits a register the spec lists')
        elif dsc == 'absent' and spc == 'absent':
            tasks.append('in neither datasheet nor spec: identify or mark kernel-only')
        elif dsc == 'absent':
            tasks.append('datasheet gap (no spec to check)')
        if dsc == 'listed' and spc == 'absent':
            tasks.append('datasheet lists it, spec does not')
        if spc == 'conflict-access':
            tasks.append('datasheet and spec disagree on access')
        if qc == 'unhandled':
            tasks.append('model task: unhandled')
        elif qc == 'handled-guessed':
            tasks.append('model task: guessed or deferred')
        name = (ds or sp or qm or [{'name': ''}])[0]['name'] if (ds or sp or qm) else ''
        # hand-written names a config carries for a chip with no specification (register_names)
        name = name or cfg.get('register_names', {}).get('0x%x' % slot, '')
        out_rows.append({
            'variant': v, 'space': space, 'offset': '0x%x' % slot, 'idx': idx, 'name': name,
            'access_seen': ''.join(sorted(r['rw'])), 'widths': ','.join(str(w) for w in sorted(r['widths'])),
            'halves': ','.join(str(h) for h in sorted(r['halves'])), 'sites': r['sites'],
            'functions': len(r['funcs']), 'images': ','.join(sorted(r['images'])),
            'example': r['example'], 'datasheet': dsc, 'datasheet_ref': ref_str(ds),
            'spec': spc, 'spec_ref': ref_str(sp), 'model': qc, 'model_detail': qd[:100],
            'flags': '; '.join(sorted(r['flags'])), 'tasks': '; '.join(tasks),
            '_slot': slot,
        })
    out_rows.sort(key=lambda x: (x['variant'], x['space'], x['_slot'], x['idx']))
    cols = ['variant', 'space', 'offset', 'idx', 'name', 'access_seen', 'widths', 'halves', 'sites', 'functions',
            'images', 'example', 'datasheet', 'datasheet_ref', 'spec', 'spec_ref', 'model', 'model_detail',
            'flags', 'tasks']
    with open(a.out + '-census.tsv', 'w') as f:
        f.write('\t'.join(cols) + '\n')
        for r in out_rows:
            f.write('\t'.join(str(r[c]) for c in cols) + '\n')

    # registers the references list that no scanned access reaches. A row whose index we could
    # not see (idx=1) stands for a run of registers starting at its offset: it is taken to reach
    # entries that start within IDX_EXTENT bytes above it, so a family is not listed as unreached
    # just because the loop index is invisible. That assumption is stated in the report.
    IDX_EXTENT = 0x40
    unreached = {}
    touched = collections.defaultdict(set)
    run_start = collections.defaultdict(set)
    for (v, space, slot, idx) in rows:
        if space:
            continue        # a boot-space access reaches no register the references list
        touched[v].add(slot)
        if idx == '1':
            run_start[v].add(slot)
    for v, rr in ref.items():
        got = touched[v] | touched['?']
        starts = run_start[v] | run_start['?']
        un = collections.OrderedDict()
        for kind in ('datasheet', 'spec'):
            for e in rr[kind]:
                if e['kind'] != 'register' or e['hi'] >= big:
                    continue
                span = range(e['lo'], e['hi'] + 1, 8) if e['hi'] > e['lo'] else [e['lo']]
                if any(x in got for x in span) or any(st <= e['lo'] < st + IDX_EXTENT for st in starts):
                    continue
                key = (e['lo'], e['hi'])
                d = un.setdefault(key, {'offset': '0x%x' % e['lo'] + ('..0x%x' % e['hi'] if e['hi'] > e['lo'] else ''),
                                        'name': e['name'], 'listed_in': []})
                d['listed_in'].append('%s %s:%s' % (kind, e['source'], e['line']))
        unreached[v] = list(un.values())

    summary = {'rows': len(out_rows), 'sites': len(sites), 'by_variant': {}, 'unreached': unreached}
    for v in sorted({r['variant'] for r in out_rows}):
        rs = [r for r in out_rows if r['variant'] == v]
        summary['by_variant'][v] = {
            'rows': len(rs), 'sites': sum(int(r['sites']) for r in rs),
            'model': dict(collections.Counter(r['model'] for r in rs)),
            'datasheet': dict(collections.Counter(r['datasheet'] for r in rs)),
            'spec': dict(collections.Counter(r['spec'] for r in rs)),
        }
    json.dump(summary, open(a.out + '-census.summary.json', 'w'), indent=1)
    wcols = ['window', 'inner_offset', 'rw', 'width', 'sites', 'functions', 'images', 'example']
    with open(a.out + '-census-windows.tsv', 'w') as f:
        f.write('\t'.join(wcols) + '\n')
        for (name, inner, rw, width), w in sorted(windows.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            f.write('\t'.join(str(x) for x in (name, hex(inner), rw, width, w['sites'], len(w['funcs']),
                                              ','.join(sorted(w['images'])), w['example'])) + '\n')
    summary['window_rows'] = len(windows)
    summary['window_sites'] = sum(w['sites'] for w in windows.values())
    json.dump(summary, open(a.out + '-census.summary.json', 'w'), indent=1)
    sc = ['image', 'function', 'addr', 'insn', 'rw', 'width', 'offset', 'idx', 'variant', 'space', 'basis']
    with open(a.out + '-census-sites.tsv', 'w') as f:
        f.write('\t'.join(sc) + '\n')
        for s in sites:
            f.write('\t'.join(s[c] if c != 'space' else space_of(s['window']) for c in sc) + '\n')
    print(json.dumps({k: summary[k] for k in ('rows', 'sites')}))
    for v, d in summary['by_variant'].items():
        print(v, d['rows'], d['model'], d['datasheet'], d['spec'])


if __name__ == '__main__':
    main()
