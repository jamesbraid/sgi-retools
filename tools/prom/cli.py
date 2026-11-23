"""promkit identify IMAGE..., unpack IMAGE and validate FILE.... Exit 0 clean, 1 a check failed, 2 a usage or setup problem."""
import argparse
import hashlib
import json
import os
import sys

from . import analyze, catalog
from .model import ContainerError, document, tool_revision
from .schema import SchemaError, validate


def _read(path):
    with open(path, 'rb') as f:
        return f.read()


def _row(index, an):
    """The index row of the file, else of the file with its transforms undone (a swapped dump)."""
    row = index.get(an.sha256)
    if row is None and an.transforms:
        row = index.get(hashlib.sha256(an.data).hexdigest())
    return row


def identify(args, index):
    status = 0
    for path in args.images:
        data = _read(path)
        an = analyze(data)
        row = _row(index, an)
        doc = {'file': os.path.basename(path), 'sha256': an.sha256, 'catalog': row, 'byte_order': an.byte_order,
               'transforms': [t['name'] for t in an.transforms], 'container': '>'.join(an.containers),
               'segments': len(an.segments), 'checks_ok': an.ok}
        if args.json:
            print(json.dumps(doc, sort_keys=True))
        else:
            what = '%s %s%s' % (row['board'], row['version'], ' rev ' + row['rev'] if row['rev'] else '') if row else 'uncatalogued'
            print('%s  %s  %s  %s  %s%s' % (an.sha256, what, an.byte_order, doc['container'],
                                            ','.join(doc['transforms']) + ' ' if doc['transforms'] else '',
                                            '' if an.ok else 'CHECK FAILED'))
        status |= 0 if an.ok else 1
    return status


def unpack(args, index):
    data = _read(args.image)
    an = analyze(data)
    out = args.out or os.path.join('.cache', 'prom', an.sha256[:16])
    files = {i: '%s.%s.bin' % (args.label, s.name) if args.label else 'segments/%s.bin' % s.name
             for i, s in enumerate(an.segments)}
    here = os.path.dirname(os.path.abspath(__file__))
    doc = document(an, os.path.basename(args.image), files, _row(index, an), tool_revision(here))
    validate(doc)       # a document the schema refuses is a bug here; nothing is written for it
    os.makedirs(out if args.label else os.path.join(out, 'segments'), exist_ok=True)
    for i, s in enumerate(an.segments):
        with open(os.path.join(out, files[i]), 'wb') as f:
            f.write(s.data)
    path = os.path.join(out, os.path.basename(args.image) + '.prom.json')
    with open(path, 'w') as f:
        json.dump(doc, f, indent=2)
        f.write('\n')
    print(path)
    for s in an.segments:
        for c in s.checks:
            if not c.ok:
                print('check failed: %s %s %s' % (s.name, c.rule, c.detail), file=sys.stderr)
    return 0 if an.ok else 1


def check_files(args, index):
    status = 0
    for path in args.files:
        try:
            with open(path, encoding='utf-8') as f:
                validate(json.load(f))
            print('%s: ok' % path)
        except SchemaError as e:
            print('%s: %s' % (path, e), file=sys.stderr)
            status = 1
    return status


def main(argv=None):
    p = argparse.ArgumentParser(prog='promkit', description='Identify and unpack SGI PROM images.')
    sub = p.add_subparsers(dest='cmd', required=True)
    for name in ('identify', 'unpack'):
        s = sub.add_parser(name)
        s.add_argument('--catalog', help='a local copy of the PROM index (default: cached .cache/prom/index.json)')
        s.add_argument('--refresh', action='store_true', help='fetch the PROM index again (unpack otherwise only reads a cached or given one)')
        if name == 'identify':
            s.add_argument('images', nargs='+')
            s.add_argument('--json', action='store_true')
        else:
            s.add_argument('image')
            s.add_argument('--out', help='output directory (default .cache/prom/<sha256 prefix>)')
            s.add_argument('--label', help='name segments LABEL.<segment>.bin in --out, with no segments/ directory')
    sub.add_parser('validate', help='check sgi-prom files against the schema').add_argument('files', nargs='+')
    args = p.parse_args(argv)
    try:
        index = None if args.cmd == 'validate' else catalog.load(
            args.catalog, args.refresh, lambda m: print('promkit: ' + m, file=sys.stderr), fetch=args.cmd == 'identify')
        return {'identify': identify, 'unpack': unpack, 'validate': check_files}[args.cmd](args, index)
    except (OSError, ValueError, ContainerError, SchemaError) as e:
        print('promkit: %s' % e, file=sys.stderr)
        return 2
