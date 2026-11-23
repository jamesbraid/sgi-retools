#!/usr/bin/env python3
"""Decompile the functions of one PROM segment with m2c, one function to a file.

  tools/re-run python3 retools/tools/m2c_flat.py --prom X.prom.json --code X.code.json --segment NAME [options]

Runs in the toolchain image, which has m2c and spimdisasm. Input is a promkit `prom.json`, a code file
(functions, jump tables and calls, as the code export writes it) and the name of a segment of the image.
spimdisasm's command line misplaces the data of a segment whose regions do not run at their offsets, so this
drives its Python API: one text section per function, one read-only section per jump table, every callee
named from the code file and a `jlabel` at every jump-table target. Each function then goes to its own m2c
process, so a branch m2c rejects fails that function and nothing else.

Output, all under --out (default .cache/m2c/<image sha256 prefix>/<segment> in the working directory, which
must be git-ignored when it is inside a repository):
  asm/ENTRY.s, c/ENTRY.c, c/ENTRY.err  the input and output of each function, ENTRY the address in hex
The one file that leaves that directory is the status file (--status, default <image>.m2c-status.json beside
the prom file): per function its entry, whether m2c finished (complete), finished with an M2C_ERROR or a read
of an unset register (partial) or did not (failed, with a reason and the first error line), the m2c commit and
the spimdisasm version. It carries no C. m2c output is navigation; it is never committed.

Options:
  --abi o32|n32      spimdisasm's ABI (default o32);  --arch 1..5   MIPS architecture level (default 3)
  --target TRIPLE    m2c's target (default mips)
  --cpu-seconds N    CPU limit for each m2c process (default 120). A function that hits it is failed, reason
                     limit. CPU time varies far less with host load than wall time, but is not exact, so the
                     code export ignores the status of such a function
"""
import argparse
import hashlib
import json
import os
import re
import resource
import subprocess
import sys

M2C_COMMIT_FILE = '/opt/m2c/COMMIT'
# What an assembler label and an m2c argument may safely be; anything else is replaced by fn_<entry>.
SAFE_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.$]*')
PARTIAL = re.compile(r'M2C_ERROR|Read from unset register')
FAILED = re.compile(r'Decompilation failure in function')


def die(message):
    sys.exit('m2c_flat: ' + message)


def hexs(n):
    return '0x%x' % n


class RegionError(Exception):
    """An address range that is not inside one region of the segment."""


class Segment:
    """The bytes of one segment and where its regions sit in the address space."""

    def __init__(self, prom, name, path):
        row = [s for s in prom['segments'] if s['name'] == name]
        if not row:
            die('no segment %s in the prom file (it has %s)' % (name, ', '.join(s['name'] for s in prom['segments'])))
        self.name = name
        with open(path, 'rb') as f:
            self.data = f.read()
        self.regions = [(int(r['address'], 16), int(r['offset'], 16), int(r['length'], 16), r['kind'])
                        for r in row[0]['regions'] if r['offset'] is not None and r['kind'] in ('code', 'readonly')]
        if len(self.data) != int(row[0]['length'], 16):
            die('%s is %d bytes, the prom file says the segment is %s' % (path, len(self.data), row[0]['length']))

    def bytes_at(self, address, length, kinds=('code', 'readonly')):
        """(offset in the segment, bytes) of LENGTH bytes at ADDRESS, which must lie inside one region."""
        for base, offset, size, kind in self.regions:
            if kind in kinds and base <= address and address + length <= base + size:
                start = offset + address - base
                return start, self.data[start:start + length]
        raise RegionError('%#x..%#x is not inside one %s region of %s' % (address, address + length, '/'.join(kinds), self.name))


def load_code(path, segment):
    """Functions, tables and call targets of SEGMENT from a code file, sorted by address."""
    with open(path) as f:
        code = json.load(f)
    names = {}
    functions = []
    for fn in code['functions']:
        if fn['segment'] != segment:
            continue
        entry, end = int(fn['entry'], 16), int(fn['end'], 16)
        name = fn['name'] if fn['name'] and SAFE_NAME.fullmatch(fn['name']) else 'fn_%x' % entry
        names[entry] = name
        functions.append({'entry': entry, 'end': end, 'name': name})
    functions.sort(key=lambda f: f['entry'])
    for a, b in zip(functions, functions[1:]):
        if b['entry'] < a['end']:
            die('functions %s and %s overlap' % (a['name'], b['name']))
    tables = {}
    for jt in code.get('jump_tables', []):
        fn = int(jt['function']['address'], 16)
        if jt['function']['segment'] != segment:
            continue
        tables.setdefault(fn, []).append({'table': int(jt['table']['address'], 16),
                                          'targets': [int(t['address'], 16) for t in jt['targets']]})
    calls = {}
    for c in code.get('calls', []):
        if c['from']['segment'] == segment and c['to'] is not None and c['to']['segment'] == segment:
            calls.setdefault(int(c['from']['address'], 16), set()).add(int(c['to']['address'], 16))
    return functions, names, tables, calls


def disassemble(seg, fn, names, tables, calls, abi, arch):
    """The assembly m2c reads for one function: its text, then its jump tables with a jlabel at each target."""
    from spimdisasm import common, mips
    cfg = common.GlobalConfig
    cfg.ABI = {'o32': common.Abi.O32, 'n32': common.Abi.N32}[abi]
    cfg.ARCHLEVEL = common.ArchLevel(arch)
    cfg.ENDIAN = common.InputEndian.BIG
    cfg.GLABEL_ASM_COUNT = False
    cfg.ASM_USE_PRELUDE = False
    cfg.ASM_GENERATED_BY = False
    cfg.ASM_COMMENT = False
    cfg.ASM_NM_LABEL = ''
    cfg.QUIET = True
    ctx = common.Context()
    entry, end = fn['entry'], fn['end']
    ctx.globalSegment.addFunction(entry).name = fn['name']
    for target in sorted(calls.get(entry, ())):
        if target in names and target != entry:
            ctx.globalSegment.addFunction(target).name = names[target]
    parts = ['.set noat', '.set noreorder', '.text']
    start, text = seg.bytes_at(entry, end - entry, ('code',))
    for jt in tables.get(entry, []):
        sym = ctx.globalSegment.addJumpTable(jt['table'])
        sym.name = 'jtbl_%X' % jt['table']   # the name its own label gets, so the load and the table agree
        for t in jt['targets']:
            ctx.globalSegment.addJumpTableLabel(t)
    section = mips.sections.SectionText(ctx, 0, len(text), entry, fn['name'], text, 0, None)
    rods = []
    for jt in tables.get(entry, []):
        size = 4 * len(jt['targets'])
        _, raw = seg.bytes_at(jt['table'], size)
        rods.append(mips.sections.SectionRodata(ctx, 0, size, jt['table'], fn['name'], raw, 0, None))
    section.analyze()
    for r in rods:
        r.analyze()
    # spimdisasm labels the function it analysed T_<ADDRESS>, whatever the context calls it; m2c finds a
    # function by its label.
    parts += [s.disassemble().replace('T_%08X' % entry, fn['name']) for s in section.symbolList]
    if rods:
        parts.append('.section .rodata')
        for r in rods:
            parts += [s.disassemble() for s in r.symbolList]
    return '\n'.join(parts) + '\n'


def run_m2c(m2c, target, asm, name, cpu_seconds):
    """(status, reason, first error line, C text) of one m2c process under a CPU limit."""
    def limit():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    p = subprocess.run([m2c, '-t', target, '--function=' + name, asm], capture_output=True, text=True, preexec_fn=limit)
    out, err = p.stdout, p.stderr
    if p.returncode < 0:
        # SIGXCPU is the soft CPU limit; SIGKILL is the hard limit or the kernel's out-of-memory killer.
        reason = {24: 'limit', 9: 'killed'}.get(-p.returncode, 'signal %d' % -p.returncode)
        return 'failed', reason, '', out
    first = next((l.strip() for l in (err + out).splitlines() if FAILED.search(l) or l.strip().startswith('Error')), '')
    if p.returncode != 0 or FAILED.search(out) or FAILED.search(err):
        return 'failed', 'exit %d' % p.returncode, first or (err.strip().splitlines() or [''])[0], out
    return ('partial' if PARTIAL.search(out) else 'complete'), None, '', out


def refuse_tracked_out(out):
    """--out may not be a place git would commit: a work tree where it is not ignored."""
    top = subprocess.run(['git', '-C', out, 'rev-parse', '--show-toplevel'], capture_output=True, text=True)
    if top.returncode == 0 and subprocess.run(['git', '-C', out, 'check-ignore', '-q', '.'],
                                              capture_output=True).returncode != 0:
        die('--out %s is inside the git work tree %s and is not ignored; m2c output is never committed'
            % (out, top.stdout.strip()))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--prom', required=True)
    ap.add_argument('--code', required=True)
    ap.add_argument('--segment', required=True)
    ap.add_argument('--segment-file', help='the segment bytes (default: the file the prom file names, beside it)')
    ap.add_argument('--out')
    ap.add_argument('--status')
    ap.add_argument('--abi', choices=('o32', 'n32'), default='o32')
    ap.add_argument('--arch', type=int, choices=range(1, 6), default=3)
    ap.add_argument('--target', default='mips')
    ap.add_argument('--cpu-seconds', type=int, default=120)
    ap.add_argument('--m2c', default='m2c')
    args = ap.parse_args(argv)
    with open(args.prom) as f:
        prom = json.load(f)
    row = [s for s in prom['segments'] if s['name'] == args.segment]
    path = args.segment_file or (os.path.join(os.path.dirname(os.path.abspath(args.prom)), row[0]['file']) if row else None)
    seg = Segment(prom, args.segment, path)
    sha = prom['identity']['sha256']
    out = args.out or os.path.join('.cache', 'm2c', sha[:16], args.segment)
    os.makedirs(out, exist_ok=True)
    refuse_tracked_out(os.path.abspath(out))
    for sub in ('asm', 'c'):
        os.makedirs(os.path.join(out, sub), exist_ok=True)
    functions, names, tables, calls = load_code(args.code, args.segment)
    import spimdisasm
    try:
        with open(M2C_COMMIT_FILE) as f:
            commit = f.read().strip()
    except OSError:
        commit = 'unknown'
    rows = []
    for fn in functions:
        stem = '%08x' % fn['entry']
        asm = os.path.join(out, 'asm', stem + '.s')
        try:
            with open(asm, 'w') as f:
                f.write(disassemble(seg, fn, names, tables, calls, args.abi, args.arch))
            status, reason, first, text = run_m2c(args.m2c, args.target, asm, fn['name'], args.cpu_seconds)
        except RegionError as e:
            status, reason, first, text = 'failed', 'region', str(e), ''
        with open(os.path.join(out, 'c', stem + '.c'), 'w') as f:
            f.write(text)
        if first:
            with open(os.path.join(out, 'c', stem + '.err'), 'w') as f:
                f.write(first + '\n')
        row = {'segment': args.segment, 'entry': hexs(fn['entry']), 'status': status}
        if status == 'failed':
            row['reason'] = reason
            row['message'] = first
        rows.append(row)
        print('%s %s %s' % (hexs(fn['entry']), fn['name'], status + (' (%s)' % reason if reason else '')), file=sys.stderr)
    status_path = args.status or re.sub(r'\.prom\.json$|\.json$', '', args.prom) + '.m2c-status.json'
    doc = {'image': {'sha256': sha}, 'm2c': commit, 'spimdisasm': spimdisasm.__version__,
           'functions': sorted(rows, key=lambda r: int(r['entry'], 16))}
    with open(status_path, 'w') as f:
        json.dump(doc, f, indent=2)
        f.write('\n')
    print(status_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
