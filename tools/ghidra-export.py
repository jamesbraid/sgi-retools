#!/usr/bin/env python3
"""Plan and finish a Ghidra decompile export or BSim load of one ELF object.

Not run directly: `tools/re-run --ghidra-export OBJECT [OPTIONS]` runs `prepare`,
then Ghidra in its own image, then `finish`, and prints where the JSON landed.
`prepare` and `finish` run in the toolchain image (they need pyelftools).

Options (after OBJECT, a path inside the repository):
  --decompile-symbol NAME|GLOB|@0xADDR   a function by name, a glob with *, or an
                                          address (not for a relocatable object);
                                          repeatable
  --decompile-list FILE                   one name, glob or @address per line
  --decompile-all                         every function Ghidra found
  --decompile-timeout SECONDS             per function (default 60)
  --types SPEC.json                       structure types to apply first (see
                                          ghidra/README.md)
  --mdebug                                import the object's .mdebug symbol table
                                          (names, line numbers, types, procedure
                                          signatures); a 32-bit MIPSpro object only
  --bsim-db NAME --bsim-label LABEL       match the object against BSim database
                                          NAME, then add it under LABEL
  --bsim-dir DIR  --bsim-min SIMILARITY   database directory (default
                                          .cache/ghidra-bsim), lowest similarity
                                          written (default 0.7)
  --timeout SECONDS  --cpus N             Ghidra analysis limits (3600, 2)

Output goes under .cache/ghidra-export/ (ignored by git): decompile.json holds one
entry per function with the decompiler's C, warnings and signature. Decompiler
output and BSim similarity are navigation, not evidence: a committed claim still
rests on the disassembly.

An ELF object (a linked library, a kernel or a relocatable driver object) takes its
language and calling convention from its header; names the loader ignores (.mdebug)
are seeded before analysis.

A flat image, such as a PROM, has no header Ghidra can read, so say what it is:
  --flat                 read OBJECT as raw bytes
  --load ADDR            the address the first byte (after --header) has in the
                         machine's address space, for example 0x1fc00000
  --header N             skip N bytes of container header first (default 0)
  --processor LANG       Ghidra language (default MIPS:BE:64:default, which holds
                         the 64-bit pointers a PROM's code uses). MIPS:BE:64:64-32addr
                         has 32-bit addresses; MIPS:BE:32:default is for a 32-bit
                         processor
  --window ADDR          for a 64-bit language, the upper bits the image is placed
                         under so a program that holds 64-bit pointers (a PROM
                         running in the extended cached window) resolves them;
                         default 0xc000000000000000 for a language with full-width
                         64-bit addresses, none otherwise
A flat image has no names: functions are `FUN_` placeholders, found by Ghidra's
analysis, so ask for them by `@0xADDR` or with --decompile-all. `address` in the
JSON is the machine address (--load), `ghidra_address` is where Ghidra holds it, and
the C text uses Ghidra's addresses.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import struct
import sys

EVIDENCE = 'decompiler output is navigation, not evidence'
SCRIPTS = '/opt/re-scripts'
# EF_MIPS_ARCH values (flags & 0xf0000000) whose ELF32 files hold 64-bit instructions.
WIDE_ARCH = {0x20000000, 0x30000000, 0x40000000, 0x60000000, 0x80000000}
EF_MIPS_ABI2 = 0x20
SHF_EXECINSTR = 4
ET_REL = 1
FLAT_DEFAULT_LANGUAGE = 'MIPS:BE:64:default'
WIDE_WINDOW = 0xc000000000000000
PLAIN = re.compile(r'[A-Za-z0-9._-]+')


def die(message):
    sys.exit('ghidra-export: ' + message)


def read_header(path):
    with open(path, 'rb') as f:
        d = f.read(0x40)
    if d[:4] != b'\x7fELF':
        die('%s is not an ELF file; only ELF objects are handled here' % path)
    if d[5] != 2:
        die('%s is not big-endian' % path)
    etype, machine = struct.unpack('>HH', d[16:20])
    if machine != 8:
        die('%s is not MIPS' % path)
    klass = d[4]
    flags, = struct.unpack('>I', d[0x24:0x28] if klass == 1 else d[0x30:0x34])
    return klass, etype, flags


def plan_language(klass, flags):
    """(processor, compiler spec): None for both lets Ghidra's ELF loader choose."""
    if klass != 1 or (flags & 0xf0000000) not in WIDE_ARCH:
        return None, None
    # ELF32 gives the pointer width, not the instruction width: the 64-bit
    # instruction set with 32-bit pointers is a processor variant of its own.
    abi = flags & 0xf000
    spec = 'n32' if flags & EF_MIPS_ABI2 else {0: 'o32', 0x1000: 'o32', 0x2000: 'o64'}.get(abi)
    if spec is None:
        die('unsupported ELF32 MIPS ABI flags %#x' % flags)
    return 'MIPS:BE:64:64-32addr', spec


def mdebug_procs(elf, data):
    sec = elf.get_section_by_name('.mdebug')
    if sec is None:
        return []
    d = sec.data()
    if len(d) < 96:
        return []
    h = struct.unpack('>2H23I', d[:96])
    cbpd, cbsym, cbss, ifd, cbfd = h[8], h[10], h[16], h[19], h[20]
    out = []
    try:
        for i in range(ifd):
            o = cbfd + 72 * i
            fd = struct.unpack('>10I2H', data[o:o + 44])
            issbase, isymbase, ipdfirst, cpd = fd[2], fd[4], fd[10], fd[11]
            for p in range(ipdfirst, ipdfirst + cpd):
                po = cbpd + 52 * p
                _adr, isym = struct.unpack('>Ii', data[po:po + 8])
                so = cbsym + 12 * (isymbase + isym)
                iss, value = struct.unpack('>iI', data[so:so + 8])
                a = cbss + issbase + iss
                b = data.index(b'\0', a)
                name = data[a:b].decode('latin1')
                if name:
                    out.append((name, value))
    except (struct.error, ValueError):
        pass
    return out


def mdebug_seeds(path):
    """Static routine names from .mdebug that .symtab and .dynsym lack, in text."""
    from elftools.elf.elffile import ELFFile
    data = pathlib.Path(path).read_bytes()
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        covered = set()
        for name in ('.symtab', '.dynsym'):
            sec = elf.get_section_by_name(name)
            if sec is not None and hasattr(sec, 'iter_symbols'):
                covered.update(s['st_value'] for s in sec.iter_symbols())
        text = [(s['sh_addr'], s['sh_addr'] + s['sh_size']) for s in elf.iter_sections()
                if s['sh_flags'] & SHF_EXECINSTR and s['sh_addr']]
        seeds = {}
        for name, value in mdebug_procs(elf, data):
            if value not in covered and any(a <= value < b for a, b in text):
                seeds.setdefault(value, name)
    return sorted(seeds.items())


def pattern(text, relocatable):
    if text.startswith('@0x') and relocatable:
        die('%s names an address in a relocatable object; name the function' % text)
    return text


def types_spec(path, relocatable):
    spec_path = pathlib.Path(path).resolve()
    try:
        spec = json.loads(spec_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        die('cannot read types %s: %s' % (path, error))
    spec['headers'] = [str(spec_path.parent / h) for h in spec.get('headers', [])]
    for entry in spec.get('functions', []):
        pattern(entry['match'], relocatable)
    if relocatable and spec.get('globals'):
        die('a global address cannot be placed in a relocatable object')
    return spec


def parser():
    p = argparse.ArgumentParser(prog='tools/re-run --ghidra-export OBJECT')
    p.add_argument('--decompile-symbol', action='append', default=[], metavar='NAME')
    p.add_argument('--decompile-list', metavar='FILE')
    p.add_argument('--decompile-all', action='store_true')
    p.add_argument('--decompile-timeout', type=int, default=60)
    p.add_argument('--types', metavar='SPEC.json')
    p.add_argument('--mdebug', action='store_true')
    p.add_argument('--bsim-db', metavar='NAME')
    p.add_argument('--bsim-label', metavar='LABEL')
    p.add_argument('--bsim-dir', default='.cache/ghidra-bsim')
    p.add_argument('--bsim-min', type=float, default=0.7)
    p.add_argument('--flat', action='store_true')
    p.add_argument('--load', type=lambda v: int(v, 0), metavar='ADDR')
    p.add_argument('--header', type=int, default=0, metavar='N')
    p.add_argument('--processor', default=None)
    p.add_argument('--window', type=lambda v: int(v, 0), default=None, metavar='ADDR')
    p.add_argument('--timeout', type=int, default=3600)
    p.add_argument('--cpus', type=int, default=2)
    return p


def prepare(argv):
    ap = parser()
    ap.add_argument('--job', required=True)
    ap.add_argument('object')
    args = ap.parse_args(argv)
    obj = pathlib.Path(args.object).resolve()
    if not obj.is_file():
        die('no object %s' % args.object)
    job = pathlib.Path(args.job).resolve()
    exporting = bool(args.decompile_symbol or args.decompile_list or args.decompile_all)
    if not exporting and not args.bsim_db:
        die('name functions with --decompile-symbol, --decompile-list or --decompile-all, or give --bsim-db')
    if args.bsim_label and not args.bsim_db:
        die('--bsim-label needs --bsim-db')
    if args.types and not exporting:
        die('--types applies to an export')
    if args.mdebug and args.flat:
        die('--mdebug reads an ELF object')
    flat = None
    if args.flat:
        if args.load is None:
            die('--flat needs --load ADDR')
        if not 0 <= args.header < obj.stat().st_size:
            die('--header %d is outside the file' % args.header)
        args.processor = args.processor or FLAT_DEFAULT_LANGUAGE
        window = args.window
        if window is None:
            window = 0 if '64-32addr' in args.processor or ':32:' in args.processor else WIDE_WINDOW
        if window and ':64:' not in args.processor:
            die('--window needs a 64-bit language')
        if window and args.load & window:
            die('--load %#x overlaps the window %#x' % (args.load, window))
        flat = {'load': args.load, 'window': window, 'processor': args.processor}
        relocatable, language, spec = False, args.processor, None
    else:
        for opt in ('load', 'window'):
            if getattr(args, opt) is not None:
                die('--%s belongs to --flat' % opt)
        if args.header or args.processor:
            die('--header and --processor belong to --flat')
        klass, etype, flags = read_header(obj)
        relocatable = etype == ET_REL
        language, spec = plan_language(klass, flags)

    wanted = list(args.decompile_symbol)
    if args.decompile_list:
        try:
            lines = pathlib.Path(args.decompile_list).read_text().splitlines()
        except OSError as error:
            die('cannot read %s: %s' % (args.decompile_list, error.strerror))
        wanted += [l.strip() for l in lines if l.strip() and not l.startswith('#')]
    names, globs, addresses = [], [], []
    for item in wanted:
        item = pattern(item, relocatable)
        if item.startswith('@0x'):
            native = int(item[1:], 16) + (flat['window'] if flat else 0)
            addresses.append('0x%x' % native)
        elif '*' in item:
            globs.append(item)
        else:
            names.append(item)
    request = {'all': args.decompile_all, 'names': names, 'glob': globs,
               'addresses': addresses, 'timeout': args.decompile_timeout,
               'types': types_spec(args.types, relocatable) if args.types else None}
    (job / 'export.json').write_text(json.dumps(request, indent=1) + '\n')

    seeds = [] if relocatable or flat or args.mdebug else mdebug_seeds(obj)
    (job / 'seeds.tsv').write_text(''.join('0x%016x\t0\t%s\n' % (a, n) for a, n in seeds))

    sha = hashlib.sha256(obj.read_bytes()).hexdigest()
    image = obj
    if flat:
        stage = job / 'flat'
        stage.mkdir()
        image = stage / obj.name
        image.write_bytes(obj.read_bytes()[args.header:])
    lines = ['set -u', 'JOB=%s' % shlex.quote(str(job))]
    if args.bsim_db:
        for what, value in (('--bsim-db', args.bsim_db), ('--bsim-label', args.bsim_label or 'x')):
            if not PLAIN.fullmatch(value):
                die('%s is a plain name (letters, digits, . _ -)' % what)
        bsim = pathlib.Path(args.bsim_dir).resolve()
        bsim.mkdir(parents=True, exist_ok=True)
        if args.bsim_label:
            # BSim keys an executable by file name, and every libGLcore is called the same.
            stage = job / 'stage'
            stage.mkdir()
            labelled = stage / args.bsim_label
            labelled.write_bytes(image.read_bytes())
            image = labelled
        db = bsim / args.bsim_db
        lines.append('[ -f %s.mv.db ] || bsim createdatabase file:%s medium_nosize --name %s || exit 1'
                     % (shlex.quote(str(db)), shlex.quote(str(db)), args.bsim_db))
    argv = ['analyzeHeadless', '"$GP"', 'firmware', '-import', str(image)]
    if language:
        argv += ['-processor', language]
        if spec:
            argv += ['-cspec', spec]
    if flat:
        base = flat['load'] + flat['window']
        argv += ['-loader', 'BinaryLoader', '-loader-baseAddr', '0x%x' % base]
        # No header states the global pointer or the entry: recover gp from the
        # code, and start disassembly at the first byte.
        argv += ['-scriptPath', SCRIPTS, '-preScript', 'ReMipsGp.java', 'auto', '0x%x' % base]
    else:
        argv += ['-scriptPath', SCRIPTS, '-preScript', 'ReMipsGp.java', 'loader', '-']
    if seeds:
        argv += ['-preScript', 'ReObjectSymbols.java', str(job / 'seeds.tsv')]
    if args.mdebug:
        argv += ['-preScript', 'ReMdebugImport.java', 'names', str(image),
                 '-postScript', 'ReMdebugImport.java', 'types', str(image)]
    if exporting:
        argv += ['-postScript', 'ReDecompileExport.java', str(job)]
    if args.bsim_db:
        argv += ['-postScript', 'ReBSimAdd.java', '%s.mv.db' % db, '%s.matches.jsonl' % db,
                 str(args.bsim_min)]
    argv += ['-analysisTimeoutPerFile', str(args.timeout), '-max-cpu', str(args.cpus), '-deleteProject']
    # analyzeHeadless makes a project inside a directory, not the directory.
    lines.append('grep -h ^application.version= /opt/ghidra/Ghidra/application.properties > "$JOB/version"')
    lines.append('GP=$(mktemp -d /tmp/gp.XXXXXX)')
    lines.append(' '.join(a if a == '"$GP"' else shlex.quote(a) for a in argv)
                 + ' > "$JOB/headless.txt" 2>&1')
    lines.append('echo $? > "$JOB/rc"')
    (job / 'ghidra.sh').write_text('\n'.join(lines) + '\n')
    (job / 'plan.json').write_text(json.dumps({
        'object': str(obj), 'image_sha256': sha, 'language': language or 'default (from the ELF header)',
        'compiler_spec_requested': spec, 'relocatable': relocatable, 'exporting': exporting,
        'bsim': bool(args.bsim_db), 'mdebug_seeds': len(seeds), 'object_path': args.object,
        'flat': flat}, indent=1) + '\n')
    print('ghidra-export: %s (%s, %d .mdebug names seeded)'
          % (args.object, language or 'language from the ELF header', len(seeds)), file=sys.stderr)
    if flat:
        print('ghidra-export: flat image, %d header bytes skipped, loaded at %#x%s'
              % (args.header, flat['load'], ' under window %#x' % flat['window'] if flat['window'] else ''),
              file=sys.stderr)


MARKER = re.compile(r're-export-(begin|end) (0x[0-9a-f]+)')


def log_warnings(path):
    """Decompiler log lines, grouped by the function being exported when they appeared."""
    found, current = {}, None
    if not path.is_file():
        return found
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        m = MARKER.search(line)
        if m:
            current = m.group(2) if m.group(1) == 'begin' else None
        elif current is not None and line.startswith(('WARN ', 'ERROR ')):
            msg = re.sub(r'^(WARN|ERROR)\s+', '', line)
            msg = re.sub(r'\s*\(\w+\)\s*$', '', msg).strip()
            found.setdefault(current, [])
            if msg not in found[current]:
                found[current].append('log: ' + msg)
    return found


def finish(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--job', required=True)
    job = pathlib.Path(ap.parse_args(argv).job).resolve()
    plan = json.loads((job / 'plan.json').read_text())
    headless = job / 'headless.txt'
    text = headless.read_text(errors='replace') if headless.is_file() else ''
    rc = int((job / 'rc').read_text()) if (job / 'rc').is_file() else 1
    for line in text.splitlines():
        if 're-' in line and ('re-bsim:' in line or 're-decompile-export:' in line or 're-symbols:' in line or 're-gp:' in line):
            print(line.split('> ', 1)[-1], file=sys.stderr)
    if rc != 0:
        die('Ghidra exited %d; see %s' % (rc, headless))
    if plan['bsim'] and 're-bsim: ' not in text:
        errors = [l for l in text.splitlines() if 'ERROR' in l and 'DWARF' not in l]
        die('the BSim step failed and nothing was added to the database'
            + ''.join('\n  ' + l for l in errors[-5:]))
    status = 0
    if plan['exporting']:
        source = job / 'functions.jsonl'
        if not source.is_file():
            die('Ghidra wrote no function export; see %s' % headless)
        warnings = log_warnings(headless)
        functions = []
        for line in source.read_text(encoding='utf-8').splitlines():
            row = json.loads(line)
            row['warnings'] = row.get('warnings', []) + warnings.get(row['address'], [])
            row['ghidra_address'] = row['address']
            window = (plan.get('flat') or {}).get('window', 0)
            if window:
                for key in ('address', 'end'):
                    if row.get(key):
                        row[key] = hex(int(row[key], 16) - window)
            functions.append(row)
        types = json.loads((job / 'types.json').read_text(encoding='utf-8'))
        version = re.search(r'=(\S+)', (job / 'version').read_text()) if (job / 'version').is_file() else None
        document = {
            'image_sha256': plan['image_sha256'],
            'tool': 'ghidra ' + (version.group(1) if version else '(version not reported)'),
            'language': plan['language'], 'compiler_spec_requested': plan['compiler_spec_requested'],
            'object': plan['object_path'], 'evidence': EVIDENCE, 'types': types, 'functions': functions}
        out = job / 'decompile.json'
        out.write_text(json.dumps(document, indent=1) + '\n', encoding='utf-8')
        done = sum(1 for f in functions if f.get('complete'))
        shown = os.path.relpath(out)
        print('ghidra-export: exported %d/%d functions to %s' % (done, len(functions), shown), file=sys.stderr)
        for note in types.get('notes', []):
            print('ghidra-export: types: %s' % note, file=sys.stderr)
        for name in types.get('unmatched', []):
            print('ghidra-export: no function matches %s' % name, file=sys.stderr)
            status = 1
        print(shown)
    if plan['bsim']:
        print('ghidra-export: BSim matches appended to the .matches.jsonl beside the database; '
              'a similarity is a lead, not a finding', file=sys.stderr)
    print('ghidra-export: ' + EVIDENCE, file=sys.stderr)
    return status


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('prepare', 'finish'):
        die('usage: ghidra-export.py prepare|finish ... (run it through tools/re-run --ghidra-export)')
    return {'prepare': prepare, 'finish': finish}[sys.argv[1]](sys.argv[2:]) or 0


if __name__ == '__main__':
    sys.exit(main())
