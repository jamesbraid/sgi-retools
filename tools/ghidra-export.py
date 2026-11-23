#!/usr/bin/env python3
"""Plan and finish a Ghidra decompile export or BSim load of one ELF object.

Not run directly: `retools/tools/re-run --ghidra-export OBJECT [OPTIONS]` runs `prepare`,
then Ghidra in its own image, then `finish`, and prints where the JSON landed.
`prepare` and `finish` run in the toolchain image (they need pyelftools).

Options (after OBJECT, a path inside the workspace):
  --decompile-symbol NAME|GLOB|@0xADDR   a function by name, a glob with *, or an
                                          address (not for a relocatable object);
                                          repeatable
                                          @0xLO-0xHI is every function entered in that range
  --decompile-component GLOB              every function in the program-tree fragment named
                                          GLOB (repeatable). The SN2 import makes one per FIT
                                          component: PAL_A_generic_7_31, PAL_A_7_31, PAL_B_7_79,
                                          SAL_A_5_04, SAL_B_5_04; read one image's names from
                                          the import log or its FIT labels
  --decompile-list FILE                   one name, glob, @address or @range per line
  --decompile-all                         every function Ghidra found
  --decompile-timeout SECONDS             per function (default 60); a ceiling against a hung decompiler,
                                          not a limit on normal work. A function that times out is tried
                                          once more with four times as long
  --decompile-max-instructions N          the decompiler's work limits, which count work and not time, so
  --decompile-max-payload MB              what decompiles does not depend on host load (defaults: Ghidra's
  --decompile-max-jumptable N             suggested 100000, 50 and 1024). Each function's row says whether it
                                          is complete, partial or failed (budget, ceiling or error)
  --types SPEC.json                       structure types to apply first (see
                                          ghidra/README.md)
  --mdebug                                import the object's .mdebug symbol table
                                          (names, line numbers, types, procedure
                                          signatures); a 32-bit MIPSpro object only
  --dbg FILE.dbg                          apply the COFF symbols, or the CodeView NB09 publics, of a
                                          Windows NT separate debug file to an x86 PE image
                                          (ghidra/scripts/ReDbgImport.java states the counting rule)
  --pdb FILE.pdb                          apply a .pdb (PDB 2.0 or 7.0) to an x86 PE image: its
                                          types, function names and parameters
  --returning NAME[,NAME]                 after analysis, clear the no-return flag on these functions
                                          (a name or @0xADDR; repeatable), re-disassemble each call
                                          to them so the code after it is reached, and rebuild the
                                          callers, for a routine analysis
                                          wrongly marked non-returning ("Subroutine does not return"
                                          in every caller)
  --callconv CONV:GLOB[,GLOB]             after analysis, give every function named GLOB (a name with
                                          * wildcards, or @0xADDR) the calling convention CONV, one
                                          of the compiler spec's (fastcall, stdcall, thiscall, cdecl,
                                          with or without leading underscores); repeatable
  --callconv-file FILE                    the same, one CONV:GLOB[,GLOB] per line (# starts a comment)
  --param-type GLOB:INDEX:TYPE            set the type of parameter INDEX (from 0) of the functions
                                          named GLOB, TYPE a type already in the program such as
                                          "__GLCOcontextRec *"; repeatable. Rules apply in the order
                                          given, calling conventions first
  --pre-script FILE  --post-script FILE   run an extra Ghidra script (repeatable, in order): pre-scripts
                                          after the importers of --dbg, --pdb and --mdebug and before
                                          analysis, post-scripts after analysis and the options above
                                          (--returning included) and before the decompile export, so what
                                          they change is exported. FILE is in the workspace
  --bsim-db NAME --bsim-label LABEL       match the object against BSim database
                                          NAME, then add it under LABEL
  --bsim-dir DIR  --bsim-min SIMILARITY   database directory (default
                                          .cache/ghidra-bsim), lowest similarity
                                          written (default 0.7)
  --timeout SECONDS  --cpus N             Ghidra analysis limits (3600, 2)
  --heap SIZE                             the Java heap of Ghidra, such as 14G. Default: 2G for an
                                          ELF object; for a flat image 2G plus 1G for each MiB of
                                          it, at most 14G (a 12 MiB SHub 2 PROM completed at 2G).
                                          The container's memory cap is RE_GHIDRA_MEMORY (16g);
                                          raise it for a larger heap
  --no-analysis                           skip Ghidra's automatic analysis. Only what the import
                                          lays out (an SN2 PROM's entries, an ELF's symbols) and the
                                          functions asked for as @0xADDR are functions; use it to
                                          read known addresses quickly

Output goes under .cache/ghidra-export/ (ignored by git): decompile.json holds one
entry per function with the decompiler's C, warnings and signature. Decompiler
output and BSim similarity are navigation, not evidence: a committed claim still
rests on the disassembly.

A 32-bit x86 PE image (a Windows NT driver or DLL) is read with the PE loader; --dbg names its
separate .dbg file.

An IA-64 PE32+ image (an EFI driver or application, machine 0x200) is read with the PE loader and
IA64Pe.java; its entry point and exports are function descriptors, resolved to functions named `entry`
and the export's name.

An ELF object (a linked library, a kernel or a relocatable driver object, or a gzip-compressed
kernel such as vmlinuz, which is inflated first) takes its
language and calling convention from its header; big-endian MIPS, little-endian
ARM (read as ARM:LE:32:v4) and IA-64 ELF files are accepted. Names the loader ignores
(.mdebug) are seeded before analysis.

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
An SGI SN2 (Altix, Prism) flash PROM is a flat image with its own layout:
  --sn2-prom             read OBJECT as an SN2 PROM: the IA-64 language, loaded
                         to end at 4 GiB, laid out by SN2PromImport.java (FIT
                         components, PAL and SAL entries, the SAL dispatch table
                         as sal_<id> functions, SAL_B's gp), then analysed
  --sal-runtime          with --sn2-prom, also inflate the gzip SAL runtime component
                         (FIT type 0x12), map its IA-64 ELF at 0x100000000 (its link
                         address 0) and make its dynamic symbols functions, named as in
                         the ELF. Reach them by name or in the SAL_runtime_* component.
                         The address SAL really inflates it to is chosen at run time.
  --gzip-elfs            with --sn2-prom, the same for the other gzip ELF components (FIT
                         types 0x13 and 0x1f): link address 0 at 0x200000000 and 0x300000000
Ask for its routines by address (@0xffc4e970) or by those names (SALE_ENTRY,
sal_02000002).
A flat image has no names: functions are `FUN_` placeholders, found by Ghidra's
analysis, so ask for them by `@0xADDR` or with --decompile-all. `address` in the
JSON is the machine address (--load), `ghidra_address` is where Ghidra holds it, and
the C text uses Ghidra's addresses.
"""
import argparse
import gzip
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
EM_MIPS, EM_ARM, EM_IA_64 = 8, 40, 50
PE_MACHINE_IA64 = 0x200
PE_MACHINE_I386 = 0x14c
ARM_LANGUAGE = 'ARM:LE:32:v4'
SHF_EXECINSTR = 4
ET_REL = 1
FLAT_DEFAULT_LANGUAGE = 'MIPS:BE:64:default'
IA64_LANGUAGE = 'IA64:LE:64:default'
WIDE_WINDOW = 0xc000000000000000
PLAIN = re.compile(r'[A-Za-z0-9._-]+')
# Ghidra 12.1.3's DecompileOptions.SUGGESTED_* limits; ghidra/scripts/ReDecompBudget.java reads the same.
BUDGET_DEFAULTS = {'max_instructions': 100000, 'max_payload_mb': 50, 'max_jumptable_entries': 1024}
RANGE = re.compile(r'@0x[0-9a-fA-F]+-0x[0-9a-fA-F]+')


def die(message):
    sys.exit('ghidra-export: ' + message)


def read_header(path):
    with open(path, 'rb') as f:
        d = f.read(0x40)
        if d[:2] == b'MZ':
            f.seek(struct.unpack('<I', d[0x3c:0x40])[0])
            pe = f.read(6)
            machine = struct.unpack('<H', pe[4:6])[0] if pe[:4] == b'PE\0\0' else 0
            if machine not in (PE_MACHINE_IA64, PE_MACHINE_I386):
                die('%s is a PE image, but not for IA-64 (machine 0x200) or x86 (0x14c)' % path)
            return machine, 2, 0, 0
    if d[:4] != b'\x7fELF':
        die('%s is neither an ELF file nor an IA-64 PE image' % path)
    order = {1: '<', 2: '>'}.get(d[5])
    if order is None:
        die('%s has no byte order in its ELF header' % path)
    etype, machine = struct.unpack(order + 'HH', d[16:20])
    if (machine, d[5]) not in ((EM_MIPS, 2), (EM_ARM, 1), (EM_IA_64, 1)):
        die('%s is not big-endian MIPS, little-endian ARM or IA-64' % path)
    klass = d[4]
    flags, = struct.unpack(order + 'I', d[0x24:0x28] if klass == 1 else d[0x30:0x34])
    return machine, klass, etype, flags


def plan_language(machine, klass, flags):
    """(processor, compiler spec): None for both lets Ghidra's ELF loader choose."""
    if machine == EM_ARM:
        return ARM_LANGUAGE, None
    if machine in (EM_IA_64, PE_MACHINE_IA64):
        return IA64_LANGUAGE, None
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
    p = argparse.ArgumentParser(prog='retools/tools/re-run --ghidra-export OBJECT')
    p.add_argument('--decompile-symbol', action='append', default=[], metavar='NAME')
    p.add_argument('--decompile-component', action='append', default=[], metavar='GLOB')
    p.add_argument('--decompile-list', metavar='FILE')
    p.add_argument('--decompile-all', action='store_true')
    p.add_argument('--decompile-timeout', type=int, default=60)
    p.add_argument('--decompile-max-instructions', type=int, default=BUDGET_DEFAULTS['max_instructions'], metavar='N')
    p.add_argument('--decompile-max-payload', type=int, default=BUDGET_DEFAULTS['max_payload_mb'], metavar='MB')
    p.add_argument('--decompile-max-jumptable', type=int, default=BUDGET_DEFAULTS['max_jumptable_entries'], metavar='N')
    p.add_argument('--types', metavar='SPEC.json')
    p.add_argument('--mdebug', action='store_true')
    p.add_argument('--dbg', metavar='FILE.dbg')
    p.add_argument('--pdb', metavar='FILE.pdb')
    p.add_argument('--returning', action='append', default=[], metavar='NAME[,NAME]')
    p.add_argument('--callconv', action='append', default=[], metavar='CONV:GLOB[,GLOB]')
    p.add_argument('--callconv-file', metavar='FILE')
    p.add_argument('--param-type', action='append', default=[], metavar='GLOB:INDEX:TYPE')
    p.add_argument('--pre-script', action='append', default=[], metavar='FILE')
    p.add_argument('--post-script', action='append', default=[], metavar='FILE')
    p.add_argument('--bsim-db', metavar='NAME')
    p.add_argument('--bsim-label', metavar='LABEL')
    p.add_argument('--bsim-dir', default='.cache/ghidra-bsim')
    p.add_argument('--bsim-min', type=float, default=0.7)
    p.add_argument('--flat', action='store_true')
    p.add_argument('--load', type=lambda v: int(v, 0), metavar='ADDR')
    p.add_argument('--header', type=int, default=0, metavar='N')
    p.add_argument('--processor', default=None)
    p.add_argument('--window', type=lambda v: int(v, 0), default=None, metavar='ADDR')
    p.add_argument('--sn2-prom', action='store_true')
    p.add_argument('--sal-runtime', action='store_true')
    p.add_argument('--gzip-elfs', action='store_true')
    p.add_argument('--timeout', type=int, default=3600)
    p.add_argument('--heap', metavar='SIZE')
    p.add_argument('--no-analysis', action='store_true')
    p.add_argument('--cpus', type=int, default=2)
    return p


CALLCONV = re.compile(r'([A-Za-z_][A-Za-z0-9_]*):([^\s:][^\t\r\n]*)')
PARAM_TYPE = re.compile(r'(\S+?):([0-9]+):([^\t\r\n]+)')


def retype_rules(args):
    """The ReFunctionTypes rule lines for --callconv, --callconv-file and --param-type, in order."""
    items = list(args.callconv)
    if args.callconv_file:
        try:
            lines = pathlib.Path(args.callconv_file).read_text().splitlines()
        except OSError as error:
            die('cannot read %s: %s' % (args.callconv_file, error.strerror))
        items += [l.strip() for l in lines if l.strip() and not l.lstrip().startswith('#')]
    rules = []
    for item in items:
        m = CALLCONV.fullmatch(item)
        if not m:
            die('--callconv wants CONV:GLOB[,GLOB], got %r' % item)
        rules += ['callconv\t%s\t%s' % (m.group(1), g) for g in m.group(2).split(',') if g]
    for item in args.param_type:
        m = PARAM_TYPE.fullmatch(item)
        if not m:
            die('--param-type wants GLOB:INDEX:TYPE, got %r' % item)
        rules.append('param\t%s\t%s\t%s' % m.groups())
    return rules


def extra_scripts(files, option):
    """Absolute paths of --pre-script or --post-script files; Ghidra finds one by its name in a script path."""
    paths = []
    for name in files:
        path = pathlib.Path(name).resolve()
        if not path.is_file():
            die('no script %s for %s' % (name, option))
        if ';' in str(path.parent):
            die('%s: a script directory with a semicolon cannot go in the script path' % name)
        paths.append(path)
    return paths


def heap_for(size):
    """The headless heap for a flat image: 2G plus 1G per MiB, from 2G to 14G."""
    return '%dG' % min(14, max(2, 2 + -(-size // (1 << 20))))


def prepare(argv):
    ap = parser()
    ap.add_argument('--job', required=True)
    ap.add_argument('object')
    args = ap.parse_args(argv)
    obj = pathlib.Path(args.object).resolve()
    if not obj.is_file():
        die('no object %s' % args.object)
    job = pathlib.Path(args.job).resolve()
    original = obj
    if not (args.flat or args.sn2_prom) and original.open('rb').read(2) == b'\x1f\x8b':
        # A compressed kernel (vmlinuz) is a gzip stream holding the ELF file.
        stage = job / 'inflated'
        stage.mkdir()
        obj = stage / re.sub(r'\.gz$', '', obj.name)
        try:
            with gzip.open(original) as src, open(obj, 'wb') as out:
                out.write(src.read(1 << 30))
        except (OSError, EOFError) as error:
            die('cannot inflate %s: %s' % (args.object, error))
    exporting = bool(args.decompile_symbol or args.decompile_list or args.decompile_all or args.decompile_component)
    if not exporting and not args.bsim_db:
        die('name functions with --decompile-symbol, --decompile-component, --decompile-list or --decompile-all, or give --bsim-db')
    if args.bsim_label and not args.bsim_db:
        die('--bsim-label needs --bsim-db')
    if args.types and not exporting:
        die('--types applies to an export')
    if args.mdebug and args.flat:
        die('--mdebug reads an ELF object')
    if (args.dbg or args.pdb) and args.flat:
        die('--dbg and --pdb read a PE image')
    returning = [n for item in args.returning for n in item.split(',') if n]
    if args.returning and not returning:
        die('--returning names functions: NAME[,NAME]')
    if args.heap and not re.fullmatch(r'[1-9][0-9]*[MG]', args.heap):
        die('--heap is a size such as 14G or 4096M')
    rules = retype_rules(args)
    pre_scripts = extra_scripts(args.pre_script, '--pre-script')
    post_scripts = extra_scripts(args.post_script, '--post-script')
    names = [s.name for s in pre_scripts + post_scripts]
    if len(set(names)) != len(names):
        die('two --pre-script or --post-script files have the same name; Ghidra finds a script by name')
    flat, mips, pe, header_kind = None, True, False, 'ELF'
    if args.sal_runtime and not args.sn2_prom:
        die('--sal-runtime reads the SAL runtime of an SN2 PROM: add --sn2-prom')
    if args.gzip_elfs and not args.sn2_prom:
        die('--gzip-elfs reads components of an SN2 PROM: add --sn2-prom')
    if args.sn2_prom:
        if args.flat or args.load is not None or args.processor or args.header:
            die('--sn2-prom sets the layout itself; drop --flat, --load, --processor and --header')
        args.flat, args.processor, args.window = True, IA64_LANGUAGE, 0
        args.load = (1 << 32) - obj.stat().st_size
    if args.flat:
        if args.load is None:
            die('--flat needs --load ADDR')
        if not 0 <= args.header < obj.stat().st_size:
            die('--header %d is outside the file' % args.header)
        args.processor = args.processor or FLAT_DEFAULT_LANGUAGE
        window = args.window
        if window is None:
            mips64 = args.processor.startswith('MIPS') and ':64:' in args.processor
            window = WIDE_WINDOW if mips64 and '64-32addr' not in args.processor else 0
        if window and not args.processor.startswith('MIPS'):
            die('--window applies to a MIPS language')
        if window and ':64:' not in args.processor:
            die('--window needs a 64-bit language')
        if window and args.load & window:
            die('--load %#x overlaps the window %#x' % (args.load, window))
        flat = {'load': args.load, 'window': window, 'processor': args.processor, 'sn2': args.sn2_prom}
        relocatable, language, spec = False, args.processor, None
    else:
        for opt in ('load', 'window'):
            if getattr(args, opt) is not None:
                die('--%s belongs to --flat' % opt)
        if args.header or args.processor:
            die('--header and --processor belong to --flat')
        machine, klass, etype, flags = read_header(obj)
        header_kind = 'PE' if machine in (PE_MACHINE_IA64, PE_MACHINE_I386) else 'ELF'
        mips = machine == EM_MIPS
        if args.mdebug and not mips:
            die('--mdebug reads a MIPS object')
        relocatable = etype == ET_REL
        pe = machine == PE_MACHINE_IA64
        if (args.dbg or args.pdb) and machine != PE_MACHINE_I386:
            die('--dbg and --pdb read an x86 PE image')
        language, spec = plan_language(machine, klass, flags)

    wanted = list(args.decompile_symbol)
    if args.decompile_list:
        try:
            lines = pathlib.Path(args.decompile_list).read_text().splitlines()
        except OSError as error:
            die('cannot read %s: %s' % (args.decompile_list, error.strerror))
        wanted += [l.strip() for l in lines if l.strip() and not l.startswith('#')]
    names, globs, addresses, ranges = [], [], [], []
    for item in wanted:
        item = pattern(item, relocatable)
        if RANGE.fullmatch(item):
            lo, hi = (int(x, 16) + (flat['window'] if flat else 0) for x in item[1:].split('-'))
            ranges.append('0x%x-0x%x' % (lo, hi))
        elif item.startswith('@0x'):
            native = int(item[1:], 16) + (flat['window'] if flat else 0)
            addresses.append('0x%x' % native)
        elif '*' in item:
            globs.append(item)
        else:
            names.append(item)
    budget = {'max_instructions': args.decompile_max_instructions, 'max_payload_mb': args.decompile_max_payload,
              'max_jumptable_entries': args.decompile_max_jumptable}
    if min(budget.values()) < 1:
        die('the decompile limits are positive')
    # A non-default limit makes the decompiler take its other options from a fresh options object, which can
    # change its output beyond the limits; a reader of decompile.json can see which kind of run it was.
    budget['other_options_reset'] = any(budget[k] != v for k, v in BUDGET_DEFAULTS.items())
    request = {'all': args.decompile_all, 'budget': budget, 'names': names, 'glob': globs,
               'addresses': addresses, 'ranges': ranges, 'components': args.decompile_component,
               'timeout': args.decompile_timeout,
               'types': types_spec(args.types, relocatable) if args.types else None}
    (job / 'export.json').write_text(json.dumps(request, indent=1) + '\n')

    seeds = [] if relocatable or flat or args.mdebug or not mips else mdebug_seeds(obj)
    (job / 'seeds.tsv').write_text(''.join('0x%016x\t0\t%s\n' % (a, n) for a, n in seeds))

    sha = hashlib.sha256(original.read_bytes()).hexdigest()
    image = obj
    if flat:
        stage = job / 'flat'
        stage.mkdir()
        image = stage / obj.name
        image.write_bytes(obj.read_bytes()[args.header:])
    lines = ['set -u', 'JOB=%s' % shlex.quote(str(job)),
             # The scripts that decompile before the export (IA64Signatures) read the same limits.
             'export RE_DECOMPILE_BUDGET=%d,%d,%d' % (budget['max_instructions'], budget['max_payload_mb'],
                                                       budget['max_jumptable_entries'])]
    heap = args.heap or (heap_for(obj.stat().st_size) if flat else None)
    if heap:
        lines.append('export GHIDRA_HEADLESS_MAXMEM=%s' % heap)
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
    if args.no_analysis:
        argv.append('-noanalysis')
    if language:
        argv += ['-processor', language]
        if spec:
            argv += ['-cspec', spec]
    if flat:
        base = flat['load'] + flat['window']
        argv += ['-loader', 'BinaryLoader', '-loader-baseAddr', '0x%x' % base, '-scriptPath', SCRIPTS]
        if flat['sn2']:
            argv += ['-preScript', 'SN2PromImport.java'] + (['sal-runtime'] if args.sal_runtime else []) \
                + (['gzip-elfs'] if args.gzip_elfs else [])
        elif flat['processor'].startswith('MIPS'):
            # No header states the global pointer or the entry: recover gp from
            # the code, and start disassembly at the first byte.
            argv += ['-preScript', 'ReMipsGp.java', 'auto', '0x%x' % base]
    else:
        argv += ['-scriptPath', SCRIPTS]
        if mips:
            argv += ['-preScript', 'ReMipsGp.java', 'loader', '-']
        elif pe:
            argv += ['-loader', 'PeLoader', '-preScript', 'IA64Pe.java']
        elif machine == PE_MACHINE_I386:
            argv += ['-loader', 'PeLoader']
        elif language == IA64_LANGUAGE:
            argv += ['-preScript', 'IA64Elf.java']
    if seeds:
        argv += ['-preScript', 'ReObjectSymbols.java', str(job / 'seeds.tsv')]
    if args.mdebug:
        argv += ['-preScript', 'ReMdebugImport.java', 'names', str(image),
                 '-postScript', 'ReMdebugImport.java', 'types', str(image)]
    for flag, script in ((args.dbg, 'ReDbgImport.java'), (args.pdb, 'RePdbImport.java')):
        if flag:
            path = pathlib.Path(flag).resolve()
            if not path.is_file():
                die('no debug file %s' % flag)
            argv += ['-preScript', script, str(path)]
    for script in pre_scripts:
        argv += ['-preScript', script.name]
    if rules:
        (job / 'retype.tsv').write_text('\n'.join(rules) + '\n')
        argv += ['-postScript', 'ReFunctionTypes.java', str(job / 'retype.tsv')]
    if returning:
        argv += ['-postScript', 'ReReturning.java', ','.join(returning)]
    if language == IA64_LANGUAGE:
        # Callee signatures first, so call sites pass exactly the callee's arguments.
        whole = args.decompile_all or globs or ranges or args.decompile_component
        roots = [] if whole else names + addresses
        argv += ['-postScript', 'IA64Signatures.java'] + roots
    for script in post_scripts:
        argv += ['-postScript', script.name]
    if exporting:
        argv += ['-postScript', 'ReDecompileExport.java', str(job)]
    if args.bsim_db:
        argv += ['-postScript', 'ReBSimAdd.java', '%s.mv.db' % db, '%s.matches.jsonl' % db,
                 str(args.bsim_min)]
    if pre_scripts or post_scripts:
        # Each script is found by name in the script path, so add the directories it sits in.
        where = argv.index('-scriptPath')
        dirs = [argv[where + 1]] + sorted({str(s.parent) for s in pre_scripts + post_scripts})
        argv[where + 1] = ';'.join(dirs)
    argv += ['-analysisTimeoutPerFile', str(args.timeout), '-max-cpu', str(args.cpus), '-deleteProject']
    # analyzeHeadless makes a project inside a directory, not the directory.
    lines.append('grep -h ^application.version= /opt/ghidra/Ghidra/application.properties > "$JOB/version"')
    lines.append('GP=$(mktemp -d /tmp/gp.XXXXXX)')
    lines.append(' '.join(a if a == '"$GP"' else shlex.quote(a) for a in argv)
                 + ' > "$JOB/headless.txt" 2>&1')
    lines.append('echo $? > "$JOB/rc"')
    (job / 'ghidra.sh').write_text('\n'.join(lines) + '\n')
    (job / 'plan.json').write_text(json.dumps({
        'object': str(original), 'image_sha256': sha, 'language': language or 'default (from the %s header)' % header_kind,
        'compiler_spec_requested': spec, 'relocatable': relocatable, 'exporting': exporting,
        'bsim': bool(args.bsim_db), 'mdebug_seeds': len(seeds), 'object_path': args.object,
        'flat': flat, 'dbg': args.dbg, 'pdb': args.pdb, 'returning': returning, 'retype_rules': rules,
        'pre_scripts': [str(s) for s in pre_scripts], 'post_scripts': [str(s) for s in post_scripts]}, indent=1) + '\n')
    print('ghidra-export: %s (%s, %d .mdebug names seeded)'
          % (args.object, language or 'language from the %s header' % header_kind, len(seeds)),
          file=sys.stderr)
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
    # What the option scripts print, and what the user's own scripts print.
    reported = ['ReDbgImport.java> ', 'RePdbImport.java> ', 'ReReturning.java> ', 'ReFunctionTypes.java> ']
    reported += ['%s> ' % pathlib.Path(s).name for s in plan.get('pre_scripts', []) + plan.get('post_scripts', [])]
    for line in text.splitlines():
        if 're-' in line and ('re-bsim:' in line or 're-decompile-export:' in line or 're-symbols:' in line or 're-gp:' in line):
            print(line.split('> ', 1)[-1], file=sys.stderr)
        elif any(m in line for m in reported):
            print('ghidra-export: ' + line.split('> ', 1)[-1], file=sys.stderr)
    if rc != 0:
        die('Ghidra exited %d; see %s' % (rc, headless))
    if plan['bsim'] and 're-bsim: ' not in text:
        errors = [l for l in text.splitlines() if 'ERROR' in l and 'DWARF' not in l]
        die('the BSim step failed and nothing was added to the database'
            + ''.join('\n  ' + l for l in errors[-5:]))
    status = 0
    for line in text.splitlines():
        if 'ReFunctionTypes.java> ReFunctionTypes: FAILED' in line:
            status = 1
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
            'budget': json.loads((job / 'export.json').read_text())['budget'],
            'language': plan['language'], 'compiler_spec_requested': plan['compiler_spec_requested'],
            'object': plan['object_path'], 'evidence': EVIDENCE, 'types': types, 'functions': functions}
        out = job / 'decompile.json'
        out.write_text(json.dumps(document, indent=1) + '\n', encoding='utf-8')
        done = sum(1 for f in functions if f.get('complete'))
        ceiling = sum(1 for f in functions if (f.get('failure') or {}).get('reason') == 'ceiling')
        if ceiling:
            print('ghidra-export: %d functions hit the decompile time ceiling; whether they decompile depends on '
                  'host load (raise --decompile-timeout)' % ceiling, file=sys.stderr)
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
        die('usage: ghidra-export.py prepare|finish ... (run it through retools/tools/re-run --ghidra-export)')
    return {'prepare': prepare, 'finish': finish}[sys.argv[1]](sys.argv[2:]) or 0


if __name__ == '__main__':
    sys.exit(main())
