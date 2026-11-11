#!/usr/bin/env python3
"""Publish-safety and consistency check for decode headers (config-driven).

Usage:
    retools/tools/defs/check-publish-safe.py --config defs.toml [--header H ...]
                                             [--rust] [--verbose]

Exit status 0 means clean, 1 means at least one failure (each offending line is
printed), 2 means a usage or setup problem (a header or a prose document is
missing, the config is bad).

Three checks per header, all configured from defs.toml (see README.md):

1. Publish-safety. The headers go into public projects, so they must carry no
   vendor source path, no routine or symbol name, no raw address or binary
   offset, and no vendor-internal identifier. Opcodes and bit ranges are
   wire-format facts and are allowed. The built-in rules are generic; a repo
   adds its own under [[banned.extra]].
2. Internal consistency. Every FIELD line is well formed and no two fields of
   one word overlap. Every ENUM value fits its field. Each TESTVEC line is
   decoded with the header's own field ranges and must come out as stated. The
   SHIFT/MASK macros agree with their FIELD line. REG offsets do not overlap and
   appear only in REG lines.
3. Cross-check against prose. [[claims]] bind a regular expression over a prose
   document to header facts (field ranges, register offsets, enum values,
   macros). A passage that no longer matches also fails, so drift in either
   direction is caught.

Line grammar (inside C comments) and the full config are in README.md.

A repo with checks that do not fit the declarative claims names a `plugin`
Python file. The plugin may define check_header(ctx, hdr), check_group(ctx,
group, hdrs) and check_final(ctx); see README.md.

Needs only the Python 3.11 standard library.
"""
import argparse
import fnmatch
import glob
import importlib.util
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defs_common import ConfigError, GRADES, Report, load_config, read_file  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# 1. Publish-safety rules: (label, regex). Each match on a line is a failure.
# The 'header file name other than ours' rule is built per repo.
# ---------------------------------------------------------------------------
HEADER_NAME_LABEL = 'header file name other than ours'
DEFAULT_BANNED = [
    ('vendor source path', r'\b(?:stand|irix|builds|refs|root)/[\w./+-]+'),
    ('vendor install path', r'\busr/(?:cpu|gfx|lib|diags)\b'),
    ('source/object file name', r'\b[\w-]+\.(?:c|s|so|a|o)\b(?![\w-])'),
    ('mixed-case call', r'\b[a-z]+[A-Z]\w*\('),
    ('vendor release cite', r'\b6\.5\.\d+m?\b'),
    ('SGI build or board token', r'\bIP\d{2}[A-Z0-9]*\b'),
    ('RE tool name', r'\bDWARF\b|\bGhidra\b|\bm2c\b|\bspimdisasm\b'),
    ('N32 or kernel virtual address', r'\b0x0d[0-9a-f]{6}\b|\b0x1fc[0-9a-f]+\b|\b0xbfc[0-9a-f]+\b|\b0xa8[0-9a-f]{6}\b|\b0x9[0-9a-f]{7}\b'),
    ('N32 code address without the leading zero', r'\b0x0?d[89a][0-9a-f]{5}\b'),
    ('binary offset', r'\+0x[0-9a-fA-F]+|\bat 0x[0-9a-fA-F]{4,}|\boffset 0x[0-9a-fA-F]{3,}|\bboard \+'),
    ('record or context offset', r'\b(?:context|record|object|mirror|shadow)\s+\+\s*\d+'),
    ('source line cite', r'\bsource line\b|\blines? \d{3,}'),
]
# Rules an allow-list name may exempt (see [allowlists]).
NAME_RULES = {'vendor source path', 'source/object file name', HEADER_NAME_LABEL}

# Legacy form: FIELD: WORD.name hi:lo grade (32-bit words, explicit macro pairs).
FIELD_RE = re.compile(r'/\*\s*FIELD:\s*(\w+)\.(\w+)\s+(\d+):(\d+)\s+(\w+)\s*\*/')
TV_RE = re.compile(r'TESTVEC:\s*(0x[0-9a-fA-F]+)\s+as\s+(\w+)\s*=>\s*(.+?)\s*$')
DEF_RE = re.compile(r'^#define\s+(\w+)\s+\(?\s*(0x[0-9a-fA-F]+|\d+)[uU]?[lL]{0,2}\s*\)?')
SHL_RE = re.compile(r'^#define\s+(\w+)\s+\(\s*1u?\s*<<\s*(\d+)\s*\)')

# Regs form.
REG_RE = re.compile(
    r'^\s*/\*\s*REG:\s*([A-Z]+)\.([a-z]\w*)\s+(0x[0-9a-f]{1,4})\s+(rw|r|w)(\d+)'
    r'(?:\s+count=(\d+))?(?:\s+space=(\w+))?\s+reset=(unknown|0x[0-9a-f]+|\d+)\s+(\w+)\s*\*/\s*$')
WORD_RE = re.compile(r'/\*\s*WORD:\s*([A-Z][A-Z_0-9]*)\s+(32|64)\s*\*/')
FIELD3_RE = re.compile(r'/\*\s*FIELD:\s*([A-Z]+)\.([a-z]\w*)\.([a-z]\w*)\s+(\d+):(\d+)\s+(\w+)\s*\*/')
FIELD2_RE = re.compile(r'/\*\s*FIELD:\s*([A-Z_0-9]+)\.([a-z]\w*)\s+(\d+):(\d+)\s+(\w+)\s*\*/')
ENUM_RE = re.compile(r'/\*\s*ENUM:\s*([\w.]+)\s+(0x[0-9a-f]+|\d+)\s+(\w+)\s+(\w+)\s*\*/')
TV2_RE = re.compile(r'\b(TESTVEC|EXAMPLE \(unverified\)):\s*(0x[0-9a-fA-F]+)\s+as\s+([\w.]+)\s*=>\s*(.+?)\s*$')
HEXLIT_RE = re.compile(r'\b0x[0-9a-fA-F]+')
DEC_BIG_RE = re.compile(r'(?<![\w.])\d{7,}(?![\w.])')


def is_mask(v):
    """True for a contiguous run of one bits starting at bit 0."""
    return v > 0 and (v & (v + 1)) == 0


class Ctx:
    """What the checks and plugins see."""

    def __init__(self, cfg, root, rep, verbose=False):
        self.cfg = cfg
        self.root = root
        self.rep = rep
        self.verbose = verbose
        self.hdrs = {}            # file path as configured -> Hdr
        self.allregs = {}         # every REG of every block header
        self.lib = sys.modules[__name__]
        chk = cfg.get('checks', {})
        self.address_bits = chk.get('address_bits', 14)
        self.max_reg_addr = (1 << self.address_bits) - 1
        self.max_reg_offset = chk.get('max_reg_offset', 0xffff)

    def read(self, path):
        return read_file(self.root, path)

    def read_doc(self, path):
        """Read a prose document; a missing one is a setup problem (exit 2)."""
        try:
            return self.read(path)
        except OSError as e:
            print('error: cannot read %s: %s' % (path, e), file=sys.stderr)
            sys.exit(2)


class Hdr:
    def __init__(self, cfg, text, selected):
        self.cfg = cfg
        self.file = cfg['file']
        self.name = os.path.basename(self.file)
        self.group = cfg.get('group', self.name)
        self.form = cfg.get('form', 'regs')
        self.block = cfg.get('block')
        self.prefix = cfg.get('prefix') or self.block or ''
        self.text = text
        self.selected = selected
        self.regs, self.fields, self.defs, self.enums = {}, {}, {}, {}
        self.vecs = []            # regs form: (kind, value, target, vals, line); legacy: dict
        self.addr_fields = []
        self.widths = {}          # field key -> bit width of its word


# ---------------------------------------------------------------------------
# Publish-safety
# ---------------------------------------------------------------------------
def load_allow(ctx, key):
    """Entries of an allow-list file: NAME<TAB>REASON, '#' comments."""
    path = ctx.cfg.get('allowlists', {}).get(key)
    if not path:
        return set()
    names = set()
    for line in ctx.read_doc(path).splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        names.add(line.split('\t', 1)[0].strip())
    return names


def banned_rules(ctx):
    cfg = ctx.cfg
    b = cfg.get('banned', {})
    skip = set(b.get('skip', []))
    own = [os.path.basename(h['file']) for h in cfg['headers']] + list(b.get('allow_includes', ['stdint.h']))
    own_rx = '|'.join(re.escape(n) for n in sorted(set(own)))
    rules = [(HEADER_NAME_LABEL, r'\b(?!(?:%s)\b)[\w-]+\.h\b' % own_rx)]
    rules += DEFAULT_BANNED
    rules += [(e['label'], e['regex']) for e in b.get('extra', [])]
    return [(l, r) for l, r in rules if l not in skip]


def allowed_match(ctx, label, tok):
    """A name on an allow-list is exempt from the file-name rules; a leak-list
    term exempts any match containing it."""
    if label in NAME_RULES:
        if tok in ctx.allow_names:
            return True
    return any(t and t in tok for t in ctx.allow_terms)


def check_banned(ctx, header, text, skip_first_line=False):
    rep = ctx.rep
    for n, line in enumerate(text.splitlines(), 1):
        if skip_first_line and n == 1:
            continue
        for label, rx in ctx.rules:
            m = re.search(rx, line)
            if m and not allowed_match(ctx, label, m.group(0)):
                rep.fail('%s:%d' % (header, n),
                         'banned content (%s) %r in: %s' % (label, m.group(0), line.strip()))


def check_docs_scan(ctx):
    """Optional: the source-path and file-name rules over prose documents."""
    ds = ctx.cfg.get('docs_scan')
    if not ds:
        return
    labels = set(ds.get('rules', sorted(NAME_RULES)))
    rules = [(l, r) for l, r in ctx.rules if l in labels]
    seen = set()
    for pat in ds.get('paths', []):
        for path in sorted(glob.glob(os.path.join(ctx.root, pat), recursive=True)):
            rel = os.path.relpath(path, ctx.root)
            if rel in seen or not os.path.isfile(path):
                continue
            seen.add(rel)
            try:
                text = ctx.read(rel)
            except (OSError, UnicodeDecodeError):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                for label, rx in rules:
                    for m in re.finditer(rx, line):
                        if not allowed_match(ctx, label, m.group(0)):
                            ctx.rep.fail('%s:%d' % (rel, n), 'banned content (%s) %r in: %s'
                                         % (label, m.group(0), line.strip()))


# ---------------------------------------------------------------------------
# Parsing and generic consistency
# ---------------------------------------------------------------------------
def parse_defines(text):
    defs = {}
    for line in text.splitlines():
        m = SHL_RE.match(line)
        if m:
            defs[m.group(1)] = 1 << int(m.group(2))
            continue
        m = DEF_RE.match(line)
        if m:
            defs[m.group(1)] = int(m.group(2), 0)
    return defs


def parse_fields(rep, header, text):
    """Legacy form: FIELD: WORD.name hi:lo grade, 32-bit words."""
    fields = {}
    for n, line in enumerate(text.splitlines(), 1):
        if 'FIELD:' not in line or '<' in line:  # '<' marks the grammar lines
            continue
        m = FIELD_RE.search(line)
        if not m:
            rep.fail('%s:%d' % (header, n), 'malformed FIELD line: %s' % line.strip())
            continue
        word, name, hi, lo, grade = m.group(1), m.group(2), int(m.group(3)), int(m.group(4)), m.group(5)
        key = '%s.%s' % (word, name)
        if key in fields:
            rep.fail('%s:%d' % (header, n), 'duplicate field %s' % key)
        if not (0 <= lo <= hi <= 31):
            rep.fail('%s:%d' % (header, n), 'bad range %d:%d for %s' % (hi, lo, key))
        if grade not in GRADES:
            rep.fail('%s:%d' % (header, n), 'bad grade %r for %s' % (grade, key))
        fields[key] = (hi, lo, grade, n)
    _check_overlap(rep, header, {k: (v[0], v[1], k.split('.')[0]) for k, v in fields.items()})
    return fields


def _check_overlap(rep, header, spans):
    by_owner = {}
    for key, (hi, lo, owner) in spans.items():
        by_owner.setdefault(owner, []).append((hi, lo, key))
    for owner, items in by_owner.items():
        items.sort()
        for i, (hi, lo, key) in enumerate(items):
            for hi2, lo2, key2 in items[i + 1:]:
                if lo2 <= hi and lo <= hi2:
                    rep.fail(header, 'fields overlap in %s: %s (%d:%d) and %s (%d:%d)'
                             % (owner, key, hi, lo, key2, hi2, lo2))


def check_macros(rep, header, fields, defs, pairs, inplace):
    """Legacy form: explicit (field, SHIFT macro, MASK macro) pairs."""
    for key, sh, mk in pairs:
        if key not in fields:
            rep.fail(header, 'missing FIELD for %s' % key)
            continue
        hi, lo = fields[key][0], fields[key][1]
        if sh not in defs or mk not in defs:
            rep.fail(header, 'missing macro %s or %s' % (sh, mk))
            continue
        if defs[sh] != lo or defs[mk] != (1 << (hi - lo + 1)) - 1:
            rep.fail(header, '%s macros (shift %d, mask 0x%x) contradict FIELD %d:%d'
                     % (key, defs[sh], defs[mk], hi, lo))
    for key, mk in inplace:
        if key not in fields:
            rep.fail(header, 'missing FIELD for %s' % key)
            continue
        hi, lo = fields[key][0], fields[key][1]
        want = ((1 << (hi - lo + 1)) - 1) << lo
        if defs.get(mk) != want:
            rep.fail(header, '%s = 0x%x, FIELD %s %d:%d needs 0x%x'
                     % (mk, defs.get(mk, -1), key, hi, lo, want))


def check_testvecs(rep, header, text, fields):
    """Legacy form. Returns {(value, word): {field: value}}."""
    vecs = {}
    for n, line in enumerate(text.splitlines(), 1):
        if 'TESTVEC:' not in line or '<' in line:
            continue
        m = TV_RE.search(line)
        if not m:
            rep.fail('%s:%d' % (header, n), 'malformed TESTVEC line: %s' % line.strip())
            continue
        value, word = int(m.group(1), 16), m.group(2)
        vecs[value, word] = {}
        for part in m.group(3).split(','):
            name, _, want = part.strip().partition('=')
            key = '%s.%s' % (word, name)
            if key not in fields:
                rep.fail('%s:%d' % (header, n), 'TESTVEC names unknown field %s' % key)
                continue
            hi, lo = fields[key][0], fields[key][1]
            got = (value >> lo) & ((1 << (hi - lo + 1)) - 1)
            vecs[value, word][name] = got
            if got != int(want, 0):
                rep.fail('%s:%d' % (header, n), '0x%x as %s: %s is %d by the header ranges (%d:%d), TESTVEC says %s'
                         % (value, word, name, got, hi, lo, want))
    return vecs


def parse_regs(rep, ctx, header, text, block, space=None):
    regs = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not re.search(r'\bREG:', line) or '<' in line:
            continue
        where = '%s:%d' % (header, n)
        m = REG_RE.match(line)
        if not m:
            rep.fail(where, 'malformed REG line (offset must be 1-4 lowercase hex digits, '
                     'one REG per line, nothing else on it): %s' % line.strip())
            continue
        blk, name, off, acc, width, count, reg_space, reset, grade = m.groups()
        key = '%s.%s' % (blk, name)
        off = int(off, 16)
        count = int(count) if count else 1
        width = int(width)
        if blk != block:
            rep.fail(where, 'REG block %s in a %s header' % (blk, block))
        if key in regs:
            rep.fail(where, 'duplicate register %s' % key)
        if grade not in GRADES:
            rep.fail(where, 'bad grade %r for %s' % (grade, key))
        if width not in (8, 16, 32, 64):
            rep.fail(where, 'odd width %d for %s' % (width, key))
        if off > ctx.max_reg_offset or off + count - 1 > ctx.max_reg_addr:
            rep.fail(where, '%s offset/count 0x%x/%d outside the %d-bit register space'
                     % (key, off, count, ctx.address_bits))
        if count < 1:
            rep.fail(where, '%s has count 0' % key)
        regs[key] = dict(off=off, acc=acc, width=width, count=count, reset=reset,
                         grade=grade, line=n, space=reg_space or space)
    if not regs:
        rep.fail(header, 'no REG entries')
    return regs


def check_reg_overlap(rep, allregs):
    # Offsets collide only within one address space; a register with no space
    # is in the default one.
    by_space = {}
    for k, r in allregs.items():
        by_space.setdefault(r.get('space'), []).append((r['off'], r['off'] + r['count'] - 1, k))
    for items in by_space.values():
        items.sort()
        for i, (lo, hi, k) in enumerate(items):
            for lo2, hi2, k2 in items[i + 1:]:
                if lo2 <= hi:
                    rep.fail('registers', '%s (0x%x-0x%x) overlaps %s (0x%x-0x%x)'
                             % (k, lo, hi, k2, lo2, hi2))


def parse_fields_new(rep, header, text, regs, widths=None):
    """widths, when given, is filled with the bit width of each field's word."""
    fields = {}
    words = {}                               # non-register word -> declared width
    for line in text.splitlines():
        m = WORD_RE.search(line)
        if m and '<' not in line:
            words[m.group(1)] = int(m.group(2))
    for n, line in enumerate(text.splitlines(), 1):
        if 'FIELD:' not in line or '<' in line:
            continue
        where = '%s:%d' % (header, n)
        m3 = FIELD3_RE.search(line)
        if m3:
            blk, reg, fname, hi, lo, grade = m3.groups()
            owner, key = '%s.%s' % (blk, reg), '%s.%s.%s' % (blk, reg, fname)
            if owner not in regs:
                rep.fail(where, 'FIELD %s names a register with no REG line' % key)
                continue
            width = regs[owner]['width']
        else:
            m2 = FIELD2_RE.search(line)
            if not m2:
                rep.fail(where, 'malformed FIELD line: %s' % line.strip())
                continue
            word, fname, hi, lo, grade = m2.groups()
            owner, key, width = word, '%s.%s' % (word, fname), words.get(word, 32)
        hi, lo = int(hi), int(lo)
        if key in fields:
            rep.fail(where, 'duplicate field %s' % key)
        if not (0 <= lo <= hi < width):
            rep.fail(where, 'bad range %d:%d for %s in a %d-bit word' % (hi, lo, key, width))
        if grade not in GRADES:
            rep.fail(where, 'bad grade %r for %s' % (grade, key))
        fields[key] = (hi, lo, grade, n, owner)
        if widths is not None:
            widths[key] = width
    _check_overlap(rep, header, {k: (v[0], v[1], v[4]) for k, v in fields.items()})
    return fields


def macro_base(key, prefix):
    parts = key.split('.')
    if len(parts) == 2:                      # a non-register word
        parts = [prefix] + parts
    return '_'.join(parts).upper()


def check_macros_new(rep, header, fields, defs, prefix):
    for key, (hi, lo, _g, n, _o) in fields.items():
        base = macro_base(key, prefix)
        sh, mk = defs.get(base + '_SHIFT'), defs.get(base + '_MASK')
        if sh is None or mk is None:
            rep.fail('%s:%d' % (header, n), 'missing macro %s_SHIFT or %s_MASK for %s' % (base, base, key))
            continue
        if sh != lo or mk != (1 << (hi - lo + 1)) - 1:
            rep.fail('%s:%d' % (header, n), '%s macros (shift %d, mask 0x%x) contradict FIELD %d:%d'
                     % (key, sh, mk, hi, lo))


def parse_enums(rep, header, text, fields, defs, prefix):
    enums = {}
    for n, line in enumerate(text.splitlines(), 1):
        if 'ENUM:' not in line or '<' in line:
            continue
        where = '%s:%d' % (header, n)
        m = ENUM_RE.search(line)
        if not m:
            rep.fail(where, 'malformed ENUM line: %s' % line.strip())
            continue
        target, val, label, grade = m.group(1), int(m.group(2), 0), m.group(3), m.group(4)
        if target not in fields:
            rep.fail(where, 'ENUM names unknown field %s' % target)
            continue
        hi, lo = fields[target][0], fields[target][1]
        if val >= 1 << (hi - lo + 1):
            rep.fail(where, 'ENUM value %d does not fit %s (%d:%d)' % (val, target, hi, lo))
        if grade not in GRADES:
            rep.fail(where, 'bad grade %r on ENUM %s' % (grade, label))
        if (target, label) in enums:
            rep.fail(where, 'duplicate ENUM %s %s' % (target, label))
        enums[target, label] = val
        macro = '%s_%s' % (macro_base(target, prefix), label.upper())
        if defs.get(macro) != val:
            rep.fail(where, 'ENUM %s %s = %d but macro %s is %s'
                     % (target, label, val, macro, defs.get(macro)))
    return enums


def hex_literals_outside_regs(ctx, header, text):
    """A register offset may appear only inside a REG line."""
    offs = set()
    for r in ctx.allregs.values():
        if r['off'] >= 0x100:
            offs.add(r['off'])
            if r['count'] <= 64:
                offs.update(range(r['off'], r['off'] + r['count']))
    for n, line in enumerate(text.splitlines(), 1):
        if REG_RE.match(line):
            continue
        for m in HEXLIT_RE.finditer(line):
            tok = m.group(0)
            v = int(tok, 16)
            digits = len(tok) - 2
            reason = None
            if v in offs:
                reason = 'a register offset'
            elif digits == 4 and 0x1000 <= v <= ctx.max_reg_addr and (v + 1) & v:
                reason = 'a 4-digit value in the register address space'
            if reason:
                ctx.rep.fail('%s:%d' % (header, n),
                             '%s (%s) outside a REG entry; write the register name, not the number: %s'
                             % (tok, reason, line.strip()))


def decode_field(value, fields, key):
    hi, lo = fields[key][0], fields[key][1]
    return (value >> lo) & ((1 << (hi - lo + 1)) - 1)


def check_vectors_new(rep, header, text, fields, allregs, widths=None):
    vecs = []
    for n, line in enumerate(text.splitlines(), 1):
        if ('TESTVEC:' not in line and 'EXAMPLE (unverified):' not in line) or '<' in line:
            continue
        where = '%s:%d' % (header, n)
        m = TV2_RE.search(line)
        if not m:
            rep.fail(where, 'malformed TESTVEC/EXAMPLE line: %s' % line.strip())
            continue
        kind, value, target, rest = m.group(1), int(m.group(2), 16), m.group(3), m.group(4)
        vals = {}
        for part in rest.split(','):
            name, _, want = part.strip().partition('=')
            key = '%s.%s' % (target, name)
            if key not in fields:
                rep.fail(where, '%s names unknown field %s' % (kind, key))
                continue
            if want.startswith('@'):
                if want[1:] not in allregs:
                    rep.fail(where, '%s refers to unknown register %s' % (kind, want))
                    continue
                exp = allregs[want[1:]]['off']
            else:
                exp = int(want, 0)
            if widths and value >> widths[key]:
                rep.fail(where, '%s value 0x%x is wider than %s (%d bits)' % (kind, value, target, widths[key]))
                continue
            got = decode_field(value, fields, key)
            vals[name] = got
            if got != exp:
                rep.fail(where, '0x%x as %s: %s is %d (0x%x) by the header ranges, %s says %s'
                         % (value, target, name, got, got, kind, want))
        vecs.append((kind, value, target, vals, n))
    return vecs


def corpus_hex(ctx, docs):
    seen = set()
    for doc in docs:
        for m in HEXLIT_RE.finditer(ctx.read_doc(doc)):
            seen.add(int(m.group(0), 16))
    return seen


def check_vectors_in_notes(ctx, h):
    """Every TESTVEC value must be one the notes record; others are EXAMPLEs."""
    hexes = corpus_hex(ctx, h.cfg['notes_corpus'])
    for kind, value, _target, _vals, n in h.vecs:
        if kind == 'TESTVEC' and value not in hexes:
            ctx.rep.fail('%s:%d' % (h.file, n), 'TESTVEC value 0x%x is not recorded in the RE notes; '
                         'write it as an unverified EXAMPLE' % value)


def check_no_addresses(ctx, h):
    """For headers that must carry no address values (DMA descriptors, say).

    A decimal literal of seven or more digits is refused; a hex literal of five
    or more digits is allowed only as a contiguous bit mask in a *_MASK macro or
    in the one configured size-limit macro; a macro with ADDR in its name must
    be a SHIFT, MASK or BITS; and no vector may name or set bits in an address
    field (a field whose name starts with the configured prefix, default 'addr').
    """
    rep, header, text, fields = ctx.rep, h.file, h.text, h.fields
    limit = h.cfg.get('size_limit_macro')
    pfx = h.cfg.get('address_field_prefix', 'addr')
    h.addr_fields = [k for k in fields if k.split('.')[1].startswith(pfx)]
    for n, line in enumerate(text.splitlines(), 1):
        where = '%s:%d' % (header, n)
        m = DEC_BIG_RE.search(line)
        if m:
            rep.fail(where, 'decimal literal %s could be an address: %s' % (m.group(0), line.strip()))
        dm = re.match(r'^#define\s+(\w+)\s+(.*)$', line)
        name = dm.group(1) if dm else None
        if 'TESTVEC:' in line or 'EXAMPLE (unverified):' in line:
            continue
        for hm in HEXLIT_RE.finditer(line):
            tok = hm.group(0)
            v = int(tok, 16)
            if len(tok) - 2 < 5:
                continue
            if name and name.endswith('_MASK') and is_mask(v):
                continue
            if limit and name == limit:
                continue
            rep.fail(where, 'hex literal %s (5+ digits) could be an address; only a contiguous '
                     'MASK%s may be this wide: %s' % (tok, ' or ' + limit if limit else '', line.strip()))
        if name and 'ADDR' in name and not re.search(r'_(SHIFT|MASK|BITS)$', name):
            rep.fail(where, 'address macro %s is not a SHIFT, MASK or BITS (values are omitted): %s'
                     % (name, line.strip()))
    for n, line in enumerate(text.splitlines(), 1):
        m = TV2_RE.search(line)
        if not m or '<' in line:
            continue
        value, target = int(m.group(2), 16), m.group(3)
        for key in h.addr_fields:
            if key.split('.')[0] != target:
                continue
            hi, lo = fields[key][0], fields[key][1]
            if (value >> lo) & ((1 << (hi - lo + 1)) - 1):
                rep.fail('%s:%d' % (header, n), '0x%x sets bits in address field %s; vectors carry no address'
                         % (value, key))
        for part in m.group(4).split(','):
            name = part.strip().partition('=')[0]
            if ('%s.%s' % (target, name)) in h.addr_fields:
                rep.fail('%s:%d' % (header, n), 'vector names address field %s.%s' % (target, name))


# ---------------------------------------------------------------------------
# Prose claims. Each claim: label, doc, regex (re.S, case-sensitive), binds.
# A bind is a list whose first element names the kind:
#   ["F", field, hi_group, lo_group]   field range equals the prose; lo_group
#                                      omitted = single bit; hi_group omitted =
#                                      the field merely has to exist
#   ["O", reg, group]                  offset equals the prose
#   ["E", reg, group]                  last register of the block
#   ["C", reg, group, mult]            count * mult equals the prose
#   ["CDEC", reg, group, add]          count equals decimal group + add
#   ["LO", field, group, add]          field's low bit is group + add
#   ["WHEX", field, group]             field width is four bits per hex digit
#   ["IN", [fields], hi_group, lo_group]  fields lie inside the prose range
#   ["M", [fields], group]             single-bit fields make up the prose mask
#   ["EN", field, label, group]        enum value
#   ["DEF", macro, group]              macro equals decimal group
#   ["DEFN", macro, group]             macro equals the (hex or decimal) group, 32 bits
#   ["DEFL", macro, group]             as DEFN, low 16 bits
#   ["FW", field, hi_group, lo_group]  field width equals the prose range's
#   ["FWD", field, group]              field width equals decimal group
#   ["WDEC", None, hi_group, lo_group, bits]  prose range is `bits` wide
#   ["EQ", value, group]               prose number equals value
# ---------------------------------------------------------------------------
def check_claims(ctx, where, claims, fields, regs, enums, defs):
    rep = ctx.rep
    cache = {}
    for c in claims:
        label, doc, rx, binds = c['label'], c['doc'], c['regex'], c.get('binds', [])
        if doc not in cache:
            cache[doc] = ctx.read_doc(doc)
        m = re.search(rx, cache[doc], re.S)
        if not m:
            rep.fail(doc, 'prose for "%s" not found (the passage changed or was removed); pattern: %s' % (label, rx))
            continue

        def g(i):
            return m.group(i)

        def num(i):
            t = g(i)
            return int(t, 16) if t.startswith('0x') else int(t)
        for b in binds:
            kind = b[0]
            if kind == 'WDEC':
                if int(g(b[2])) - int(g(b[3])) + 1 != b[4]:
                    rep.fail(doc, '"%s": prose field is not %d bits wide' % (label, b[4]))
                continue
            if kind == 'EQ':
                if num(b[2]) != b[1]:
                    rep.fail(doc, '"%s": prose says %s, the header says %s' % (label, g(b[2]), b[1]))
                continue
            if kind in ('DEFN', 'DEFL'):
                want = num(b[2]) & (0xffff if kind == 'DEFL' else 0xffffffff)
                if defs.get(b[1]) != want:
                    rep.fail(where, '%s is %s but %s says 0x%x ("%s")'
                             % (b[1], defs.get(b[1]), doc, want, label))
                continue
            if kind in ('FW', 'FWD'):
                key = b[1]
                if key not in fields:
                    rep.fail(where, 'no FIELD for %s (claim "%s")' % (key, label))
                    continue
                have = fields[key][0] - fields[key][1] + 1
                want = int(g(b[2])) - int(g(b[3])) + 1 if kind == 'FW' else int(g(b[2]))
                if have != want:
                    rep.fail(where, '%s is %d bits wide but %s says %d ("%s")'
                             % (key, have, doc, want, label))
                continue
            if kind == 'DEF':
                if defs.get(b[1]) != int(g(b[2])):
                    rep.fail(where, '%s is %s but %s says %s ("%s")'
                             % (b[1], defs.get(b[1]), doc, g(b[2]), label))
                continue
            if kind == 'F':
                key = b[1]
                if key not in fields:
                    rep.fail(where, 'no FIELD for %s (claim "%s")' % (key, label))
                    continue
                if len(b) < 3 or b[2] is None:
                    continue
                hi = int(g(b[2]))
                lo = int(g(b[3])) if len(b) > 3 and b[3] else hi
                if (hi, lo) != (fields[key][0], fields[key][1]):
                    rep.fail(where, '%s is %d:%d in the header but %d:%d in %s ("%s")'
                             % (key, fields[key][0], fields[key][1], hi, lo, doc, label))
            elif kind in ('O', 'E', 'C', 'CDEC'):
                key = b[1]
                if key not in regs:
                    rep.fail(where, 'no REG for %s (claim "%s")' % (key, label))
                    continue
                r = regs[key]
                if kind == 'O':
                    want, have, what = num(b[2]), r['off'], 'offset'
                elif kind == 'E':
                    want, have, what = num(b[2]), r['off'] + r['count'] - 1, 'last register'
                elif kind == 'C':
                    want, have, what = num(b[2]), r['count'] * b[3], 'count'
                else:
                    want, have, what = int(g(b[2])) + b[3], r['count'], 'count'
                if want != have:
                    rep.fail(where, '%s %s is 0x%x in the header but 0x%x in %s ("%s")'
                             % (key, what, have, want, doc, label))
            elif kind == 'LO':
                key = b[1]
                if key in fields and fields[key][1] != int(g(b[2])) + b[3]:
                    rep.fail(where, '%s low bit is %d but %s implies %d ("%s")'
                             % (key, fields[key][1], doc, int(g(b[2])) + b[3], label))
            elif kind == 'WHEX':
                key = b[1]
                if key in fields and fields[key][0] - fields[key][1] + 1 != 4 * len(g(b[2])):
                    rep.fail(where, '%s width contradicts the %d-bit mask in %s ("%s")'
                             % (key, 4 * len(g(b[2])), doc, label))
            elif kind == 'IN':
                lo_, hi_ = int(g(b[3])), int(g(b[2]))
                for key in b[1]:
                    if key in fields and not (lo_ <= fields[key][1] and fields[key][0] <= hi_):
                        rep.fail(where, '%s (%d:%d) lies outside %d:%d in %s ("%s")'
                                 % (key, fields[key][0], fields[key][1], hi_, lo_, doc, label))
            elif kind == 'M':
                bits = 0
                for key in b[1]:
                    if key in fields:
                        bits |= 1 << fields[key][1]
                if bits != num(b[2]):
                    rep.fail(where, 'fields %s make mask 0x%x but %s says 0x%x ("%s")'
                             % (', '.join(b[1]), bits, doc, num(b[2]), label))
            elif kind == 'EN':
                got = enums.get((b[1], b[2]))
                if got != int(g(b[3])):
                    rep.fail(where, 'ENUM %s %s is %s but %s says %s ("%s")'
                             % (b[1], b[2], got, doc, g(b[3]), label))
            else:
                rep.fail(where, 'claim "%s": unknown bind kind %r' % (label, kind))


# ---------------------------------------------------------------------------
# Generated Rust: leak scan and staleness
# ---------------------------------------------------------------------------
def rust_modules(ctx):
    return {h['module']: h['file'] for h in ctx.cfg['headers'] if h.get('module')}


def rust_out_dir(ctx):
    return ctx.cfg.get('rust', {}).get('out_dir', 'generated')


def regen_hint(ctx):
    return ctx.cfg.get('project', {}).get(
        'regenerate', 'retools/tools/defs/gen_decode_rust.py --config defs.toml')


def check_rust(ctx):
    rep = ctx.rep
    name = ctx.cfg['project']['name']
    rust_dir_rel = rust_out_dir(ctx)
    rust_dir = os.path.join(ctx.root, rust_dir_rel)
    mods = rust_modules(ctx)
    banner = re.compile(r'^// generated from %s [0-9a-f]{12} ([\w.-]+) - do not edit, regenerate in %s$'
                        % (re.escape(name), re.escape(name)))
    rust_banned = [
        ('%s named outside the banner' % name, r'(?i)\b%s\b' % re.escape(name)),
        ('note-file pointer', r'docs/|\.md\b|\.rs\b'),
        ('URL or host pointer', r'https?://|git@|ssh://'),
    ]
    rust_banned += [(e['label'], e['regex']) for e in ctx.cfg.get('rust', {}).get('banned_extra', [])]
    if not os.path.isdir(rust_dir):
        rep.fail(rust_dir, 'generated Rust directory is missing; run %s' % regen_hint(ctx))
        return
    for f in sorted(f for f in os.listdir(rust_dir) if not f.startswith('.')):
        if not f.endswith('.rs') or f[:-3] not in mods:
            rep.fail(os.path.join(rust_dir, f), 'not one of the %d generated modules' % len(mods))
    for mod, header in mods.items():
        rel = '%s/%s.rs' % (rust_dir_rel, mod)
        try:
            with open(os.path.join(rust_dir, mod + '.rs'), encoding='utf-8') as f:
                text = f.read()
        except OSError:
            rep.fail(rel, 'missing; run %s' % regen_hint(ctx))
            continue
        lines = text.splitlines()
        m = banner.match(lines[0]) if lines else None
        if not m or m.group(1) != os.path.basename(header):
            rep.fail(rel + ':1', 'banner is not "generated from %s <12 hex> %s - do not edit, regenerate in %s"'
                     % (name, os.path.basename(header), name))
        hdr = ctx.read(header).lower()
        for n, line in enumerate(lines, 1):
            where = '%s:%d' % (rel, n)
            if n > 1:
                for label, rx in ctx.rules:
                    mm = re.search(rx, line)
                    if mm and not allowed_match(ctx, label, mm.group(0)):
                        rep.fail(where, 'banned content (%s) %r in: %s' % (label, mm.group(0), line.strip()))
                for label, rx in rust_banned:
                    mm = re.search(rx, line)
                    if mm:
                        rep.fail(where, 'banned content (%s) %r in: %s' % (label, mm.group(0), line.strip()))
            for lit in re.findall(r'\b0x([0-9a-fA-F]{5,})\b', line):
                v = int(lit, 16)
                low = (v >> ((v & -v).bit_length() - 1)) if v else 0
                contiguous = v & (v + 1) == 0 or low & (low + 1) == 0
                if not contiguous and lit.lower().lstrip('0') not in hdr:
                    rep.fail(where, 'hex literal 0x%s is neither in %s nor a bit mask: %s'
                             % (lit, os.path.basename(header), line.strip()))
            if re.search(r'\b\d{7,}\b', line):
                rep.fail(where, 'decimal literal of seven or more digits: %s' % line.strip())


def check_rust_fresh(ctx, config_path):
    gen = os.path.join(HERE, 'gen_decode_rust.py')
    r = subprocess.run([sys.executable, gen, '--config', config_path, '--check'],
                       capture_output=True, text=True)
    if r.returncode:
        for line in (r.stderr or r.stdout).strip().splitlines() or ['generator failed']:
            ctx.rep.fail(rust_out_dir(ctx), line)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def load_plugin(ctx, config_path):
    path = ctx.cfg.get('project', {}).get('plugin')
    if not path:
        return None
    full = os.path.join(ctx.root, path)
    spec = importlib.util.spec_from_file_location('defs_plugin', full)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.dirname(full))
    spec.loader.exec_module(mod)
    return mod


def parse_header(ctx, hc, text, selected):
    rep = ctx.rep if selected else Report(silent=True)
    h = Hdr(hc, text, selected)
    if h.form == 'legacy':
        h.fields = parse_fields(rep, h.file, text)
        h.defs = parse_defines(text)
        check_macros(rep, h.file, h.fields, h.defs,
                     hc.get('macro_pairs', []), hc.get('inplace', []))
        h.vecs = check_testvecs(rep, h.file, text, h.fields)
    elif h.form == 'regs':
        h.regs = parse_regs(rep, ctx, h.file, text, h.block, hc.get('space')) if h.block else {}
        h.fields = parse_fields_new(rep, h.file, text, h.regs, h.widths)
        h.defs = parse_defines(text)
        check_macros_new(rep, h.file, h.fields, h.defs, h.prefix)
        h.enums = parse_enums(rep, h.file, text, h.fields, h.defs, h.prefix)
    else:
        raise ConfigError('%s: unknown form %r (use "regs" or "legacy")' % (h.file, h.form))
    return h


def run(cfg, root, config_path, selected_files=None, rust_only=False, verbose=False):
    rep = Report()
    ctx = Ctx(cfg, root, rep, verbose)
    ctx.allow_names = load_allow(ctx, 'source_names') | load_allow(ctx, 'copy')
    ctx.allow_terms = load_allow(ctx, 'leak')
    ctx.rules = banned_rules(ctx)
    plugin = load_plugin(ctx, config_path)
    configured = [h['file'] for h in cfg['headers']]
    chosen = [] if rust_only else (selected_files or configured)
    for f in chosen:
        if f not in configured:
            print('error: %s is not a configured header (%s)' % (f, ', '.join(configured)), file=sys.stderr)
            return 2

    for hc in cfg['headers']:
        try:
            text = ctx.read(hc['file'])
        except OSError as e:
            if hc['file'] in chosen or not chosen:
                print('error: cannot read %s: %s' % (hc['file'], e), file=sys.stderr)
                return 2
            continue
        h = parse_header(ctx, hc, text, hc['file'] in chosen)
        ctx.hdrs[hc['file']] = h
        if h.block:
            ctx.allregs.update(h.regs)

    sel = [ctx.hdrs[f] for f in chosen if f in ctx.hdrs]
    if any(h.block for h in sel):
        check_reg_overlap(rep, ctx.allregs)
    for h in sel:
        check_banned(ctx, h.file, h.text)
        if h.form == 'regs':
            regs_pool = ctx.allregs if h.block else {}
            if h.block:
                hex_literals_outside_regs(ctx, h.file, h.text)
            h.vecs = check_vectors_new(rep, h.file, h.text, h.fields, regs_pool, h.widths)
            if h.cfg.get('notes_corpus'):
                check_vectors_in_notes(ctx, h)
            if h.cfg.get('no_addresses'):
                check_no_addresses(ctx, h)
        if plugin and hasattr(plugin, 'check_header'):
            plugin.check_header(ctx, h)
        if verbose:
            print('%s: %d registers, %d fields, %d enums, %d vectors, %d macros'
                  % (h.file, len(h.regs), len(h.fields), len(h.enums), len(h.vecs), len(h.defs)))

    # Claims and group checks run once per group that has a selected header.
    groups = {}
    for h in ctx.hdrs.values():
        groups.setdefault(h.group, []).append(h)
    claims = list(cfg.get('claims', []))
    if plugin and hasattr(plugin, 'CLAIMS'):
        claims += list(plugin.CLAIMS)
    for gname, members in groups.items():
        if not any(m.selected for m in members):
            continue
        merged = dict(fields={}, regs={}, enums={}, defs={})
        for m in members:
            merged['fields'].update(m.fields)
            merged['regs'].update(m.regs)
            merged['enums'].update(m.enums)
            merged['defs'].update(m.defs)
        label = '/'.join(m.file for m in members)
        gclaims = [c for c in claims if c.get('group', c.get('header')) == gname]
        if gclaims:
            check_claims(ctx, label, gclaims, merged['fields'], merged['regs'], merged['enums'], merged['defs'])
        if plugin and hasattr(plugin, 'check_group'):
            plugin.check_group(ctx, gname, members)
    known = set(groups)
    for c in claims:
        k = c.get('group', c.get('header'))
        if k not in known:
            print('error: claim "%s" names unknown group/header %r' % (c.get('label'), k), file=sys.stderr)
            return 2

    if chosen == configured or rust_only:
        check_docs_scan(ctx)
    if plugin and hasattr(plugin, 'check_final'):
        plugin.check_final(ctx)
    if (rust_only or not selected_files) and cfg.get('rust'):
        check_rust(ctx)
        check_rust_fresh(ctx, config_path)

    if rep.fails:
        print('%d failure(s)' % len(rep.fails))
        return 1
    if chosen:
        print('ok: %s publish-safe and consistent with the prose' % ', '.join(chosen))
    if (rust_only or not selected_files) and cfg.get('rust'):
        print('ok: generated Rust publish-safe and fresh against the headers')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--config', required=True, help='path to the repo defs.toml')
    ap.add_argument('--header', action='append',
                    help='header (as listed in the config) to check; repeatable; default all')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--rust', action='store_true',
                    help='check only the generated Rust (leak scan and staleness)')
    args = ap.parse_args(argv)
    try:
        cfg, root = load_config(args.config)
    except ConfigError as e:
        print('error: %s' % e, file=sys.stderr)
        return 2
    try:
        return run(cfg, root, os.path.abspath(args.config), args.header, args.rust, args.verbose)
    except ConfigError as e:
        print('error: %s' % e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
