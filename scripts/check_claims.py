#!/usr/bin/env python3
"""Check the mechanical claims of routine entries against the binaries.

Usage: scripts/check_claims.py [DOC ...] [--status established|all] [--routine NAME]
                               [--json FILE] [--blocking] [--jobs N] [--quiet]

Each entry (a "- " bullet with its continuation lines, or a table row with a routine and a
binary column) that names a routine and its binary is compared with the fact sheet that
scripts/facts.py builds for that routine in that build. The claims read are:

  address      the routine's address, and any "`name` at 0x..." of another routine in the file
  size         "occupies N bytes", "N bytes at address", table sizes, "N words", "0xA to 0xB"
  frame        "N-byte frame", "frame is N bytes"
  got          "gp-N" slots, "GOT index N", "local GOT entry N", "dynamic symbol N"
  callee       "calls `X`", "call to `X`", "`X` (at 0xA)" naming a routine of the file
  error        SetError arguments (numbers and the GL error names)
  error-name   an error named in words with no number anywhere in the entry
  branch-likely  bnel/beql/... mnemonics and "branch-likely" statements
  delay-slot   "skips the li", "runs only when taken", "in the delay slot of"
  return       constant return values ("returns 0", "returns TRUE")
  args         "Nth argument (aN)", source and destination arguments, "the word at address N"
  store-order  "+A, then +B", "in that order", "ascending", issue-order lists
  bytes-per-pass  "N bytes a pass"
  immediate    0x constants that the routine does not form, load or compare
  offset       "+N" offsets the routine does not reach from any base
  width        "word" or "doubleword at +N" against the width of the accesses at that offset
  width-absolute  the same for absolute process-page words ("the word at address 4128")
  width-narrow "byte" or "halfword at +N" (often a field inside a wider load: report only)
  addiu-word   "the word at +N" where +N is only an address formed with addiu
  stack        "sp+N", "N(sp)" slots that are never stored, or hold a saved register
  position     "the Nth instruction/word"
  insn-address "`insn` at 0xA" or "call at 0xA" where 0xA holds something else
  section      ".mdebug absent", "has no .symtab" and similar
  duplicate    two entries for one routine and address in a document; a repeated clause

A mismatch is reported with the entry, the claim, the fact and the reason. A claim the
checker recognised but could not evaluate is reported as unchecked, never passed. Entries
whose routine or binary cannot be resolved are listed as unresolved.

Run from the repository root inside the toolchain environment (as scripts/facts.py).
With --blocking the exit status is 1 when any mismatch falls in a blocking class
(BLOCKING below); otherwise the run only reports.
"""
import argparse
import collections
import glob
import json
import multiprocessing
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import facts  # noqa: E402

# classes whose mismatches block a push (near-zero false positives on the Established entries)
BLOCKING = ('address', 'size', 'got', 'duplicate', 'delay-slot', 'insn-address', 'addiu-word', 'branch-likely', 'offset',
            'width-absolute')

DEFAULT_DOCS = ['docs/*.md', 'chips/*/README.md']
STATUS_RE = re.compile(r'\b(Established|Inferred|Unverified)\b\.?\**\s*$', re.I)
PATH_RE = re.compile(r'((?:builds/[\w.+-]+/)?(?:usr|sbin|stand|unix|var)(?:/[\w.+-]+)+(?:\([\w.+-]+\))?)')
HEX = r'0x[0-9a-fA-F]+'
ORD = {'first': 1, 'second': 2, 'third': 3, 'fourth': 4, 'fifth': 5, 'sixth': 6, 'seventh': 7, 'eighth': 8,
       'ninth': 9, 'tenth': 10, 'eleventh': 11, 'twelfth': 12}
NUMW = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9,
        'ten': 10, 'eleven': 11, 'twelve': 12}
GL_ERRORS = {1280: ('invalid enum', 'invalid-enum', 'invalid enumeration', 'invalid-enumeration'),
             1281: ('invalid value', 'invalid-value'),
             1282: ('invalid operation', 'invalid-operation'),
             1283: ('stack overflow', 'stack-overflow'),
             1284: ('stack underflow', 'stack-underflow'),
             1285: ('out of memory', 'out-of-memory'),
             0x8031: ('table too large', 'table-too-large')}
# every MIPS IV branch-likely form: the compare branches, the REGIMM branches (the -al forms also link, so
# facts.py counts them as calls), the pseudo-forms beqzl/bnezl and the coprocessor branches
LIKELY_MN = {'beql', 'bnel', 'blezl', 'bgtzl', 'bltzl', 'bgezl', 'bltzall', 'bgezall', 'beqzl', 'bnezl',
             'bc0tl', 'bc0fl', 'bc1tl', 'bc1fl', 'bc2tl', 'bc2fl'}
LIKELY_RE = r'\b(%s)\b' % '|'.join(sorted(LIKELY_MN))
MNEMONICS = set('''add addi addiu addu and andi b bal beq beql beqz beqzl bgez bgezal bgezall bgezl bgtz bgtzl blez
blezl bltz bltzal bltzall bltzl bne bnel bnez bnezl break bc1f bc1fl bc1t bc1tl cache cfc1 ctc1 dadd daddi daddiu daddu
ddiv ddivu div divu dmfc0 dmfc1 dmtc0 dmtc1 dmult dmultu dsll dsll32 dsllv dsra dsra32 dsrav dsrl dsrl32 dsrlv dsub
dsubu eret j jal jalr jr lb lbu ld ldc1 ldl ldr lh lhu li ll lld lui lw lwc1 lwl lwr lwu lwxc1 ldxc1 mfc0 mfc1 mfhi mflo
move movn movz movf movt mtc0 mtc1 mthi mtlo mult multu negu nop nor not or ori pref sb sc scd sd sdc1 sdl sdr sh sll
sllv slt slti sltiu sltu sra srav srl srlv sub subu sw swc1 swl swr swxc1 sdxc1 sync syscall teq tne xor xori abs.s
abs.d add.s add.d c.eq.s c.eq.d c.lt.s c.lt.d c.le.s c.le.d c.un.s c.un.d c.ult.s c.ult.d c.ole.s c.ole.d cvt.d.s
cvt.d.w cvt.s.d cvt.s.w cvt.w.s cvt.w.d cvt.d.l cvt.s.l cvt.l.d cvt.l.s div.s div.d floor.w.s floor.w.d madd.s madd.d
msub.s msub.d mov.s mov.d mul.s mul.d neg.s neg.d nmadd.s nmadd.d nmsub.s nmsub.d recip.s rsqrt.s sqrt.s sqrt.d
sub.s sub.d trunc.w.s trunc.w.d trunc.l.d round.w.s ceil.w.s movf.s movt.s movf.d movt.d movn.s movz.s movn.d movz.d
dneg dnegu'''.split())
CALLEE_SAVED = {'s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 'gp', 'ra', 'fp'} | \
    {'f%d' % i for i in range(20, 32)}


# ===================================================================== entries

class Entry:
    def __init__(self, doc, line, text, heading, table=None):
        self.doc, self.line, self.text, self.heading = doc, line, text, heading
        self.table = table or {}
        self.name = self.binary = self.address = self.size = None
        self.status = ''
        self.subst = ''
        self.file_entry = False
        self.last = line

    @property
    def id(self):
        return '%s:%d' % (self.doc, self.line)


def split_cells(line):
    s = line.strip()
    if s.startswith('|'):
        s = s[1:]
    if s.endswith('|'):
        s = s[:-1]
    return [c.strip() for c in re.split(r'(?<!\\)\|', s)]


def read_entries(doc, text):
    """Bullets (with continuation lines) and table rows of one document."""
    lines = text.split('\n')
    out, heading, head, preamble = [], '', None, []
    i = 0
    seen_entry = False
    while i < len(lines):
        ln = lines[i]
        if ln.startswith('#'):
            heading = ln.lstrip('#').strip()
            head = None
            i += 1
            continue
        if ln.startswith('|'):
            cells = split_cells(ln)
            if head is None:
                head = [c.lower() for c in cells]
            elif not all(re.fullmatch(r':?-+:?', c) for c in cells if c):
                row = dict(zip(head, cells))
                out.append(Entry(doc, i + 1, ln, heading, row))
                seen_entry = True
            i += 1
            continue
        head = None
        if re.match(r'^(?:- |\d+\. )', ln):
            j = i + 1
            body = [re.sub(r'^(?:- |\d+\. )', '', ln)]
            while j < len(lines) and lines[j].strip() and not re.match(r'^(- |#|\||\d+\. )', lines[j]):
                body.append(lines[j].strip())
                j += 1
            out.append(Entry(doc, i + 1, ' '.join(body), heading))
            out[-1].last = j
            seen_entry = True
            i = j
            continue
        if not seen_entry:
            preamble.append(ln)
        i += 1
    return out, '\n'.join(preamble)


class Binaries:
    """Binary paths known to the workspace, to resolve short names (kona.so, odsy_init.o)."""

    def __init__(self):
        self.keys = set()
        tsv = os.path.join(REPO, 'docs', 'inventory', 'functions.tsv')
        if os.path.exists(tsv):
            with open(tsv, encoding='utf-8') as f:
                f.readline()
                for ln in f:
                    self.keys.add(ln.split('\t', 1)[0])
        if not self.keys:
            top = os.path.join(REPO, 'root')
            for d, dirs, files in os.walk(top):
                dirs.sort()
                for f in files:
                    if f.endswith(('.o', '.so', '.a')) or f in ('unix',) or f.endswith(('.img', '.bin', '.image')):
                        self.keys.add(os.path.relpath(os.path.join(d, f), top))
        self.by_base = collections.defaultdict(set)
        for k in self.keys:
            b = k.rsplit('/', 1)[-1]
            self.by_base[b].add(k)
            m = re.search(r'\(([^)]+)\)$', k)
            if m:
                self.by_base[m.group(1)].add(k)
                self.by_base[k.rsplit('/', 1)[-1].split('(')[0] + '(' + m.group(1) + ')'].add(k)

    def resolve(self, ref, hints):
        ref = ref.strip('`').strip()
        if ref in self.keys:
            return ref
        if os.path.exists(os.path.join(REPO, 'root', ref)):
            return ref
        cands = set()
        for k in self.keys:
            if k.endswith('/' + ref) or k == ref:
                cands.add(k)
        if not cands:
            base = ref.rsplit('/', 1)[-1]
            cands = set(self.by_base.get(base, ()))
            if '/' in ref:
                cands = {k for k in cands if ref.split('/')[0] in k}
        if len(cands) == 1:
            return cands.pop()
        if cands:
            for h in hints:
                hc = {k for k in cands if h in k}
                if len(hc) == 1:
                    return hc.pop()
                if hc:
                    cands = hc
            plain = {k for k in cands if not k.startswith('builds/')}
            if len(plain) == 1:
                return plain.pop()
        return None


def identify(e, bins, hints, default_bin):
    t = e.text
    row = e.table
    if row:
        name = next((row[k] for k in row if k in ('routine', 'function', 'name', 'symbol')), '')
        m = re.search(r'`([^`]+)`', name)
        e.name = m.group(1) if m else name.strip() or None
        b = next((row[k] for k in row if k in ('binary', 'file', 'build', 'object')), '')
        bm = PATH_RE.search(b)
        sub = re.search(r'\((builds/[\w.+-]+)\)', b)
        ref = bm.group(1) if bm else b.strip('` ')
        if sub and not ref.startswith('builds/'):
            ref = sub.group(1) + '/' + ref
        e.binary = bins.resolve(ref, hints) if ref else None
        a = next((row[k] for k in row if k in ('address', 'addr')), '')
        am = re.search(HEX, a)
        e.address = int(am.group(0), 16) if am else None
        s = next((row[k] for k in row if k in ('size', 'bytes')), '')
        sm = re.match(r'\s*(\d+)\s*$', s)
        e.size = int(sm.group(1)) if sm else None
        e.status = next((row[k] for k in row if k in ('label', 'status')), '')
        return
    m = re.match(r'\s*`([^`]+)`', t)
    e.name = m.group(1) if m else None
    if e.name and re.search(r'\.(?:so|o|a)(?:\([\w.+-]+\))?$|^(?:usr|builds|sbin)/', e.name):
        e.binary = bins.resolve(e.name, hints)
        e.name = None
        e.file_entry = True
        st = re.findall(r'\b(Established|Inferred|Unverified)\b\.?', t, re.I)
        e.status = st[-1] if st else ''
        return
    lead = t[:400]
    bm = PATH_RE.search(lead)
    ref = None
    if bm:
        ref = bm.group(1)
    else:
        sm = re.match(r'\s*`[^`]+`\s*\(`([^`]+)`', t) or re.match(r'\s*`[^`]+`\s+in\s+`?([\w.+()/-]+\.(?:so|o|a\([\w.]+\)))', t) or \
            re.match(r'\s*`[^`]+`\s*\(\s*([\w.+/-]+\.(?:so|o)|[\w./+-]+\.a\([\w.+-]+\))[\s,]', t)
        if sm:
            ref = sm.group(1)
    if ref:
        sub = re.search(r'\((builds/[\w.+-]+)\)', lead)
        if sub and not ref.startswith('builds/'):
            ref = sub.group(1) + '/' + ref
        e.binary = bins.resolve(ref, hints)
    elif default_bin:
        e.binary = default_bin
    am = re.search(r'^\s*`[^`]+`\s*\((?:[^()]|\([^()]*\))*?(' + HEX + r')', t) or \
        re.search(r'occupies \d+ bytes at (?:address |offset )(' + HEX + r')\b', t) or \
        re.search(r'\d+ bytes at (?:address |offset )(' + HEX + r')\b', t) or \
        re.search(r'(' + HEX + r'),\s*\d+ bytes', lead) or re.search(r'at address (' + HEX + r')\b', t) or \
        re.search(r'\b(?:instructions|bytes) at (?:address |offset )?(' + HEX + r')\b', t)
    e.address = int(am.group(1), 16) if am else None
    sm = re.search(r'occupies (\d+) bytes', t) or re.search(r'(\d+) bytes at (?:address|offset) ' + HEX, t) or \
        re.search(HEX + r',\s*(\d+) bytes', lead)
    e.size = int(sm.group(1)) if sm else None
    st = re.findall(r'\b(Established|Inferred|Unverified)\b\.?', t, re.I)
    e.status = st[-1] if st else ''


# ===================================================================== fact access

class Facts:
    def __init__(self):
        self.cache = {}

    def get(self, binary, name, address, size=None):
        key = (binary, name, address)
        if key in self.cache:
            return self.cache[key]
        path = binary
        member = None
        m = re.fullmatch(r'(.+)\(([^)]+)\)', binary)
        if m:
            path, member = m.groups()
        full = os.path.join(REPO, 'root', path)
        res = None
        err = None
        if os.path.exists(full):
            img = self.image(binary)
            syms = [x for x in img.byname.get(name, []) if x[4]] if (img is not None and name) else []
            order, debug_elsewhere = [], False
            if address is not None and any(x[0] == address for x in syms):
                order = [('0x%x' % address, None)]
            elif address is not None and syms and all(x[5].startswith('inventory') for x in syms):
                # the name is known only from debug information, at another address: a static routine
                # of that name can exist more than once, so read the stated address
                order = [('0x%x' % address, size)]
                debug_elsewhere = True
            elif syms and address is not None and len({x[0] for x in syms}) > 1:
                # facts.py refuses a name that matches several routines; the stated address says which
                order = [('0x%x' % address, size)]
            elif syms:
                order = [(name, None)]
            elif address is not None:
                order = [('0x%x' % address, size)]
            for routine, sz in order:
                try:
                    res = facts.fact_sheet(full, routine, member, size=sz, with_insns=True)
                    if debug_elsewhere:
                        res['routine']['name_elsewhere'] = sorted('0x%x' % x[0] for x in syms)
                    break
                except SystemExit as x:
                    err = str(x)
                except Exception as x:  # a decoding failure is reported, not fatal
                    err = '%s: %s' % (type(x).__name__, x)
        else:
            err = 'no file root/%s' % path
        self.cache[key] = (res, err)
        return res, err

    def image(self, binary):
        path, member = binary, None
        m = re.fullmatch(r'(.+)\(([^)]+)\)', binary)
        if m:
            path, member = m.groups()
        try:
            return facts.image(os.path.join(REPO, 'root', path), member)
        except (SystemExit, Exception):
            return None


# ===================================================================== helpers

def sentences(text):
    parts = re.split(r'(?<=[.;:])\s+(?=[A-Z`(_])', text)
    return [p for p in parts if p.strip()]


FOREIGN = re.compile(r'\((?:the |in the |its )?(?:N32|64-bit|o32|N64|IP\d+\w*|original(?: 32-bit)? build|the N32 build|in N32)\b[^()]*(?:\([^()]*\)[^()]*)*\)|'
                     r'\b(?:N32|64-bit|o32|N64) (?:0x[0-9a-f]+|\+\d+|sp\+\d+|gp-\d+|word \d+|pointer \+\d+)')


ABI_WORDS = {'n32': r'N32', 'n64': r'64-bit|N64', 'o32': r'[Oo]32|original(?: 32-bit)?(?: build)?|older 32-bit'}


def mask_foreign(t, abi=None):
    """Blank what an entry says about another build, so its numbers are not checked against this one:
    parenthesised remarks ("(N32: +528 in place of +704)"), clauses whose subject is another build
    ("; N32 uses gp-28616", "the N32 routine sends two vertices"), contrasts ("where kona.so uses
    0x16c318") and slots of another release ("the 6.5.30 o32 slot at gp-32476"). A sentence that only
    compares with another build ("the same steps as the N32 build: ...") keeps its claims."""
    blank = lambda m: ' ' * len(m.group(0))
    t = FOREIGN.sub(blank, t)
    others = [w for k, w in ABI_WORDS.items() if k != abi] if abi else list(ABI_WORDS.values())
    end = r'[^;]*?(?=\.\s|\.$|;|$)'
    if others:
        subj = (r'(?:(?<=[.;:(])|^|(?<=, )|(?<=\band )|(?<=\bbut ))\s*(?:[Tt]he |[Ii]ts |[Ii]n the |[Ii]n )?(?:' + '|'.join(others) +
                r")(?: build| routine| copy| copies| body| code| entry| listing| version)?(?:'s)?,?\s+"
                r'(?:[a-z]+s|use|load|have|are|instead|only|also|then|first|never|always)\b')
        t = re.sub(subj + end, blank, t)
        t = re.sub(r'\b(?:' + '|'.join(others) + r')\s*:' + end, blank, t)
    t = re.sub(r'\b(?:where|whereas|unlike|as opposed to|in place of|instead of)\b' + end, blank, t)
    t = re.sub(r'(?:(?<=[.;]\s)|^)(?:Against|Compared with|In) `?[\w.+-]+\.(?:so|o|a)`?' + end, blank, t)
    t = re.sub(r'\b(?:the|its|their|that) (?:[\w.-]+ ){0,2}?(?:6\.5\.\d+|vpro[- ]patch(?:[- ]\d+)?|410[34]|IP\d\d\w*|media|other|older|newer|sibling)'
               r'(?: [\w.-]+){0,2}? (?:copy|copies|build|builds|slot|entry|entries|routine|version|twin|listing)\b[^.;,:]*', blank, t)
    return t


def abi_of_binary(binary, img):
    if img is not None and img.abi in ('n32', 'n64', 'o32'):
        return img.abi
    return None


def hexval(s):
    return int(s, 16) if s.lower().startswith('0x') else int(s)


def canon(text):
    """objdump no-aliases text to the forms entries use, as a set of spellings."""
    out = {text}
    m = re.match(r'(\S+)\s*(.*)$', text)
    if not m:
        return out
    mn, ops = m.group(1), [o for o in m.group(2).split(',') if o]
    if mn in ('addiu', 'daddiu', 'ori') and len(ops) == 3 and ops[1] == 'zero':
        out.add('li %s,%s' % (ops[0], ops[2]))
        out.add('li')
    if mn in ('or', 'addu', 'daddu') and len(ops) == 3 and ops[2] == 'zero':
        out.add('move %s,%s' % (ops[0], ops[1]))
        out.add('move')
    if mn == 'sll' and ops == ['zero', 'zero', '0x0']:
        out.add('nop')
    if mn == 'beq' and len(ops) == 3 and ops[0] == ops[1] == 'zero':
        out.add('b %s' % ops[2])
        out.add('b')
    if mn in ('beq', 'bne', 'beql', 'bnel') and len(ops) == 3 and ops[1] == 'zero':
        z = {'beq': 'beqz', 'bne': 'bnez', 'beql': 'beqzl', 'bnel': 'bnezl'}[mn]
        out.add('%s %s,%s' % (z, ops[0], ops[2]))
        out.add(z)
    if mn == 'bgezal' and ops and ops[0] == 'zero':
        out.add('bal')
    if mn == 'bgezall' and ops and ops[0] == 'zero':
        out.add('bgezall')
    if mn in ('subu', 'dsubu') and len(ops) == 3 and ops[1] == 'zero':
        out.add('negu' if mn == 'subu' else 'dnegu')
    out.add(mn)
    return out


def insn_match(claim, actual):
    """Whether an instruction quoted in prose names the disassembled one (aliases, abbreviated operands)."""
    n = norm_insn(claim)
    for f in canon(actual):
        f = norm_insn(f)
        if n == f or f.startswith(n + ',') or (' ' not in n and f.split(' ')[0] == n):
            return True
        a, b = n.split(' ', 1) if ' ' in n else (n, ''), f.split(' ', 1) if ' ' in f else (f, '')
        if a[0] == b[0] and a[1] and b[1]:
            ca, cb = a[1].split(','), b[1].split(',')
            if len(cb) == 3 and cb[0] == cb[1] and ca == [cb[0], cb[2]]:
                return True
    return False


def norm_insn(s):
    s = s.strip().strip('`').replace('$', '')
    s = re.sub(r'\s*,\s*', ',', s)
    s = re.sub(r'\s+', ' ', s)
    return s.lower()


def num_tokens(s):
    return [int(x) for x in re.findall(r'(?<![\w.+-])(\d+)(?![\w.])', s)]


class Ctx:
    """What one fact sheet offers, indexed for the checks."""

    def __init__(self, fs, img):
        self.fs, self.img = fs, img
        r = fs['routine']
        self.addr = int(r['address'], 16)
        self.size = r['size']
        self.end = self.addr + self.size
        self.insn_at = {int(a, 16): t for a, t in fs.get('insns', [])}
        self.order = [int(a, 16) for a, t in fs.get('insns', [])]
        self.callees = {c['callee'] for c in fs['calls'] if c.get('callee')}
        self.call_targets = {int(c['target'], 16) for c in fs['calls'] if c.get('target')}
        self.got_by_off = collections.defaultdict(list)
        for g in fs['got_loads']:
            self.got_by_off[g['gp_offset']].append(g)
        self.error_codes = set()
        self.error_unknown = False
        for e in fs['errors']:
            if e.get('code') is not None:
                self.error_codes.add(e['code'] & 0xffffffff)
            elif e.get('codes'):
                self.error_codes |= {c & 0xffffffff for c in e['codes']}
            else:
                self.error_unknown = True
        self.unresolved_calls = any(c['kind'] == 'register' for c in fs['calls'])
        self.numbers = set()
        for x in fs['immediates']:
            v = x['immediate']
            self.numbers |= {v, v & 0xffff, v & 0xffffffff}
            if x['mnemonic'] == 'lui':
                self.numbers |= {(v << 16) & 0xffffffff, facts.sx32(v << 16)}
        if img is not None and img.got is not None:
            ga, gs, local, gotsym, gsz, gd = img.got
            self.numbers |= {ga, local, gotsym, img.gp}
        for x in fs['constants']:
            v = int(x['value'], 16) if not x['value'].startswith('-') else -int(x['value'][1:], 16)
            self.numbers |= {v, v & 0xffffffff, v & 0xffffffffffffffff}
        for x in fs['literals']:
            self.numbers.add(int(x['word'], 16))
            self.numbers.add(int(x['data_address'], 16))
        for a in fs['accesses']:
            self.numbers.add(a['offset'] & 0xffffffff)
            if re.fullmatch(r'-?0x[0-9a-f]+', a['value']):
                v = int(a['value'].lstrip('-'), 16) * (-1 if a['value'].startswith('-') else 1)
                self.numbers |= {v, v & 0xffffffff}
            if 'origin_offset' in a:
                self.numbers.add(a['origin_offset'])
            if 'absolute' in a:
                self.numbers.add(int(a['absolute'], 16))
                self.numbers.add(int(a['absolute'], 16) & 0xffffffff)
        for m in fs['mmio']:
            for c in m.get('constant_part', []) + m.get('physical_constant_part', []):
                self.numbers.add(int(c, 16))
        for a in fs['addresses']:
            self.numbers.add(a['offset'])
        for t in fs['jump_tables']:
            self.numbers.add(int(t['table'], 16))
            self.numbers |= {int(x, 16) for x in t['targets']}
        self.numbers |= set(self.insn_at)
        self.numbers |= self.call_targets
        self.numbers.add(self.end)
        # comparisons through a subtracted base: "addiu rd,rs,-K" then sltiu
        self.bases = [-x['immediate'] for x in fs['immediates'] if x['mnemonic'] in ('addiu', 'daddiu', 'addi')
                      and x['immediate'] < 0]
        self.tbl_bounds = [x['immediate'] for x in fs['immediates'] if x['mnemonic'] == 'sltiu']
        self.offsets_access = collections.defaultdict(list)   # origin offset -> accesses
        self.raw_offsets = collections.defaultdict(list)
        for a in fs['accesses']:
            if a.get('stack'):
                continue
            if 'origin_offset' in a:
                self.offsets_access[a['origin_offset']].append(a)
            self.raw_offsets[a['offset']].append(a)
        for mm in fs['mmio']:
            for cc in mm.get('physical_constant_part', []) + ([mm['physical']] if 'physical' in mm else []):
                self.offsets_access[int(cc, 16) & ((1 << 33) - 1)].append(mm)
                self.offsets_access[int(cc, 16) & 0xffffff].append(mm)
        self.offsets_addr = collections.defaultdict(list)
        for a in fs['addresses']:
            if not a.get('stack'):
                self.offsets_addr[a['offset']].append(a)
        self.abs_loads = collections.defaultdict(list)
        for a in fs['accesses']:
            if 'absolute' in a:
                self.abs_loads[int(a['absolute'], 16) & 0xffffffff].append(a)
        self.frame = r['frame_size']
        self.stack = collections.defaultdict(list)
        for a in fs['accesses']:
            if a.get('stack') and a['base'] == 'sp':
                self.stack[a['offset']].append(a)
        self.likely = [b for b in fs['branches'] if b.get('likely') and b['mnemonic'] not in facts.CALLS]
        self.likely_mn = set()
        # the linking forms (bltzall, bgezall) are branch-likely too, though self.likely leaves calls out
        for b in fs['branches']:
            if b.get('likely'):
                self.likely_mn |= canon(b['text'])
        self.branch_at = {int(b['address'], 16): b for b in fs['branches']}
        self.delay_at = {int(b['delay_address'], 16): b for b in fs['branches'] if b.get('delay_address')}

    def returns(self):
        vals, unknown = set(), False
        for e in self.fs['exits']:
            for p in e['paths'] or [{'v0': e['v0']}]:
                v = p['v0']
                if v.startswith('one of '):
                    for x in v[7:].split(', '):
                        vals.add(int(x, 16) if not x.startswith('-') else -int(x[1:], 16))
                elif re.fullmatch(r'-?0x[0-9a-f]+', v):
                    vals.add(int(v, 16) if not v.startswith('-') else -int(v[1:], 16))
                else:
                    unknown = True
        return vals, unknown

    def args_access(self):
        return self.fs['args']['accessed_through']


# ===================================================================== checks

class Checker:
    def __init__(self, entry, ctx, report, bins, factsrc):
        self.e, self.c, self.report = entry, ctx, report
        self.bins, self.factsrc = bins, factsrc
        text = entry.text if not entry.table else ' '.join(
            v for k, v in entry.table.items() if k not in ('routine', 'binary', 'address', 'size', 'label', 'status',
                                                          'function-table hash', 'words compared'))
        self.text = mask_foreign(text, abi_of_binary(entry.binary, ctx.img))

    def out(self, cls, verdict, claim, fact='', reason=''):
        self.report.append({'entry': self.e.id, 'routine': self.e.name, 'binary': self.e.binary, 'class': cls,
                            'verdict': verdict, 'claim': claim[:300], 'fact': str(fact)[:300], 'reason': reason,
                            'status': self.e.status})

    def mismatch(self, cls, claim, fact, reason):
        self.out(cls, 'mismatch', claim, fact, reason)

    def ok(self, cls, claim, fact=''):
        self.out(cls, 'ok', claim, fact)

    def unchecked(self, cls, claim, reason):
        self.out(cls, 'unchecked', claim, '', reason)

    def run(self):
        for f in (self.address, self.size, self.frame, self.width, self.got, self.callee, self.errors, self.likely,
                  self.delay, self.returns, self.args, self.arglist, self.never, self.store_order, self.store_value, self.arg_offsets, self.callee_at, self.return_omission, self.per_pass, self.immediates,
                  self.offsets, self.stack, self.position, self.insn_address, self.sections, self.clauses):
            try:
                f()
            except Exception as x:  # a checker bug is reported as an unchecked claim, never a pass
                self.unchecked(f.__name__, self.text[:120], 'checker error %s: %s' % (type(x).__name__, x))

    # ---------------------------------------------------------- address and size

    def address(self):
        e, c = self.e, self.c
        if c.fs['routine'].get('name_elsewhere'):
            self.unchecked('address', '0x%x' % e.address, '%s is known only from debug information, at %s' % (
                e.name, ', '.join(c.fs['routine']['name_elsewhere'])))
        elif e.address is not None:
            if e.address == c.addr:
                self.ok('address', '0x%x' % e.address)
            else:
                self.mismatch('address', 'address 0x%x' % e.address, 'symbol %s at 0x%x' % (e.name, c.addr),
                              'the routine is not at the stated address')
        # other routines named with an address: "`name` at 0xA" / "`name` (0xA)" / "name (at 0xA)"
        img = self.c.img
        if img is None:
            return
        for m in re.finditer(r'`?([A-Za-z_][\w.$]*)`?\s*(?:\(at |at |\()(' + HEX + r')\b', self.text):
            nm, a = m.group(1), int(m.group(2), 16)
            syms = [x for x in img.byname.get(nm, []) if x[4]]
            if not syms or nm == e.name and a == e.address:
                continue
            if img.kind != 'object' and img.section_of(a) is None:
                continue    # "__glSetError(0x502)": an argument, not an address
            if all(x[5].startswith('inventory') for x in syms) and img.symbolize(a) is None:
                continue    # a static name known from debug information; another copy may sit at a
            if any(x[0] == a for x in syms):
                self.ok('callee', m.group(0), '0x%x' % a)
            elif any(x[1] and x[0] <= a < x[0] + x[1] for x in syms):
                self.ok('callee', m.group(0), 'an address inside %s' % nm)
            elif a in c.insn_at:
                continue    # an instruction address inside this routine, e.g. "the call to X at 0xA"
            elif any(abs(x[0] - a) < 0x10 for x in syms):
                continue
            elif len(syms) == 1 and img.symbolize(a) is None and not (c.addr <= a < c.end):
                self.mismatch('callee', m.group(0), '%s is at 0x%x' % (nm, syms[0][0]),
                              'the named routine is not at the stated address')

    def size(self):
        e, c = self.e, self.c
        if e.size is not None and c.fs['routine'].get('name_elsewhere'):
            pass
        elif e.size is not None:
            if e.size == c.size:
                self.ok('size', '%d bytes' % e.size)
            elif e.size < c.size and e.size % 4 == 0 and all(
                    c.insn_at.get(x, 'sll zero,zero,0x0') in ('sll zero,zero,0x0', 'nop')
                    for x in range(c.addr + e.size, c.end, 4)):
                self.ok('size', '%d bytes' % e.size, 'the rest is padding')
            elif c.fs['routine'].get('size_source') != 'symbol':
                self.unchecked('size', '%d bytes' % e.size, 'the file gives no size; %d bytes to the next symbol' % c.size)
            else:
                self.mismatch('size', '%d bytes' % e.size, '%d bytes (%s)' % (c.size, c.fs['routine'].get('size_source')),
                              'stated size differs from the routine size')
        for m in re.finditer(r'(' + HEX + r') to (' + HEX + r')', self.text):
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if a == c.addr:
                if b in (c.end, c.end - 4):
                    self.ok('size', m.group(0))
                elif b > c.end and c.fs['routine'].get('size_source') == 'symbol':
                    self.mismatch('size', m.group(0), '0x%x to 0x%x' % (c.addr, c.end), 'range runs past the routine end')
        for m in re.finditer(r'\b(?:[Ss]ame |the |all |)(\d+) words\b', self.text):
            n = int(m.group(1))
            ctxs = self.text[max(0, m.start() - 40):m.end() + 30]
            if re.search(r'\b(of|as|copied|listing|instruction|record|block|table|stack|array)\b', ctxs) and \
                    not re.search(r'[Ss]ame \d+ words', ctxs):
                continue
            if n == c.size // 4:
                self.ok('size', m.group(0))
            elif re.match(r'[Ss]ame ', m.group(0)):
                self.mismatch('size', m.group(0), '%d words' % (c.size // 4), 'word count differs from the routine size')

    WIDTH_WORDS = {'byte': 1, 'halfword': 2, 'half-word': 2, 'word': 4, 'doubleword': 8, 'double-word': 8,
                   'dword': 8}

    def width(self):
        """ "the word at +N", "the doubleword at context +N", "+N (a halfword)": the access width there."""
        c, t = self.c, self.text
        pat = (r'\b(byte|half-?word|(?:double-?)?word|dword)\s+at\s+(?:the\s+)?'
               r'(?:(?:context|record|object|array|leaf|branch|vertex|texture|pointer|block|entry|struct|table|'
               r'structure|argument|first argument|second argument|third argument|state|buffer)\s+)?'
               r'(?:offset\s+)?\+(0x[0-9a-f]+|\d+)\b(?![\w.]*\()')
        for m in re.finditer(pat, t, re.I):
            kind = m.group(1).lower()
            want = self.WIDTH_WORDS.get(kind)
            v = int(m.group(2), 0)
            pre = t[max(0, m.start() - 40):m.start()]
            if re.search(r'\b(?:float|single|double|pair|two|three|four|eight|several|\d+)\s*$', pre) or \
                    re.search(r'\b(no|not|never|without)\b[^.;]{0,25}$', pre):
                continue
            acc = [a for a in c.offsets_access.get(v, []) if 'width' in a and not a.get('stack')]
            if not acc:
                acc = [a for a in c.raw_offsets.get(v, []) if not a.get('stack')]
            if not acc:
                continue    # the offset check reports it
            self._judge_width(m, kind, want, acc, '+%d' % v)
        # absolute process-page words: "the context word at address 4128", "the word at absolute 0x1088",
        # "process-page word 4128", "process doubleword 4128"
        apat = (r'\b(byte|half-?word|(?:double-?)?word|dword)\s+(?:at\s+)?(?:the\s+)?'
                r'(?:absolute\s+(?:address\s+)?|(?:process(?:-page)?\s+)?address\s+|process(?:-page)?\s+(?:word\s+)?)'
                r'(0x[0-9a-f]+|\d+)\b'
                r'|\bprocess(?:-page)?\s+(byte|half-?word|(?:double-?)?word)\s+(0x[0-9a-f]+|\d+)\b')
        for m in re.finditer(apat, t, re.I):
            kind = (m.group(1) or m.group(3)).lower()
            want = self.WIDTH_WORDS.get(kind)
            v = int(m.group(2) or m.group(4), 0)
            if not (0x200 <= v < 0x100000):
                continue
            pre = t[max(0, m.start() - 40):m.start()]
            if re.search(r'\b(no|not|never|without)\b[^.;]{0,25}$', pre):
                continue
            acc = c.abs_loads.get(v, [])
            if acc:
                self._judge_width(m, kind, want, acc, 'absolute 0x%x' % v, absolute=True)

    def _judge_width(self, m, kind, want, acc, where, absolute=False):
        t = self.text
        widths = sorted({a['width'] for a in acc})
        cls = ('width-absolute' if absolute else 'width') if want >= 4 else 'width-narrow'
        # the claim's own clause: between the nearest , ; : ( ) or sentence end on either side
        lo = max([t.rfind(x, 0, m.start()) for x in (',', ';', ':', '(', ')', '. ')] + [-1]) + 1
        his = [i for i in (t.find(x, m.end()) for x in (',', ';', ':', '(', ')', '. ')) if i >= 0]
        clause = t[lo:min(his) if his else len(t)]
        if want in widths or (want == 4 and 8 in widths and re.search(r'64-bit word|8-byte|doubleword', clause)):
            self.ok(cls, m.group(0))
        else:
            a = acc[0]
            self.mismatch(cls, m.group(0), '%s accesses %s with width %s (%s)' % (
                a.get('text', '?').split()[0], where, '/'.join(map(str, widths)), a.get('text', '')),
                'the access there is not a %s' % kind)

    def frame(self):
        for m in re.finditer(r'(?<![\w.])(0x[0-9a-f]+|\d+)-byte (?:stack )?frame(?![- ]?buffer)|frame (?:is|of) (0x[0-9a-f]+|\d+) bytes', self.text):
            n = int(m.group(1) or m.group(2), 0)
            if n == self.c.frame:
                self.ok('frame', m.group(0))
            elif self.c.frame == 0 and not any(i for i in self.c.insn_at.values() if 'sp,sp,-' in i):
                self.unchecked('frame', m.group(0), 'no frame allocation found')
            else:
                self.mismatch('frame', m.group(0), '%d-byte frame' % self.c.frame, 'frame size differs')

    # ---------------------------------------------------------- GOT and callees

    def got(self):
        c = self.c
        t = self.text
        for m in re.finditer(r'\bgp\s*([-+])\s*(\d+)\b', t):
            off = int(m.group(2)) * (-1 if m.group(1) == '-' else 1)
            near = re.split(r'[,;.]| and ', t[m.end():m.end() + 160])[0]
            if re.match(r'\s*(?:plus|minus|with -?\d+ added|\+|-\s*\d)', near):
                self.ok('got', m.group(0), 'slot plus an addend')
                continue
            gl = c.got_by_off.get(off)
            if not gl and any(re.search(r'[ ,]%d\(gp\)' % off, x) for x in c.insn_at.values()):
                self.unchecked('got', m.group(0), 'the load is in code the analysis did not reach')
                continue
            if c.img is not None and c.img.got is None:
                self.unchecked('got', m.group(0), 'this file has no GOT')
                continue
            if not gl:
                # a gp-relative load that is not a GOT slot (.lit4 / .sdata) is fine
                if any(int(a['offset']) == off and a['base'] == 'gp' for a in c.fs['accesses']) or \
                        (c.img is not None and c.img.gp is not None and (c.img.gp + off) in c.numbers):
                    self.ok('got', m.group(0), 'gp-relative load')
                    continue
                if re.search(r'plus|\+\s*-?\d|GOT gp', t[m.start() - 20:m.end() + 12]) or \
                        not (c.addr <= (c.img.gp + off if c.img and c.img.gp else 0) or True):
                    pass
                self.mismatch('got', m.group(0), 'GOT loads at %s' % sorted(c.got_by_off), 'no load from gp%+d in this routine' % off)
                continue
            g = gl[0]
            names = {g.get('name'), g.get('value_symbol')} - {None, ''}
            # a named holder right after the slot: "which holds X", "= X", "(X)", "holds 0xA, the address of X"
            nm = re.match(r'[^.;]{0,80}?(?:holds|hold|is|=|resolves to|names|for|to|\()\s*`?([A-Za-z_][\w$.]*)`?', near)
            hv = re.match(r'[^.;]{0,40}?(?:holds|which holds|value|=)\s*(' + HEX + ')', near)
            if hv:
                v = int(hv.group(1), 16)
                fact = g.get('value') or ''
                if g['kind'] == 'local' and fact and int(fact, 16) != v:
                    self.mismatch('got', m.group(0) + near[:hv.end()], 'slot holds %s' % fact, 'slot value differs')
                    continue
            if nm and nm.group(1) not in ('the', 'a', 'an', 'its', 'which', 'GOT', 'slot', 'local', 'global',
                                          'index', 'entry', 'this', 'that') and nm.group(1) in self._symbols():
                if nm.group(1) in names or self._same_address(nm.group(1), g):
                    self.ok('got', m.group(0) + ' ' + nm.group(1), g.get('name') or g.get('value_symbol'))
                else:
                    self.mismatch('got', m.group(0) + ' ' + nm.group(1), 'slot %d holds %s' % (
                        g['slot'], g.get('name') or g.get('value_symbol') or g.get('value')), 'GOT slot names another routine')
                    continue
            else:
                self.ok('got', m.group(0), g.get('name') or g.get('value_symbol') or g.get('value'))
        for m in re.finditer(r'GOT (?:index|slot|entry) (\d+)|local GOT entry (\d+)|dynamic symbol (?:index )?(\d+)|'
                             r'dynsym (?:index )?(\d+)', t):
            gi, li, di, d2 = [int(x) if x else None for x in m.groups()]
            di = di if di is not None else d2
            ctxs = t[max(0, m.start() - 200):m.end() + 200]
            offs = [int(x) * (-1 if s == '-' else 1) for s, x in re.findall(r'gp\s*([-+])\s*(\d+)', ctxs)]
            gls = [g for o in offs for g in c.got_by_off.get(o, [])] or c.fs['got_loads']
            if not gls:
                self.unchecked('got', m.group(0), 'no GOT load in the routine')
                continue
            hit = None
            for g in gls:
                if li is not None and g.get('local_entry') == li:
                    hit = g
                elif di is not None and g.get('dynsym_index') == di:
                    hit = g
                elif gi is not None and (g['slot'] == gi):
                    hit = g
            if hit:
                self.ok('got', m.group(0))
            elif gi is not None and any(g.get('dynsym_index') == gi for g in gls):
                g = next(g for g in gls if g.get('dynsym_index') == gi)
                self.mismatch('got', m.group(0), 'dynsym %d is GOT slot %d (%s)' % (gi, g['slot'], g.get('formula')),
                              'a dynamic symbol index given as the GOT index')
            elif gi is not None and offs:
                g = gls[0]
                self.mismatch('got', m.group(0), 'slot %d (%s%s)' % (g['slot'], g['kind'],
                              ', local entry %d' % g['local_entry'] if 'local_entry' in g else ', dynsym %s' % g.get('dynsym_index')),
                              'GOT index differs from the slot the gp offset selects')
            else:
                self.unchecked('got', m.group(0), 'index not matched to a load')

    def _symbols(self):
        if not hasattr(self, '_syms'):
            img = self.c.img
            self._syms = (set(img.byname) | set(img.dynsym)) if img is not None else set()
        return self._syms

    def _same_address(self, name, g):
        img = self.c.img
        if img is None or 'value' not in g:
            return False
        v = int(g['value'], 16)
        return any(x[0] == v for x in img.byname.get(name, []))

    def callee(self):
        c, t = self.c, self.text
        syms = self._symbols()
        called = set(c.callees)
        for g in c.fs['got_loads']:
            called |= {g.get('name'), g.get('value_symbol')}
        img = c.img
        for x in list(c.call_targets):
            nm = img.func_name_at(x) if img else None
            if nm:
                called.add(nm)
                called |= {y[2] for y in img.syms if y[0] == x}
        for m in re.finditer(r'\b(?:calls|calling|call to|calls to|tail[- ]jumps? to|jumps to)\s+`([A-Za-z_][\w$.]*)`', t):
            nm = m.group(1)
            pre = t[max(0, m.start() - 100):m.start()]
            if nm == self.e.name:
                continue
            if re.search(r"\b(public|sample|source|N32|64-bit|o32|original|other build|does not|doesn't|no|never|not)\b(?:[^.;]|\.\w)*$", pre):
                continue
            if re.search(r'\b(?:helper|routine|function|stub|which|that)\s+(?:that\s+|which\s+)?$', pre):
                continue    # "a 52-byte helper that calls X": the helper's call
            am = re.match(r'\s*\((?:at )?(' + HEX + r')', t[m.end():m.end() + 16])
            if am and int(am.group(1), 16) in c.call_targets | {int(x.get('target', '0'), 16) for x in c.fs['calls']}:
                self.ok('callee', m.group(0), 'call reaches the stated address')
                continue
            if nm not in syms:
                self.unchecked('callee', m.group(0), '%s is not a symbol of this file' % nm)
                continue
            if nm in called:
                self.ok('callee', m.group(0))
            elif any(d['name'] == nm for d in c.fs.get('unreached_got', [])):
                d = next(d for d in c.fs['unreached_got'] if d['name'] == nm)
                self.mismatch('callee', m.group(0), 'the only load of %s is at %s, in code no path reaches' % (nm, d['address']),
                              'the call is unreachable')
            elif c.unresolved_calls:
                self.unchecked('callee', m.group(0), 'the routine has calls through unresolved registers')
            elif any(re.search(r'\+\d+$', x or '') or not x for x in c.callees | {''} if x != '') and \
                    c.img is not None and all(y[5].startswith('inventory') for y in c.img.byname.get(nm, [])):
                self.unchecked('callee', m.group(0), 'a call goes to an unnamed address; %s is known only from debug information' % nm)
            else:
                self.mismatch('callee', m.group(0), 'callees: %s' % ', '.join(sorted(x for x in called if x)),
                              'the routine does not call or load %s' % nm)
        for m in re.finditer(r'\b(?:does not|never) calls? `?([A-Za-z_][\w$.]*)`?|\bno call to `?([A-Za-z_][\w$.]*)`?', t):
            nm = m.group(1) or m.group(2)
            if re.search(r'\b(public|sample|source|N32|64-bit|o32|other)\b(?:[^.;]|\.\w)*$', t[max(0, m.start() - 60):m.start()]):
                continue
            if nm in syms and nm in c.callees:
                self.mismatch('callee', m.group(0), 'called', 'the routine calls %s' % nm)

    # ---------------------------------------------------------- errors

    def errors(self):
        c, t = self.c, self.text
        stated = set()
        for s in sentences(t):
            if re.search(r'\bpublic\b|\bsample\b|\bsource\b', s) and not re.search(r'\bshipped\b|\bbody (?:gives|reports|raises)\b', s):
                continue
            for m in re.finditer(r'\b(128[0-5])\b|\b(0x50[0-5]|0x8031)\b', s):
                v = int(m.group(1)) if m.group(1) else int(m.group(2), 16)
                ctx = s[max(0, m.start() - 40):m.end() + 40]
                if re.search(r'error|SetError|invalid|operation|enum|value|memory|reports|gives|raises', ctx, re.I):
                    stated.add((v, m.group(0), s))
        indirect = any(re.search(r'(?i)error|invalid', x.get('callee') or '') and 'SetError' not in x.get('callee', '')
                       for x in c.fs['calls'])
        stored = {int(a['value'], 16) & 0xffffffff for a in c.fs['accesses'] if a['kind'] == 'store' and
                  re.fullmatch(r'0x[0-9a-f]+', a['value'])}
        stated = {x for x in stated if x[0] not in stored}
        if indirect:
            for v, tok, s in stated:
                if v not in c.error_codes:
                    self.unchecked('error', tok, 'an error is raised through another routine')
            stated = {x for x in stated if x[0] in c.error_codes}
        if not c.fs['errors'] and not any('SetError' in (x.get('callee') or '') for x in c.fs['calls']):
            for v, tok, s in stated:
                if c.unresolved_calls or c.error_unknown:
                    self.unchecked('error', tok, 'no resolved error call')
                elif re.search(r'SetError|error', s):
                    self.mismatch('error', tok, 'no call to an error routine', 'the routine reports no error')
            return
        for v, tok, s in stated:
            if v in c.error_codes:
                self.ok('error', tok)
            elif c.error_unknown or c.unresolved_calls or c.fs['unreached']:
                self.unchecked('error', tok, 'an error argument is not constant, or part of the routine was not analysed')
            else:
                self.mismatch('error', tok, 'SetError arguments: %s' % sorted(c.error_codes),
                              'stated error code is not an argument of any error call')
        nums = {v for v, _, _ in stated}
        named = set()
        for code, names in GL_ERRORS.items():
            for nm in names:
                for m in re.finditer(r'\b' + re.escape(nm) + r'\b', t, re.I):
                    pre = t[max(0, m.start() - 80):m.start()]
                    s = next((x for x in sentences(t) if m.group(0) in x), '')
                    if re.search(r'\bpublic\b(?:[^.;]|\.\w)*$', pre):
                        continue
                    named.add(code)
                    if code not in c.error_codes and not c.error_unknown and code not in nums and \
                            not re.search(r'\b(public|sample)\b', s):
                        self.mismatch('error', m.group(0), 'SetError arguments: %s' % sorted(c.error_codes),
                                      'named error is not an argument of any error call')
        if c.error_codes and not nums and named:
            self.mismatch('error-name', ', '.join(GL_ERRORS[x][0] for x in sorted(named)),
                          'SetError arguments: %s' % sorted(c.error_codes), 'error given by name without its number')

    # ---------------------------------------------------------- branch-likely and delay slots

    def likely(self):
        c, t = self.c, self.text
        for m in re.finditer(LIKELY_RE, t):
            mn = m.group(1)
            pre = t[max(0, m.start() - 50):m.start()]
            if re.search(r'\b(no|not|never|without|instead of|rather than|public)\b(?:[^.;]|\.\w)*$', pre):
                continue
            if mn in c.likely_mn:
                self.ok('branch-likely', mn)
            else:
                self.mismatch('branch-likely', m.group(0), 'branch-likely: %s' % ', '.join(
                    sorted({b['mnemonic'] for b in c.likely})) or 'none', 'the routine has no %s' % mn)
        for s in sentences(t):
            if not re.search(r'branch[- ]likely', s, re.I):
                continue
            neg = re.search(r'\b(no|not|never|without|none)\b[^.;]{0,40}branch[- ]likely|branch[- ]likely[^.;]{0,20}\b(absent|none)\b', s, re.I)
            if re.search(r'\bpublic\b|\bsample\b', s) and not re.search(r'shipped|body|this build', s):
                continue
            if re.search(r"\b(?:in the|the) (?:N32|64-bit|o32|original|other) (?:build|entry|routine)(?:'s)?\b|\b(?:N32|64-bit|o32):", s) and \
                    not re.search(r'this build', s):
                continue
            n = len(c.likely)
            cnt = re.search(r'\b(one|two|three|four|five|six|\d+) (?:of the )?(?:tests|branches|compares|conditional branches)? ?(?:are|is)? ?branch[- ]likely', s, re.I) or \
                re.search(r'\bthe (one|only) branch[- ]likely', s, re.I)
            if neg:
                if n == 0:
                    self.ok('branch-likely', s[:80])
                elif re.search(r'\bno branch[- ]likely\b|\bnot branch[- ]likely\b', s) and \
                        not re.search(r'\b(the|this|that|its|other|remaining|second|first|loop|test|compare)\b[^.;]{0,30}\bnot branch', s):
                    if re.search(r'\bno branch[- ]likely\b', s):
                        self.mismatch('branch-likely', s[:160], 'branch-likely at %s' % ', '.join(b['address'] for b in c.likely),
                                      'the routine has branch-likely instructions')
                    else:
                        self.unchecked('branch-likely', s[:120], 'negative statement about one branch')
                continue
            if n == 0:
                self.mismatch('branch-likely', s[:160], 'no branch-likely instruction (plain branches only)',
                              'branch-likely claimed but the routine has none')
                continue
            if cnt:
                k = cnt.group(1).lower()
                k = 1 if k in ('one', 'only') else NUMW.get(k, int(k) if k.isdigit() else None)
                if k is not None and k == n:
                    self.ok('branch-likely', cnt.group(0))
                elif k is not None and re.search(r'\bthe (one|only)\b|\bin the routine\b|\bof the routine\b|\bonly\b', s):
                    self.mismatch('branch-likely', cnt.group(0), '%d branch-likely instructions' % n, 'count differs')
                else:
                    self.unchecked('branch-likely', cnt.group(0), 'count of a subset')
            else:
                self.ok('branch-likely', s[:80], '%d present' % n)

    def delay(self):
        c, t = self.c, self.text
        for s in sentences(t):
            low = s.lower()
            # "the branch ... skips the `li`": a non-likely branch never skips its delay slot
            m = re.search(r'skip(?:s|ping)? the `([^`]+)`|`([^`]+)`[^.;]{0,40}(?:is )?skipped', s)
            if m and 'delay' not in low or (m and 'branch' in low):
                ins = norm_insn(m.group(1) or m.group(2))
                mn = ins.split()[0]
                ds = [(a, b) for a, b in c.delay_at.items() if mn in canon(c.insn_at.get(a, ''))]
                if ds:
                    plain = [b for a, b in ds if not b.get('likely')]
                    if plain and len(plain) == len(ds):
                        b = plain[0]
                        self.mismatch('delay-slot', m.group(0), '`%s` sits in the delay slot of %s at %s, which is not '
                                      'branch-likely, so it runs on both paths' % (b['delay_slot'], b['mnemonic'], b['address']),
                                      'a plain branch does not skip its delay slot')
                    else:
                        self.ok('delay-slot', m.group(0))
            # "`insn` in the delay slot (of the X) [at 0xA]"
            for m in re.finditer(r'`([^`]+)`(?: at (' + HEX + r'))?,? (?:is )?in (?:its|the|their) delay slot(?: of (?:the |a |its )?`?([a-z0-9.]+)`?)?(?: at (' + HEX + r'))?', s):
                ins = norm_insn(m.group(1))
                a = int(m.group(2) or m.group(4) or '0', 16) or None
                cand = [(x, b) for x, b in c.delay_at.items() if insn_match(m.group(1), c.insn_at.get(x, ''))]
                if a is not None and c.addr <= a < c.end:
                    if a in c.delay_at and any(x == a for x, _ in cand):
                        self.ok('delay-slot', m.group(0))
                    elif a in c.delay_at:
                        self.mismatch('delay-slot', m.group(0), '0x%x holds %s' % (a, c.insn_at.get(a)), 'other instruction in that delay slot')
                    elif a in c.insn_at:
                        self.mismatch('delay-slot', m.group(0), '0x%x (%s) is not a delay slot' % (a, c.insn_at.get(a)),
                                      'not a delay slot')
                    continue
                if cand:
                    if m.group(3) and not any(m.group(3) in canon(b['text']) for x, b in cand):
                        self.unchecked('delay-slot', m.group(0), 'branch kind not matched')
                    else:
                        self.ok('delay-slot', m.group(0))
                elif ins.split()[0] in ('li', 'move', 'nop', 'lw', 'sw', 'ld', 'sd', 'addiu', 'daddiu', 'or', 'lui',
                                        'mov.s', 'mov.d', 'jr', 'sll', 'lwc1', 'swc1', 'ldc1', 'sdc1', 'sb', 'sh', 'lbu',
                                        'lhu', 'lb', 'lh', 'addu', 'daddu', 'ori', 'andi'):
                    self.mismatch('delay-slot', m.group(0), 'delay slots: %s' % ', '.join(
                        sorted({b['delay_slot'] for b in c.delay_at.values() if b.get('delay_slot')})[:12]),
                        'no delay slot holds that instruction')
            # "runs only when taken" for a delay slot of a plain branch
            m = re.search(r'`([^`]+)`[^.;]{0,60}\b(?:runs?|executes?) only when (?:the|its) branch is taken', s)
            if m:
                ins = norm_insn(m.group(1))
                ds = [b for a, b in c.delay_at.items() if ins in {norm_insn(z) for z in canon(c.insn_at.get(a, ''))}]
                if ds and all(not b.get('likely') for b in ds):
                    self.mismatch('delay-slot', m.group(0), 'delay slot of plain %s at %s' % (ds[0]['mnemonic'], ds[0]['address']),
                                  'a plain branch always runs its delay slot')
                elif ds:
                    self.ok('delay-slot', m.group(0))

    def returns(self):
        c, t = self.c, self.text
        vals, unknown = c.returns()
        if not c.fs['exits']:
            return
        words = {'true': 1, 'false': 0, 'zero': 0, 'one': 1, 'gl_true': 1, 'gl_false': 0, 'null': 0}
        for s in sentences(t):
            if re.search(r'\bpublic\b|\bsample\b|\breal (?:function|routine)\b', s) and \
                    not re.search(r'\bshipped\b|\bthis body\b|\bthe body\b', s):
                continue
            for m in re.finditer(r'\b(?:returns?|result is)\s+(?:the value\s+|a value of\s+)?(-?\d+|0x[0-9a-f]+|TRUE|FALSE|GL_TRUE|GL_FALSE|zero|one|NULL)\b(?![.\d])(?!\s*(?:bytes|words|-byte|-word|elements|entries|of|times|arguments?))', s, re.I):
                tok = m.group(1)
                v = words.get(tok.lower())
                if v is None:
                    v = hexval(tok) if not tok.startswith('-') else -hexval(tok[1:])
                pre = s[max(0, m.start() - 60):m.start()]
                if re.search(r'\b(callee|call|it calls|routine at|which|that)\b(?:[^.;]|\.\w)*$', pre) and 'returns' in m.group(0):
                    continue
                if v in vals:
                    self.ok('return', m.group(0))
                elif unknown:
                    self.unchecked('return', m.group(0), 'a return path has a non-constant value')
                else:
                    self.mismatch('return', m.group(0), 'return values on the paths: %s' % sorted(vals),
                                  'no exit path returns that value')

    # ---------------------------------------------------------- arguments

    def args(self):
        c, t = self.c, self.text
        acc = c.args_access()
        for m in re.finditer(r'\b(first|second|third|fourth|fifth|sixth|seventh|eighth) argument \((?:register )?`?(a\d)`?\)', t):
            k = ORD[m.group(1)]
            want = 'a%d' % (k - 1)
            if m.group(2) == want:
                self.ok('args', m.group(0))
            else:
                self.mismatch('args', m.group(0), 'the %s argument is %s' % (m.group(1), want), 'ordinal and register disagree')
        for m in re.finditer(r'\b(a\d)\b,? (?:is |as )?the (first|second|third|fourth|fifth|sixth|seventh|eighth)\b', t):
            k = ORD[m.group(2)]
            if m.group(1) == 'a%d' % (k - 1):
                self.ok('args', m.group(0))
            else:
                self.mismatch('args', m.group(0), '%s is argument %d' % (m.group(1), int(m.group(1)[1]) + 1), 'ordinal and register disagree')
        for s in sentences(t):
            if re.search(r'\bpublic\b|\bsample\b|\bcaller\b|\bcallee\b|\bpasses\b|\bpassed\b|\bwith the\b', s):
                continue
            for role, kind in (('destination', 'store'), ('source', 'load')):
                for m in re.finditer(r'\b(?:the )?' + role + r'\b(?!:)[^.;,]{0,30}?\b(?:is |in |=)?\s*(?:the )?(?:(first|second|third|fourth) argument|\(?(a[0-7])\)?)\b', s):
                    r = 'a%d' % (ORD[m.group(1)] - 1) if m.group(1) else m.group(2)
                    a = acc.get(r, {})
                    if not a:
                        self.unchecked('args', m.group(0), '%s is not used as a memory base' % r)
                    elif a.get(kind):
                        self.ok('args', m.group(0))
                    else:
                        self.mismatch('args', m.group(0), '%s is only %sed through' % (r, 'stor' if kind == 'load' else 'load'),
                                      'the %s argument is never %sed through' % (role, kind[:-1] + 'e' if kind == 'store' else 'load'))
        # "the word at (process-page word|address|absolute) N" must be read or written
        for m in re.finditer(r'(?:word|doubleword|byte|half(?:word)?) at (?:the )?(?:process[- ]page word |process address |absolute address |address |absolute word |the absolute )(' + HEX + r'|\d+)\b|process[- ]page word (' + HEX + r'|\d+)', t):
            v = hexval(m.group(1) or m.group(2))
            if v < 0x200 or v > 0x100000:
                continue
            pre = t[max(0, m.start() - 80):m.start()]
            if re.search(r'\b(public|N32|64-bit|o32|other build|original)\b(?:[^.;]|\.\w)*$', pre) or \
                    re.search(r'\b(no|never|not|without)\b[^.;]{0,30}$', pre):
                continue
            other = re.findall(r'`([A-Za-z_][\w$.]*)`[^`.;]*$', pre)
            if other and other[-1] != self.e.name:
                continue    # "the stub `glColor3fv` (dispatch word at process address 0x15ec)"
            if v in c.abs_loads:
                self.ok('args', m.group(0))
            else:
                self.mismatch('args', m.group(0), 'absolute accesses: %s' % ', '.join(
                    '0x%x' % x for x in sorted(c.abs_loads) if x < 0x100000) or 'none',
                    'the routine never reads or writes that absolute word')

    # ---------------------------------------------------------- stores

    def store_order(self):
        c, t = self.c, self.text
        stores = [a for a in c.fs['accesses'] if a['kind'] == 'store' and not a.get('stack')]
        for s in sentences(t):
            if re.search(r'\bpublic\b|\bsample\b', s) and not re.search(r'\bshipped\b|\bthis body\b|\bthe body\b|\bbuild\b', s):
                continue
            if not re.search(r'\bstor(?:e|es|ed|ing)\b|\bwrit(?:e|es|ten)\b|\bclears?\b|\bfills?\b', s):
                continue
            if re.search(r'\bascending\b|\bincreasing order\b', s) and not re.search(r'\b(not|never|rather than)\b[^.;]{0,20}(ascending|increasing)', s) \
                    and not re.search(r'\border(?: element| slot)?s? \d+, \d+|\bother build|\bdescending\b', s):
                self._ascending(s, stores)
            # explicit chains: "+A, then +B, then +C" or "+A, +B and +C in that order"
            chain = None
            m = re.search(r'((?:\+(?:0x[0-9a-f]+|\d+)[^.;+]{0,25}?\bthen\b[^.;+]{0,25}?)+\+(?:0x[0-9a-f]+|\d+))', s)
            if m:
                chain = m.group(1)
            if m and re.search(r'\+(?:0x[0-9a-f]+|\d+)(?:,| and)\s*$', s[max(0, m.start() - 12):m.start()]):
                chain = None    # "+0, +20, +40 and +60, then +64": the list is not an issue order
            if not chain:
                continue
            offs = [int(x, 0) for x in re.findall(r'\+(0x[0-9a-f]+|\d+)', chain)]
            if len(offs) < 2 or len(set(offs)) != len(offs):
                continue
            seq = []
            for o in offs:
                hits = [a for a in stores if a.get('origin_offset') == o or a['offset'] == o]
                seq.append(min(int(a['address'], 16) for a in hits) if hits else None)
            if any(x is None for x in seq):
                self.unchecked('store-order', chain, 'offsets not all stored: %s' % offs)
            elif seq == sorted(seq):
                self.ok('store-order', chain)
            else:
                real = [o for _, o in sorted(zip(seq, offs))]
                self.mismatch('store-order', chain, 'issue order %s' % ', '.join('+%d' % o for o in real),
                              'stores are issued in another order')

    def _ascending(self, s, stores):
        c = self.c
        regions = [(int(lp['head'], 16), int(lp['back_branch'], 16) + 4) for lp in c.fs['loops']] or [(c.addr, c.end)]
        bad, good = None, False
        for lo, hi in regions:
            by = collections.defaultdict(list)
            for a in stores:
                if lo <= int(a['address'], 16) <= hi:
                    by[(a['base'], a['width'])].append(a['offset'])
            for b, v in by.items():
                if len(v) >= 3 and len(set(v)) == len(v):
                    if v == sorted(v):
                        good = True
                    elif v != sorted(v, reverse=True) or len(v) >= 3:
                        bad = bad or (b, v)
        if bad:
            self.mismatch('store-order', s[:160], 'stores through %s issue offsets %s' % (bad[0][0], bad[1][:12]),
                          'stores are not in ascending order')
        elif good:
            self.ok('store-order', 'ascending')

    def never(self):
        c, t = self.c, self.text
        nt = c.fs.get('never_taken', [])
        if not nt:
            return
        for m in re.finditer(r'\b(?:is not compared|takes [^.;]{0,40}? without (?:a |any )?compar\w*|(?:name|value|first|count)\S* without (?:a |any )?compar\w*|no compare (?:of|on) the (?:first|peeled))\b', t):
            self.mismatch('never-taken', m.group(0), 'the branch at %s compares a register with itself and is never taken' % nt[0],
                          'the body does compare; the compare can never succeed')
        if not re.search(r'never taken|unreachable|with itself|itself\b|dead code|never runs|cannot be taken|not reached', t):
            self.out('never-taken', 'omission', 'never-taken branch at %s' % ', '.join(nt), 'branches %s are never taken' % ', '.join(nt),
                     'the entry does not mention a branch that can never be taken')

    def arglist(self):
        c, t = self.c, self.text
        acc = c.args_access()
        m = re.search(r'\(arguments?:\s*([^)]*)\)', t)
        if m:
            items = [x.strip() for x in re.split(r',|;', m.group(1)) if x.strip()]
            for k, it in enumerate(items[:8]):
                rm = re.search(r'\b(?:in )?(a[0-7])\b', it)
                r = rm.group(1) if rm else 'a%d' % k
                if rm is None and re.search(r'\b(record|that|the record in)\b', it) and k >= len(items) - 1 and ' in ' in it:
                    continue
                role = 'destination' if re.search(r'\bdestination|\boutput\b|\bresult\b', it) else \
                    'source' if re.search(r'\bsource|\binput\b', it) else None
                if role is None:
                    continue
                a = acc.get(r, {})
                kind = 'store' if role == 'destination' else 'load'
                if not a:
                    self.unchecked('args', it, '%s is not used as a memory base' % r)
                elif a.get(kind):
                    self.ok('args', it)
                else:
                    self.mismatch('args', '%s (argument %d, %s)' % (it, k + 1, r), '%s is only %s through' % (
                        r, 'stored' if kind == 'load' else 'loaded'), 'the %s argument is never %s through' % (role, 'stored' if kind == 'store' else 'loaded'))
        for m in re.finditer(r'\b(?:the )?(record|structure|block|table|descriptor|state)\b(?: \w+)? (?:is |in |as )?the (first|second|third|fourth|fifth|sixth) argument', t):
            r = 'a%d' % (ORD[m.group(2)] - 1)
            if acc.get(r):
                self.ok('args', m.group(0))
            else:
                others = sorted(x for x in acc if x != r)
                if others:
                    self.mismatch('args', m.group(0), '%s is never a memory base; %s %s' % (r, ', '.join(others),
                                  'is' if len(others) == 1 else 'are'), 'the named argument is not used as a pointer')
                else:
                    self.unchecked('args', m.group(0), 'no argument is used as a memory base')

    def store_value(self):
        c, t = self.c, self.text
        stores = [a for a in c.fs['accesses'] if a['kind'] == 'store']
        calls = [x for x in c.fs['calls'] if x.get('callee')]
        for m in re.finditer(r'\bstores? the (?:`([\w$.]+)`|(\w+)) result\b|\bstores? the (?:result|pointer|value) (?:of|from|that) `([\w$.]+)`(?: returns)?', t):
            word = m.group(1) or m.group(2) or m.group(3)
            cands = [x['callee'] for x in calls if x['callee'] == word] or \
                sorted({x['callee'] for x in calls if word.lower() in x['callee'].lower().strip('_').split('_')})
            if len(set(cands)) != 1:
                self.unchecked('store-value', m.group(0), 'callee for "%s" not identified' % word)
                continue
            cal = cands[0]
            if any(a['value'] == 'ret(%s)' % cal for a in stores):
                self.ok('store-value', m.group(0))
                continue
            rets = [a for a in stores if a['value'].startswith('ret(') and not a.get('stack')]
            if rets:
                a = rets[0]
                self.mismatch('store-value', m.group(0), '%s at %s stores %s' % (a['text'], a['address'], a['value']),
                              'the stored value comes from another call (check the delay slots)')
            else:
                self.unchecked('store-value', m.group(0), 'no store of a call result found')

    def arg_offsets(self):
        c, t = self.c, self.text
        for m in re.finditer(r'\b(stor|writ|load|read)\w*\b[^.;]{0,60}?\boffsets? ((?:\d+(?:,? and |, | or )?)+)(?:\s*\([^)]*\))? of (?:its|the) (first|second|third|fourth|fifth|sixth) argument', t):
            verb = 'store' if m.group(1) in ('stor', 'writ') else 'load'
            offs = [int(x) for x in re.findall(r'\d+', m.group(2))]
            r = 'a%d' % (ORD[m.group(3)] - 1)
            acc = [a for a in c.fs['accesses'] if a['kind'] == verb and a.get('origin_offset') in offs]
            via = {a.get('origin') for a in acc}
            if not acc:
                self.unchecked('args', m.group(0), 'no %s at those offsets' % verb)
            elif r in via:
                self.ok('args', m.group(0))
            else:
                self.mismatch('args', m.group(0), 'the %ss at %s go through %s' % (verb, offs, ', '.join(sorted(x or '?' for x in via))),
                              'the accesses are not through the %s argument' % m.group(3))

    def callee_at(self):
        c, t = self.c, self.text
        bycallee = collections.defaultdict(set)
        for x in c.fs['calls']:
            a = int(x['address'], 16)
            bycallee[x['callee']] |= {a, a + 4}
        for g in c.fs['got_loads']:
            for nm in (g.get('name'), g.get('value_symbol')):
                if nm:
                    bycallee[nm].add(int(g['address'], 16))
        for m in re.finditer(r'`([A-Za-z_][\w$.]*)`([^.;`,]{0,22}?)\((?:at |the call at |called at )?(' + HEX + r')\)', t):
            nm, a = m.group(1), int(m.group(3), 16)
            if not (c.addr <= a < c.end) or nm not in bycallee or \
                    re.search(r'\b(GOT|slot|address|holds|table|path|branch|case|block|code|loop|returns?|result)\b', m.group(2)):
                continue
            if a in bycallee[nm]:
                self.ok('insn-address', m.group(0))
            else:
                calls = sorted(int(x['address'], 16) for x in c.fs['calls'] if x['callee'] == nm)
                self.mismatch('insn-address', m.group(0), '0x%x holds %s; the call to %s is at %s' % (
                    a, c.insn_at.get(a), nm, ', '.join('0x%x' % x for x in calls) or '?'),
                    'the stated address is not the call or its GOT load')

    def return_omission(self):
        c, t = self.c, self.text
        vals, unknown = c.returns()
        if unknown or not vals or not c.fs['exits'] or vals == {0} and len(c.fs['exits']) == 1:
            return
        if len(vals) >= 2 and not re.search(r'\breturn|\bresult\b|\bgives\b|\byields\b|TRUE|FALSE', t, re.I):
            self.out('return', 'omission', 'return values %s' % sorted(vals), 'paths return %s' % sorted(vals),
                     'the entry gives no return value, and the exit paths return different constants')

    def per_pass(self):
        c, t = self.c, self.text
        for m in re.finditer(r'(\d+) (?:output |input |source |destination )?bytes? (?:a|per|each) (?:pass|iteration|loop)', t):
            n = int(m.group(1))
            loops = c.fs['loops']
            if not loops:
                self.unchecked('bytes-per-pass', m.group(0), 'no loop found')
                continue
            cand = set()
            for lp in loops:
                cand.add(lp['bytes_stored'])
                cand |= set(lp['bytes_stored_by_base'].values())
                cand |= set(lp['bytes_loaded_by_base'].values())
                cand |= {abs(v) for v in lp['pointer_steps'].values()}
            if n in cand:
                self.ok('bytes-per-pass', m.group(0))
            else:
                self.mismatch('bytes-per-pass', m.group(0), 'per pass: stored %s, pointer steps %s' % (
                    sorted({lp['bytes_stored'] for lp in loops}), sorted({abs(v) for lp in loops for v in lp['pointer_steps'].values()})),
                    'no loop stores, loads or steps that many bytes')

    # ---------------------------------------------------------- numbers and offsets

    def immediates(self):
        c, t = self.c, self.text
        img = c.img
        negs = [(mm.start(), mm.end()) for mm in re.finditer(r'[^.;]*\b(?:no|not|rejects?|other|outside|never|without|lacks?|absent|unlike|instead of|in place of|where the public|public)\b[^.;]*', t)]
        for m in re.finditer(r'(?<![\w+])(0x[0-9a-fA-F]+)\b', t):
            v = int(m.group(1), 16)
            if v in (0, 1) or v == c.addr or v == c.end:
                continue
            if any(a <= m.start() < b for a, b in negs):
                continue
            pre = t[max(0, m.start() - 70):m.start()]
            post = t[m.end():m.end() + 40]
            if re.search(r'\b(public|N32|64-bit|o32|original|other|sibling|IP35|IP30|IP27|build|inventory|table has|in the file)\b(?:[^.;]|\.\w)*$', pre):
                continue
            if re.search(r'^\s*\((?:GL_|`?GL)', post) or re.search(r'\benumerant|\bname\b|\bpname\b|\btarget\b|\bGL_', pre[-30:]):
                pass
            if self._known_number(v):
                self.ok('immediate', m.group(0))
                continue
            if img is not None and (img.section_of(v) or img.func_name_at(v)) and not (c.addr <= v < c.end):
                continue   # an address elsewhere in the file (another routine, a table, a string)
            if 0x10000000 <= v < 0x100000000 and img is not None and img.kind == 'shared-object':
                continue
            if v > 0xffffffff:
                continue
            if c.addr <= v < c.end:
                continue
            cl0 = max(t.rfind(';', 0, m.start()), t.rfind(':', 0, m.start()), t.rfind('. ', 0, m.start()))
            pre2 = t[max(0, m.start() - 28):m.start()]
            clause = t[cl0 + 1:m.start()]
            post2 = t[m.end():m.end() + 8]
            operand = re.search(r'\b(?:ORs?|ANDs?|XORs?|masks?(?: with)?|stores?|writes?|compares?(?: it)? with|tests?(?: it)? against|'
                                r'adds?|subtracts?|li|lui|ori|andi|xori|addiu|immediate|constant)\s+(?:the (?:constant|value|immediate) )?$', pre2)
            if not operand and re.search(r'\b(?:ORs|ANDs|XORs|masks|stores|writes)\b[^,]*\band\s*$', clause):
                operand = True    # "ORs 0x10 into +6080 and 0x00800000 into +6068"
            ranged = re.search(r'\bto\s*$|\.\.\s*$|-\s*$', pre2) or re.match(r'\s*(?:to|\.\.|-)\s*0x', post2)
            sent_start = max(t.rfind('. ', 0, m.start()), t.rfind('; ', 0, m.start()), 0)
            others = [x for x in re.findall(r'`([A-Za-z_][\w$.]*)`', t[sent_start:m.start()]) if x != self.e.name and x in self._symbols()]
            if operand and not ranged and not others:
                self.mismatch('immediate', m.group(0), 'not formed, loaded, compared or addressed by the routine',
                              'the routine has no such constant')
            else:
                self.unchecked('immediate', m.group(0), 'constant not found in the routine (not an operand claim)')

    def _known_number(self, v):
        c = self.c
        if v in c.numbers or (v & 0xffffffff) in c.numbers or -v in c.numbers or (v + 1) in c.numbers or \
                (v - 1) in c.numbers:
            return True
        for b in c.bases:
            if any(0 <= v - b < n for n in c.tbl_bounds) or (b > 0 and v - b in (0,)):
                return True
        for tb in c.fs['jump_tables']:
            for b in c.bases:
                if 0 <= v - b < tb['entries']:
                    return True
        return False

    def offsets(self):
        c, t = self.c, self.text
        for m in re.finditer(r'(?<![\w.])(?:context |record |array |object |leaf |branch |vertex |texture |pointer |block |entry |struct |table )?\+(0x[0-9a-fA-F]+|\d+)\b(?![\w.]*\()', t):
            v = int(m.group(1), 0)
            pre = t[max(0, m.start() - 90):m.start()]
            post = t[m.end():m.end() + 20]
            if re.search(r'\b(public|N32|64-bit|o32|original|other build|sibling|IP35|IP30|IP27|in the N32|N32:)\b(?:[^.;]|\.\w)*$', pre) or \
                    re.search(r'^\s*(?:bytes|\)|in the|on N32)', post) and False:
                continue
            if re.search(r'(N32|64-bit|o32)\s*:?[^.;()]*$', pre[-40:]) or re.search(r'\((?:N32|64-bit|o32)[^)]*$', pre):
                continue
            if v in c.offsets_access or v in c.raw_offsets:
                if v not in c.offsets_access and c.raw_offsets[v] and \
                        all(a.get('origin_offset') not in (None, v) and 'one of' not in a.get('origin', '') and
                            a.get('origin', '?') != '?' and a.get('base_origin', '?') != '?' and
                            not a.get('origin', '').startswith('(') for a in c.raw_offsets[v]) and \
                        re.search(r'\bcontext\b', m.group(0) + pre[-20:]):
                    a = c.raw_offsets[v][0]
                    if re.search(r'\+%d\b|\+0x%x\b' % (a.get('origin_offset', -1), a.get('origin_offset', -1) & 0xffffffff), t):
                        self.ok('offset', m.group(0), 'the entry states the offset from the origin too')
                        continue
                    self.mismatch('offset', m.group(0), '%s reaches %s%+d' % (a['text'], a.get('origin'), a.get('origin_offset')),
                                  'the base register was moved, so the access is not at that offset from the origin')
                else:
                    if re.search(r'\bword at\b[^.;]{0,30}$', pre) and v not in c.offsets_access and v in c.offsets_addr:
                        self.mismatch('addiu-word', m.group(0), c.offsets_addr[v][0]['text'], 'only an address formed with addiu; nothing loads it')
                    else:
                        self.ok('offset', m.group(0))
                continue
            if v in c.offsets_addr:
                if re.search(r'\b(?:word|doubleword|float|byte|value|halfword) at (?:the )?(?:\w+ )?$', pre[-40:]) and \
                        not re.search(r'\baddress\b', pre[-30:]) and c.offsets_addr[v][0]['text'].split()[0] in ('addiu', 'daddiu') \
                        and v not in c.raw_offsets:
                    a = c.offsets_addr[v][0]
                    self.mismatch('addiu-word', m.group(0), '%s forms the address %s' % (a['text'], a['value']),
                                  'an address formed with addiu, not a load of the word there')
                else:
                    self.ok('offset', m.group(0))
                continue
            if any(abs(lp_step) == v for lp in c.fs['loops'] for lp_step in lp['pointer_steps'].values()):
                self.ok('offset', m.group(0))
                continue
            if v in c.numbers:
                self.ok('offset', m.group(0))
                continue
            self.unchecked('offset', m.group(0), 'no access or address at that offset from any base')

    def stack(self):
        c, t = self.c, self.text
        for m in re.finditer(r'\bsp\s*\+\s*(0x[0-9a-f]+|\d+)\b|\b(\d+)\(sp\)', t):
            v = int(m.group(1) or m.group(2), 0)
            pre = t[max(0, m.start() - 80):m.start()]
            post = t[m.end():m.end() + 80]
            if re.search(r'\b(N32|64-bit|o32|public|caller)\b(?:[^.;]|\.\w)*$', pre):
                continue
            acc = c.stack.get(v, [])
            stores = [a for a in acc if a['kind'] == 'store'] or \
                [a for o, aa in c.stack.items() for a in aa if a['kind'] == 'store' and o < v < o + a['width']]
            neg = re.search(r'\b(never|not|no|nothing)\b[^.;]{0,40}$', pre) or re.search(r'^[^.;]{0,40}\b(never|not|does not) (written|stored|set|writes|stores|sets|write|store)', post)
            if neg and re.search(r'\b(stor|writ|set)', pre[-40:] + post[:40]):
                if stores:
                    self.mismatch('stack', m.group(0), stores[0]['text'], 'the slot is stored')
                else:
                    self.ok('stack', m.group(0))
                continue
            if re.search(r'\b(stor|sav|spill|keep|kept|writ|held|holds)\w*\b', pre[-50:] + post[:30]):
                if not stores:
                    if not acc and c.frame:
                        self.mismatch('stack', m.group(0), 'no store to %d(sp)' % v, 'nothing is stored in that slot')
                    elif not acc:
                        self.unchecked('stack', m.group(0), 'slot may be relative to another base')
                    else:
                        self.mismatch('stack', m.group(0), acc[0]['text'], 'the slot is read but never stored')
                    continue
                vals = {a['value'] for a in stores}
                srcs = {a['source'] for a in stores}
                saved = [a for a in stores if a['value'] == a['source'] and a['source'] in CALLEE_SAVED]
                ctx = pre[-60:] + post[:60]
                syn = {'ra': 'return address', 'gp': 'global pointer|gp', 's8': 'frame pointer|s8|fp'}
                words = '|'.join(re.escape(x) for x in srcs) + '|' + '|'.join(syn.get(x, x) for x in srcs)
                if saved and len(saved) == len(stores) and not re.search(r'\b(callee[- ]saved|preserv\w*|caller\'s|' + words + r')\b', ctx):
                    self.mismatch('stack', m.group(0), 'the slot holds the incoming %s (%s)' % (saved[0]['source'], saved[0]['text']),
                                  'the slot saves a callee-saved register, not a computed value')
                else:
                    self.ok('stack', m.group(0), ', '.join(sorted(vals))[:80])

    # ---------------------------------------------------------- instruction positions and addresses

    def position(self):
        c, t = self.c, self.text
        pat = (r'`([^`]+)`\s+(?:is|as)\s+the\s+(first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|'
               r'\d+(?:st|nd|rd|th))\s+(instruction|word)(?:\s+after\s+`([^`]+)`(?:\s+at\s+(' + HEX + r'))?)?')
        for m in re.finditer(pat, t):
            if m.group(1).split()[0].lower() not in MNEMONICS:
                continue
            ins = norm_insn(m.group(1))
            k = ORD.get(m.group(2)) or int(re.match(r'\d+', m.group(2)).group(0))
            after = m.group(4)
            positions = [i for i, a in enumerate(c.order)
                         if ins in {norm_insn(z) for z in canon(c.insn_at[a])}]
            if not positions:
                self.mismatch('position', m.group(0), 'no `%s` in the routine' % ins, 'instruction not found')
                continue
            if after:
                anc = norm_insn(after)
                ap = [i for i, a in enumerate(c.order) if anc in {norm_insn(z) for z in canon(c.insn_at[a])} or
                      norm_insn(c.insn_at[a]).startswith(anc)]
                if m.group(5):
                    ap = [i for i in ap if c.order[i] == int(m.group(5), 16)] or ap
                if not ap:
                    self.unchecked('position', m.group(0), 'anchor `%s` not found' % after)
                    continue
                got = [p - ap[0] for p in positions if p > ap[0]]
                if k in got:
                    self.ok('position', m.group(0))
                else:
                    self.mismatch('position', m.group(0), '`%s` is instruction %s after the anchor (word %d of the routine)'
                                  % (ins, got[0] if got else '?', positions[0] + 1), 'position miscounted')
            else:
                if k - 1 in positions:
                    self.ok('position', m.group(0))
                else:
                    self.mismatch('position', m.group(0), '`%s` is word %d' % (ins, positions[0] + 1), 'position miscounted')

    def insn_address(self):
        c, t = self.c, self.text
        for m in re.finditer(r'`([^`]+)`\s+(?:\(|at |is at )(' + HEX + r')\)?|(' + HEX + r')\s*(?::|holds|is)\s*`([^`]+)`', t):
            ins = m.group(1) or m.group(4)
            a = int(m.group(2) or m.group(3), 16)
            if re.match(r'\s*(?:to|-|\.\.)\s*0x', t[m.end():m.end() + 8]) or re.search(r'` and `[^`]*$', t[max(0, m.start() - 30):m.start() + 1]):
                continue
            if not (c.addr <= a < c.end):
                continue
            if not re.match(r'(?:[a-z][a-z0-9]*(?:\.[a-z0-9]+)*)(?:\s+\$?[a-z0-9]+(?:,|\s*$|\()|\s*$)', ins) or \
                    ins.split()[0] not in MNEMONICS:
                continue    # a symbol, a string or a C expression, not an instruction
            got = c.insn_at.get(a)
            if got is None:
                self.mismatch('insn-address', m.group(0), 'not an instruction start', 'address inside the routine is not an instruction')
                continue
            n = norm_insn(ins)
            forms = {norm_insn(z) for z in canon(got)}
            if n in forms or n.split()[0] in forms or any(f.startswith(n) for f in forms):
                self.ok('insn-address', m.group(0))
            else:
                near = [x for x in (a - 4, a + 4, a - 8, a + 8) if x in c.insn_at and
                        (n in {norm_insn(z) for z in canon(c.insn_at[x])} or n.split()[0] in {norm_insn(z) for z in canon(c.insn_at[x])})]
                self.mismatch('insn-address', m.group(0), '0x%x holds %s%s' % (a, got, (' (the instruction is at 0x%x)' % near[0]) if near else ''),
                              'the stated address holds another instruction')
        # "call at 0xA" / "compare at 0xA" / "store at 0xA"
        for m in re.finditer(r'\b(call|jump|store|load|compare|branch)(?:es|s)? (?:\w+ ){0,2}at (' + HEX + r')\b', t):
            kind, a = m.group(1), int(m.group(2), 16)
            if not (c.addr <= a < c.end) or re.search(r'delay|slot|target|path|block|case', m.group(0)) or \
                    re.match(r'\s*(?:to|-|\.\.)\s*0x', t[m.end():m.end() + 8]):
                continue
            got = c.insn_at.get(a)
            if got is None:
                self.mismatch('insn-address', m.group(0), 'not an instruction start', 'address inside the routine is not an instruction')
                continue
            mn = got.split()[0]
            named = re.match(r'\s*\(`?([a-z][a-z0-9.]*)`?\)', t[m.end():m.end() + 14])
            if named and named.group(1) in MNEMONICS:
                if insn_match(named.group(1), got):
                    self.ok('insn-address', m.group(0) + named.group(0))
                else:
                    self.mismatch('insn-address', m.group(0) + named.group(0), '0x%x holds %s' % (a, got),
                                  'the stated address holds another instruction')
                continue
            seq = [c.insn_at.get(a + 4 * k, '').split(' ')[0] for k in range(1, 4)]
            near_branch = any(facts.is_branch(c.insn_at.get(a + 4 * k, 'x').split(' ')[0]) or
                              c.insn_at.get(a + 4 * k, 'x').startswith(('slt', 'c.')) for k in (-2, -1, 1, 2))
            okk = {'call': mn in facts.CALLS or mn in ('jr', 'j') or (mn in ('lw', 'ld') and ' t9,' in got and
                                                                      any(x in facts.CALLS | {'jr'} for x in seq)),
                   'jump': facts.is_branch(mn),
                   'store': mn in facts.STORES, 'load': mn in facts.LOADS or 'li' in canon(got) or mn == 'lui',
                   'compare': mn.startswith('c.') or mn.startswith('slt') or facts.is_branch(mn) or mn in ('xor', 'subu', 'dsubu', 'xori')
                   or near_branch,
                   'branch': facts.is_branch(mn)}[kind]
            if okk:
                self.ok('insn-address', m.group(0))
            else:
                near = [x for x in (a - 4, a + 4) if x in c.insn_at and (
                    (kind == 'call' and c.insn_at[x].split()[0] in facts.CALLS) or
                    (kind == 'store' and c.insn_at[x].split()[0] in facts.STORES) or
                    (kind == 'load' and c.insn_at[x].split()[0] in facts.LOADS) or
                    (kind in ('compare', 'branch', 'jump') and facts.is_branch(c.insn_at[x].split()[0])))]
                if kind == 'call' and a - 4 in c.insn_at and c.insn_at[a - 4].split()[0] in facts.CALLS:
                    near = [a - 4]
                self.mismatch('insn-address', m.group(0), '0x%x holds %s%s' % (a, got, (' (the %s is at 0x%x)' % (kind, near[0])) if near else ''),
                              'the stated address holds no %s' % kind)

    def sections(self):
        c, t = self.c, self.text
        names = {s['name'] for s in c.fs['sections']}
        for m in re.finditer(r'(?:\b(no|without|lacks?|has no|carries no)\s+(?:an? )?`?(\.[a-z_][\w.]*)`?)|(?:`?(\.[a-z_][\w.]*)`?\s+(?:section\s+)?(?:is\s+)?(absent|missing|present))', t):
            neg = bool(m.group(1)) or m.group(4) in ('absent', 'missing')
            sec = m.group(2) or m.group(3)
            if sec in ('.so', '.o', '.a', '.c', '.h', '.s', '.md'):
                continue
            pre = t[max(0, m.start() - 60):m.start()]
            if re.search(r'\b(N32|64-bit|o32|other|IP35|IP30|IP27|build)\b(?:[^.;]|\.\w)*$', pre):
                continue
            has = sec in names
            if neg == (not has):
                self.ok('section', m.group(0))
            else:
                self.mismatch('section', m.group(0), 'sections: %s' % ' '.join(sorted(names)) if not has else '%s present' % sec,
                              'section claim contradicts the section headers')

    def clauses(self):
        t = self.text
        n = len(re.findall(r'\boccupies \d+ bytes at address', t))
        if n > 1:
            self.mismatch('duplicate', 'occupies ... (x%d)' % n, '', 'the size and address clause is repeated in one entry')


# ===================================================================== driver

def expand_docs(args):
    out = []
    for d in args or DEFAULT_DOCS:
        if os.path.isdir(os.path.join(REPO, d)):
            d = os.path.join(d, '*.md')
        for p in sorted(glob.glob(os.path.join(REPO, d))):
            if os.path.isfile(p) and '/inventory/' not in p:
                out.append(os.path.relpath(p, REPO))
    return out


def hints_of(doc, preamble):
    h = re.findall(r'(IP\d+boot|IP\d+[A-Z]+\d*|builds/[\w.+-]+|6\.5\.\d+-media)', preamble)
    if '6.5.30-media' in ' '.join(h):
        h.append('builds/6.5.30-media')
    return list(dict.fromkeys(h))


def default_binary(preamble, bins):
    paths = PATH_RE.findall(preamble)
    if len(set(paths)) == 1:
        return bins.resolve(paths[0], [])
    return None


_STATE = {}


def check_entry(args):
    e, = args
    rep = []
    if e.file_entry and e.binary:
        return check_file_entry(e)
    if not e.name or not e.binary:
        return rep, ('unresolved', e.id, e.name, e.binary, 'no %s' % ('routine' if not e.name else 'binary'))
    F = _STATE.setdefault('facts', Facts())
    fs, err = F.get(e.binary, e.name, e.address, e.size)
    if fs is None:
        return rep, ('unresolved', e.id, e.name, e.binary, err)
    img = F.image(e.binary)
    ctx = Ctx(fs, img)
    Checker(e, ctx, rep, None, F).run()
    return rep, None


CHIP_DOC = re.compile(r'(?:^|/)chips/[^/]+/README\.md$')


class ChipDoc:
    """A chip page: register tables and prose that name routines of the objects the page cites."""

    def __init__(self, doc, text, bins):
        self.doc, self.bins = doc, bins
        hints = re.findall(r'\b(IP\d\d)\b', text[:3000])
        hints = list(dict.fromkeys(hints)) or ['IP35']
        names = sorted(set(re.findall(r'`([\w.+-]+\.o)`', text)) | set(re.findall(r'\b([\w+-]+\.o)\b', text[:3000])))
        self.binaries = []
        for n in names:
            b = bins.resolve(n, [h + 'boot' for h in hints] + hints)
            if b and b not in self.binaries:
                self.binaries.append(b)
        self.F = _STATE.setdefault('facts', Facts())
        self._where = {}

    def locate(self, name):
        """(binary, symbol) of a routine the page names, trying the accessor prefixes the pages drop."""
        if name in self._where:
            return self._where[name]
        found = None
        for cand in (name, 'pcireg_' + name, 'pcibr_' + name, 'pic_' + name):
            for b in self.binaries:
                img = self.F.image(b)
                if img is not None and any(x[4] for x in img.byname.get(cand, [])):
                    found = (b, cand)
                    break
            if found:
                break
        self._where[name] = found
        return found

    def sheet(self, name):
        loc = self.locate(name)
        if not loc:
            return None, None
        fs, err = self.F.get(loc[0], loc[1], None)
        return loc, fs

    @staticmethod
    def reached(fs):
        """{offset: [(width, kind)]} of the register offsets a routine reaches: instruction offsets, offsets from
        a base's origin, and the low 33 bits of constant (window) addresses."""
        out = collections.defaultdict(list)
        for a in fs['accesses']:
            if a.get('stack'):
                continue
            k = (a['width'], a['kind'])
            out[a['offset']].append(k)
            if 'origin_offset' in a:
                out[a['origin_offset']].append(k)
            if 'absolute' in a:
                out[int(a['absolute'], 16) & ((1 << 33) - 1)].append(k)
        for m in fs['mmio']:
            k = (m['width'], m['kind'], 'window')
            for c in m.get('physical_constant_part', []) + ([m['physical']] if 'physical' in m else []):
                out[int(c, 16) & ((1 << 33) - 1)].append(k)
                out[int(c, 16) & 0xffffff].append(k)
        return out

    def check_row(self, e, rep):
        row = e.table
        reg = row.get('register', '')
        m = re.fullmatch(r'`?\+(0x[0-9a-f]+)`?', reg.strip())
        if not m:
            return
        off = int(m.group(1), 16)
        widths = {int(x) for x in re.findall(r'\d+', row.get('widths', ''))}
        access = row.get('access', '').strip()
        accs = re.findall(r'`([A-Za-z_][\w$.]*)`', row.get('accessors and callers (names from the binary)', ''))
        base = {'entry': e.id, 'binary': None, 'class': 'register', 'status': ''}
        kinds = set()
        for nm in accs:
            r = dict(base, routine=nm, claim='%s reaches +0x%x' % (nm, off))
            if re.match(r'(?:prom|sub)_[0-9a-f]+$', nm):
                rep.append(dict(r, verdict='unchecked', fact='', reason='a pseudo-function name with no symbol'))
                continue
            loc, fs = self.sheet(nm)
            if fs is None:
                rep.append(dict(r, verdict='unchecked', fact='', reason='not a routine of the objects the page cites'))
                continue
            r['binary'] = loc[0]
            hit = self.reached(fs).get(off) or self.reached(fs).get(off & 0xffffff)
            if hit:
                kinds |= {h[1] for h in hit if len(h) > 2}
                if widths and not any(h[0] in widths for h in hit):
                    rep.append(dict(r, verdict='mismatch', fact='widths at +0x%x: %s' % (off, sorted({h[0] for h in hit})),
                                    reason='no access of a stated width'))
                else:
                    rep.append(dict(r, verdict='ok', fact='', reason=''))
            elif any(c['kind'] == 'register' for c in fs['calls']) or fs['unreached'] or \
                    any(not c.get('callee') or c['callee'].startswith('.') for c in fs['calls']):
                rep.append(dict(r, verdict='unchecked', fact='', reason='offset not found; the routine has unresolved calls or unreached code'))
            else:
                near = sorted(k for k in self.reached(fs) if isinstance(k, int) and abs(k - off) <= 0x40)[:6]
                if any(c.get('callee') for c in fs['calls']):
                    rep.append(dict(r, verdict='unchecked', fact='offsets near: %s' % ', '.join('+0x%x' % x for x in near),
                                    reason='offset not reached in this routine itself (it may be a caller of the accessor)'))
                else:
                    rep.append(dict(r, verdict='mismatch', fact='offsets near: %s' % ', '.join('+0x%x' % x for x in near),
                                    reason='the routine makes no access at that offset and calls nothing'))
        if access and kinds:
            want = {'r': {'load'}, 'w': {'store'}, 'rw': {'load', 'store'}}.get(access)
            if want and not kinds <= want:
                rep.append(dict(base, routine=', '.join(accs[:3]), verdict='mismatch', claim='access %s at +0x%x' % (access, off),
                                fact='the named routines %s' % ' and '.join(sorted({'load': 'read', 'store': 'write'}[k] for k in kinds)),
                                reason='access column misses a kind the routines perform'))

    def prose(self, e, rep):
        """Each routine named in a bullet gets the sentences that open with it (and their continuations)."""
        names = []
        for nm in re.findall(r'`([A-Za-z_][\w$.]*)`', e.text):
            if nm not in names and self.locate(nm):
                names.append(nm)
        if not names:
            return
        sents = sentences(e.text)
        for nm in names:
            keep, on = [], False
            for snt in sents:
                pos = sorted((snt.find('`%s`' % x), x) for x in names if '`%s`' % x in snt)
                if pos and pos[0][1] == nm and pos[0][0] <= 2:
                    keep.append(snt)
                    on = True
                elif pos or not re.match(r'\s*(?:It|Its|This routine|The routine)\b', snt):
                    on = False
                elif on:
                    keep.append(snt)
            if not keep:
                continue
            loc, fs = self.sheet(nm)
            if fs is None:
                continue
            sub = Entry(e.doc, e.line, ' '.join(keep), e.heading)
            sub.name, sub.binary, sub.status = loc[1], loc[0], 'chips'
            Checker(sub, Ctx(fs, self.F.image(loc[0])), rep, None, self.F).run()


def check_chip_doc(doc, text, bins, only=None):
    cd = ChipDoc(doc, text, bins)
    entries, pre = read_entries(doc, text)
    rep = []
    cd.count = 0
    for e in entries:
        cd.count += 1
        if e.table and 'register' in e.table:
            if only is None or any(x in e.text for x in only):
                cd.check_row(e, rep)
        elif not e.table:
            if only is None or any(x in e.text for x in only):
                cd.prose(e, rep)
    return rep, cd


SUB_RE = re.compile(r'`([A-Za-z_][\w$.]*)` at (' + HEX + r') \((\d+) bytes\)')


def sub_entries(e):
    """Routines a file entry describes inline: "`name` at 0xA (N bytes)". Each gets the sentences that
    name it, and the sentences after one of those up to the next that names another such routine."""
    ms = list(SUB_RE.finditer(e.text))
    names = {m.group(1) for m in ms}
    sents = sentences(e.text)
    out = []
    for m in ms:
        nm = m.group(1)
        keep, on = [], False
        for snt in sents:
            pos = sorted((snt.find('`%s`' % x), x) for x in names if '`%s`' % x in snt)
            named = {x for _, x in pos}
            if pos and pos[0][1] == nm and pos[0][0] < 12:
                keep.append(snt)
                on = True
            elif named or not re.match(r'\s*(?:It|Its|This routine|The routine|The body)\b', snt):
                on = False
            elif on:
                keep.append(snt)
        sub = Entry(e.doc, e.line, ' '.join(keep), e.heading)
        sub.name, sub.address, sub.size, sub.binary, sub.status = nm, int(m.group(2), 16), int(m.group(3)), \
            e.binary, e.status
        sub.sub_of = e.id
        out.append(sub)
    return out


def check_file_entry(e):
    rep = []
    subs = sub_entries(e)
    if not subs:
        return rep, ('unresolved', e.id, None, e.binary, 'file entry names no routine with an address and size')
    F = _STATE.setdefault('facts', Facts())
    for sub in subs:
        if ONLY and sub.name not in ONLY:
            continue
        fs, err = F.get(sub.binary, sub.name, sub.address, sub.size)
        if fs is None:
            rep.append({'entry': e.id, 'routine': sub.name, 'binary': e.binary, 'class': 'address', 'verdict': 'unchecked',
                        'claim': sub.name, 'fact': '', 'reason': err or 'no fact sheet', 'status': e.status})
            continue
        Checker(sub, Ctx(fs, F.image(sub.binary)), rep, None, F).run()
    return rep, None


ONLY = set()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('docs', nargs='*', help='documents (globs relative to the repository root)')
    ap.add_argument('--status', default='established', help='established (default), inferred, unverified or all')
    ap.add_argument('--routine', action='append', help='only entries for this routine (repeatable)')
    ap.add_argument('--line', type=int, action='append', help='only the entry starting at this line')
    ap.add_argument('--json', help='write every result (ok, mismatch, unchecked) here')
    ap.add_argument('--blocking', action='store_true', help='exit 1 on a mismatch in a blocking class')
    ap.add_argument('--jobs', type=int, default=1)
    ap.add_argument('--quiet', action='store_true', help='print only mismatches and the summary')
    ap.add_argument('--text-from', help='read the documents from this directory instead (same relative paths)')
    ap.add_argument('--changed', metavar='REV', help='only entries whose lines differ from REV (git diff)')
    a = ap.parse_args(argv)
    bins = Binaries()
    work = []
    dups = []
    changed = changed_lines(a.changed) if a.changed else None
    chip_results, chip_entries = [], 0
    for doc in expand_docs(a.docs):
        src = os.path.join(a.text_from, doc) if a.text_from else os.path.join(REPO, doc)
        text = open(src, encoding='utf-8').read()
        if CHIP_DOC.search(doc):
            r, cd = check_chip_doc(doc, text, bins, a.routine)
            chip_results += r
            chip_entries += cd.count
            continue
        entries, pre = read_entries(doc, text)
        hints = hints_of(doc, pre)
        dflt = default_binary(pre, bins)
        seen = collections.defaultdict(list)
        for e in entries:
            identify(e, bins, hints, dflt)
            if e.name and e.binary and e.address is not None:
                seen[(e.binary, e.address, e.name)].append(e)
            st = (e.status or '').lower().strip('*. ')
            if a.status != 'all' and st != a.status:
                continue
            if a.routine and e.name not in a.routine and not (e.file_entry and any(
                    x.name in a.routine for x in sub_entries(e))):
                continue
            if a.line and e.line not in a.line:
                continue
            if changed is not None and not touched(changed, e):
                continue
            work.append(e)
        for k, es in seen.items():
            if len(es) > 1 and (changed is None or any(touched(changed, x) for x in es)):
                for e in es:
                    if a.routine and e.name not in a.routine:
                        continue
                    dups.append({'entry': e.id, 'routine': e.name, 'binary': e.binary, 'class': 'duplicate',
                                 'verdict': 'mismatch', 'claim': '0x%x' % e.address,
                                 'fact': 'also at ' + ', '.join(x.id for x in es if x is not e),
                                 'reason': 'two entries for the same routine and address in one document',
                                 'status': e.status})
    ONLY.update(a.routine or ())
    results, unresolved = list(dups) + chip_results, []
    if a.jobs > 1:
        with multiprocessing.Pool(a.jobs) as pool:
            outs = pool.map(check_entry, [(e,) for e in work], chunksize=8)
    else:
        outs = [check_entry((e,)) for e in work]
    for rep, un in outs:
        results += rep
        if un:
            unresolved.append(un)
    mism = [r for r in results if r['verdict'] == 'mismatch']
    unchk = [r for r in results if r['verdict'] == 'unchecked']
    omit = [r for r in results if r['verdict'] == 'omission']
    for r in mism:
        print('MISMATCH\t%s\t%s\t%s\t%s\tclaim: %s\tfact: %s\t%s' % (r['class'], r['entry'], r['routine'], r['binary'],
                                                                  r['claim'], r['fact'], r['reason']))
    if not a.quiet:
        for r in unchk:
            print('UNCHECKED\t%s\t%s\t%s\tclaim: %s\t%s' % (r['class'], r['entry'], r['routine'], r['claim'], r['reason']))
        for r in omit:
            print('OMISSION\t%s\t%s\t%s\tclaim: %s\t%s' % (r['class'], r['entry'], r['routine'], r['claim'], r['reason']))
        for u in unresolved:
            print('UNRESOLVED\t%s\t%s\t%s\t%s' % (u[1], u[2], u[3], u[4]))
    by = collections.Counter((r['class'], r['verdict']) for r in results)
    classes = sorted({r['class'] for r in results})
    print('summary: %d entries checked, %d unresolved; %d mismatches, %d unchecked claims, %d claims held' % (
        len(work) - len(unresolved) + chip_entries, len(unresolved), len(mism), len(unchk), by_total(by, 'ok')))
    for cl in classes:
        print('  %-15s ok %5d  mismatch %4d  unchecked %4d  omission %4d%s' % (
            cl, by[(cl, 'ok')], by[(cl, 'mismatch')], by[(cl, 'unchecked')], by[(cl, 'omission')],
            '  (blocking)' if cl in BLOCKING else ''))
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump({'results': results, 'unresolved': unresolved}, f, indent=1, sort_keys=True)
    if a.blocking and any(r['class'] in BLOCKING for r in mism):
        return 1
    return 0


def changed_lines(rev):
    """{doc: set of line numbers} that differ from rev in the working tree."""
    import subprocess
    out = subprocess.run(['git', '-C', REPO, 'diff', '-U0', rev, '--', 'docs'], capture_output=True, text=True).stdout
    res, doc = collections.defaultdict(set), None
    for ln in out.split('\n'):
        if ln.startswith('+++ '):
            doc = ln[6:] if ln.startswith('+++ b/') else None
        m = re.match(r'@@ -\S+ \+(\d+)(?:,(\d+))? @@', ln)
        if m and doc:
            start, n = int(m.group(1)), int(m.group(2) or 1)
            res[doc] |= set(range(start, start + max(n, 1)))
    return res


def touched(changed, e):
    lines = changed.get(e.doc, ())
    return any(x in lines for x in range(e.line, max(e.last, e.line) + 1))


def by_total(by, verdict):
    return sum(v for (c, vv), v in by.items() if vv == verdict)


if __name__ == '__main__':
    sys.exit(main())
