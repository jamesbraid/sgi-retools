#!/usr/bin/env python3
"""Measure what the workspace has covered, from the binaries.

Usage: scripts/inventory.py [--config scripts/inventory-config.json]
                            [--out docs/inventory] [--no-coverage] [--jobs N]

Run it from the repository root with root/ populated (IRIX_FILES.md), inside
the toolchain environment of AGENTS.md (MIPS objdump, dwarfdump, pyelftools).

The script is the same in every workspace. Everything that belongs to one
graphics family -- which files are in scope and what role each plays, the
register windows and how code reaches them, where command tokens come from,
which kernel tables dispatch ioctls, the microcode images and any register
tables from a specification -- is in scripts/inventory-config.json.

It writes eight tables to docs/inventory/ and rewrites the block between the
inventory markers in docs/coverage.md:

  binaries.tsv        every file in scope, one row per distinct content
  functions.tsv       one row per (binary, function symbol)
  mmio.tsv            one row per register offset the code reaches
  tokens.tsv          command tokens and constant words sent to the hardware
  ioctls.tsv          one row per ioctl number handled or sent
  ucode.tsv           microcode routines, labels and dispatch entries
  spec-registers.tsv  registers listed by a specification or register table
  summary.tsv         row counts per status, and unresolved access sites

docs/inventory/README.md defines every column and status. The output is
deterministic: the same inputs give byte-identical tables.
"""
import argparse
import bisect
import collections
import difflib
import fnmatch
import glob
import hashlib
import io
import json
import multiprocessing
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile

# Child tools and every sort must not depend on the caller's locale: text is read and written as UTF-8
# explicitly, and the tools run under the C locale.
os.environ['LC_ALL'] = os.environ['LANG'] = 'C'
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'scripts'))

STATUSES = ('undocumented', 'named-only', 'located', 'understood', 'no-software-dependency')
RANK = {'understood': 4, 'no-software-dependency': 3, 'located': 2, 'named-only': 1, 'undocumented': 0}
NSD_PHRASE = re.compile(r'no\s+shipped\s+software\s+or\s+published\s+source', re.I)
NSD_ROUTES = re.compile(r'\b(?:routes?|tried)\b', re.I)
MAX_ITEMS = 3          # a line naming more items than this documents none of them
MIN_ROLE_WORDS = 6     # plain words an entry needs to state a role and a hardware effect
TEMPLATE_CAP = 5       # entries that contain one sentence skeleton: more than this and that sentence earns nothing
MIN_DATA = 2           # items an entry states about its subject: numbers or code names, citation included
MARK_BEGIN, MARK_END = '<!-- inventory:begin -->', '<!-- inventory:end -->'
OLD_MARKS = (re.compile(r'<!-- inventory:start[^>]*-->'),)

COLUMNS = {
    'binaries': ['binary', 'group', 'role', 'kind', 'abi', 'bytes', 'sha256', 'copies', 'functions',
                 'address_source', 'access_sites', 'unresolved_sites', 'status', 'doc', 'section'],
    'functions': ['binary', 'role', 'abi', 'elf_section', 'address', 'size', 'name', 'source', 'code_sha',
                  'rejected', 'scope', 'status', 'doc', 'section'],
    'mmio': ['window', 'offset', 'name', 'access', 'sites', 'binaries', 'functions', 'evidence', 'example',
             'status', 'doc', 'section'],
    'tokens': ['kind', 'value', 'name', 'register', 'detail', 'sources', 'sites', 'binaries', 'example',
               'status', 'doc', 'section'],
    'ioctls': ['number', 'hex', 'table', 'handler', 'evidence', 'senders', 'binaries', 'example',
               'status', 'doc', 'section'],
    'ucode': ['program', 'kind', 'address', 'name', 'detail', 'status', 'doc', 'section'],
    'spec-registers': ['spec', 'table', 'page', 'window', 'offset', 'name', 'count', 'stride', 'width', 'rw',
                       'reached_in_code', 'status', 'doc', 'section'],
    'summary': ['table', 'rows', 'out_of_scope', 'understood', 'understood_with_open', 'understood_distinct', 'templated', 'located', 'named_only',
                'undocumented', 'no_software_dependency', 'pct_understood', 'pct_located_or_better',
                'pct_mentioned', 'pct_done', 'unresolved_sites', 'truncated', 'audited_real_pct',
                'audited_sample', 'audited_date', 'computes', 'reused', 'multi_unit', 'shared_address', 'input'],
}
TABLES = ('binaries', 'functions', 'mmio', 'tokens', 'ioctls', 'ucode', 'spec-registers')


def num(s):
    if isinstance(s, int):
        return s
    s = str(s).strip()
    neg = s.startswith('-')
    s = s.lstrip('-')
    v = int(s, 16) if s.lower().startswith('0x') else int(s)
    return -v if neg else v


def s64(v):
    v &= (1 << 64) - 1
    return v - (1 << 64) if v >> 63 else v


def s32(v):
    v &= 0xffffffff
    return v - (1 << 32) if v >> 31 else v


def globs_match(path, pats):
    return any(fnmatch.fnmatch(path, p) for p in pats)


def toolchain_objdump():
    import toolchain
    return toolchain.objdump()


# ===================================================================== docs

def slug(h):
    h = re.sub(r'[`*_]', lambda m: '_' if m.group(0) == '_' else '', h.strip().lower())
    h = re.sub(r'[^\w\s-]', '', h)
    return re.sub(r'\s', '-', h)


IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_$.]*[A-Za-z0-9_$]|[A-Za-z_]')
CODELIKE = re.compile(r'(?=.*[_0-9])|(?=.*[a-z][A-Z])')
HEXLIT = re.compile(r'(\+?)\b0[xX]([0-9a-fA-F]+)\b')
DECLIT = re.compile(r'(?<![\w.+-])(\d{1,10})(?![\w.])')
FILELIKE = re.compile(r'[A-Za-z0-9_+@-]+(?:\.[A-Za-z0-9_+@-]+)+')
WORD = re.compile(r'\b[A-Za-z]{2,}\b')


def plain_list(text):
    text = re.sub(r'`[^`]*`', ' ', text)
    text = re.sub(r'\]\([^)]*\)', ' ', text)
    text = re.sub(r'0[xX][0-9a-fA-F]+|\b\w*[_0-9]\w*\b|\b\w+[a-z][A-Z]\w*\b', ' ', text)
    return WORD.findall(text)


def plain_words(text):
    return len(plain_list(text))


def name_parts(subj):
    """The lower-case words an item's identifiers are made of: split at underscores, digits and case."""
    parts = set()
    for k in subj:
        if k[0] == 'id':
            for p in re.findall(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+', k[1]):
                if len(p) >= 2:
                    parts.add(p.lower())
    return parts


def from_name(word, parts):
    """True when a word of prose is one of the identifier's own words, an inflection of it, or the
    word an abbreviation in it stands for (exp, exponential): restating the name says nothing."""
    w = word.lower()
    for p in parts:
        if w == p or (len(p) >= 3 and w.startswith(p)) or (len(w) >= 4 and p.startswith(w)):
            return True
    return False


def role_words(text, subj):
    """The plain words of an entry that do not come from its subject's name or its label."""
    parts = name_parts(subj)
    return [w for w in plain_list(text)
            if not LABEL.fullmatch(w) and not from_name(w, parts)]


LABEL = re.compile(r'\b(?:established|inferred)\b', re.I)
UNKNOWN = re.compile(r'\bunknown\b', re.I)
# A sentence that says "unknown" about the entry's role or effect leaves nothing to understand; one that
# says it about a sub-fact (which unit serves which source, the width of one field) does not.
ROLE_UNKNOWN = re.compile(r'\b(?:role|effect|purpose|function|behaviou?r|meaning|semantics)\b|'
                          r'\bwhat\b[^.;]{0,40}\b(?:does|do|is\s+for|are\s+for|means|computes)\b|\bused\s+for\b', re.I)
# An entry "computes" when it names the routine's inputs and outputs and describes an operation on data:
# arithmetic, conversion, packing or a decision. The input and output words alone say nothing about what the
# routine does, so the credit keys on the operation: the words below, read in the description and not in a
# sentence that only restates inputs and outputs. A routine that only moves words (a copy, store, load or
# dispatch) earns it only when it also describes two different operations of its own.
COMPUTES_IN = re.compile(r'\b(?:inputs?|operands?|arguments?|takes|consumes)\b', re.I)
COMPUTES_OUT = re.compile(r'\b(?:outputs?|results?|returns|produces|yields)\b', re.I)
COMPUTES_OP = re.compile(r'\b(?:computes?|calculates?|evaluates?|converts?|converted|multipl(?:ies|y|ied)|'
                         r'divides?|divided|subtracts?|subtracted|clamps?|clamped|normali[sz](?:es?|ed)|'
                         r'interpolates?|rounds?|rounded|scales?|scaled|packs?|packed|unpacks?|unpacked|shifts?|'
                         r'combines?|compares?|compared|derives?|accumulates?|negates?|sums?|squares?|truncates?|'
                         r'reciprocals?|transforms?|adds)\b(?!\s+(?:of|at)\b)', re.I)
# "does no arithmetic", "nothing converts": the entry says it performs no operation
COMPUTES_NEG = re.compile(r'\b(?:does|performs|with|without|has)\s+(?:no|any)\s+(?:arithmetic|computation|conversion)\b|'
                          r'\bnothing\s+(?:converts|is\s+computed)\b', re.I)
# an entry that opens by saying the routine moves words
COMPUTES_MOVE = re.compile(r'^\W*(?:an?\s+)?(?:[\w-]+\s+)?(?:copies|copy|moves?|stores?|loads?|forwards?|'
                           r'dispatch\w*|clears?|fills?|writes?|reads?|passes|sets?|zeroes|splits|sends?|latches?)\b',
                           re.I)
# A hedge says the role was not derived from the item itself, so it demotes the entry as "unknown" does.
HEDGE = re.compile(
    r"\bnot\s+(?:yet\s+)?(?:derived|shown|determined|known|established|decoded|identified|verified|"
    r"confirmed|explained|understood)\b|\bnever\s+(?:decoded|derived)\b|"
    r"\bguess(?:ed|es|work)?\b|\bpresum(?:ably|ed|es|ing)\b|\bspeculat\w*|\bassum(?:ed|ing)\b|"
    r"\bnamed\s+(?:for|after)\b|\bfrom\s+(?:its|the|their)\s+(?:names?|labels?)\b|\bname[- ]only\b|"
    r"\bname-derived\b|\bun(?:determined|identified|confirmed|verified|clear)\b", re.I)
# What a citation must name to tie an entry to its own item: an offset, an address, a callee or
# caller, or a source file. A release or a binary name is shared by every item of the build.
CITE_OFFSET = re.compile(r'\+0[xX]([0-9a-fA-F]+)|\b(?:[Oo]ffsets?|[Aa]ddress(?:es)?|[Aa]ddr|[Aa]t|[Ee]ntry|[Rr]ecord)\s*[:=]?\s*'
                         r'0[xX]([0-9a-fA-F]+)|@\s*0[xX]([0-9a-fA-F]+)')
# A call word, then every routine written in code in the list that follows it ("calls `a`, `b` and `c`").
# Each name of the list is a callee or caller citation, and none counts against the items on the line.
CALL_LIST = re.compile(r'\b(?:calls?|callees?|callers?|calling|called\s+(?:from|by)|reached\s+from)\b[^.|;`]{0,30}'
                       r'((?:`[^`]+`)(?:\s*(?:,|;|/|\band\b|\bor\b)\s*(?:and\s+|or\s+)?`[^`]+`)*)', re.I)
# A path written in an entry: at least two slashes, or one slash and a file extension. Its directory
# names are where the file is, not items the entry states.
PATHLIKE = re.compile(r'(?<![\w/.+@$-])(?:[\w.+@$-]+/){2,}[\w.+@$-]+(?:\([\w.+@$-]+\))?|'
                      r'(?<![\w/.+@$-])[\w.+@$-]+/[\w+@$-]+\.[\w+@$-]+')
# The words a derivation by body reading uses, and those of an identification by matching alone
# (the same name, size or number of calls as a public routine).
BODY_READ = re.compile(r'\bread\s+(?:in\s+full|end[- ]to[- ]end|against|from\s+(?:the|that|this)\s+(?:body|build)|'
                       r'the\s+(?:whole|full|entire)\s+(?:body|routine))|\b(?:whole|entire)\s+body\b', re.I)
MATCH_ONLY = re.compile(r'\bmatched\b[^.;|]{0,60}\b(?:names?|sizes?|calls?)\b|\bsame\s+number\s+of\s+calls\b|'
                        r'\b(?:comparable|similar)\s+size\b|\bis\s+the\s+specification\s+this\s+routine\s+is\s+'
                        r'generated\s+from\b', re.I)
# What a match cannot supply: a datum read from this build. An offset, an immediate value, or the address
# of a callee. The routine's own address and size are the row's identity, not such a datum.
_HEXN = r'0[xX][0-9a-fA-F]+'
BUILD_DATUM = re.compile(
    r'\+' + _HEXN + r'|\boffsets?\s+(?:of\s+)?`?(?:' + _HEXN + r'|\d+)|'
    r'\b(?:immediates?|constants?|literals?|opcodes?|masks?|values?)\s+(?:of\s+)?`?(?:' + _HEXN + r'|-?\d+(?:\.\d+)?)|'
    r'\b(?:calls?|calling|callees?|jumps?\s+to)\b(?:(?!\bbuilds?\b)[^.;|]){0,80}?\b(?:at|address)\s+(?:address\s+)?' + _HEXN,
    re.I)
# The sentence of an entry that says how it was derived, as opposed to what the item does.
EVIDENCE = re.compile(r'\bread\s+(?:in\s+full|against|from|end)\b|\bmatched\b|\bholds\s+the\s+same\b|'
                      r'\bsame\s+number\s+of\s+calls\b|\b(?:compared|checked|derived)\s+(?:with|against|from)\b|'
                      r'\bgenerated\s+from\b|\bdisassembl(?:y|ed)\b', re.I)
SIMILAR = 0.9          # role texts at least this alike are the same text, for the cross-workspace check
CITE_PATH = re.compile(r'\b[\w.+@-]+/[\w.+@-]+/[\w./+@-]+')
CITE_SOURCE = re.compile(r'\b[\w+@-]+\.(?:c|h|cc|cpp|s|asm|u|lst|y|l)\b')
CITE_BINARY = re.compile(r'[\w+@-]+\.(?:o|a|so|bin|elf|u)\b')
LOCATED = re.compile(r'\b(?:address(?:es)?|offsets?|sizes?|bytes?|records?|extents?|callers?|called|sites?|'
                     r'calls?|entry|entries|lanes?)\b|0[xX][0-9a-fA-F]+', re.I)
_NUM = r'(?:0[xX][0-9a-fA-F]+|\d+)'
_RANGE = _NUM + r'(?:\s*(?:[:\-\u2013]|\.\.|\bto\b)\s*' + _NUM + r')?'
_SEP = r'\s*(?:,|;|/|\band\b|\bor\b)\s*(?:and\s+|or\s+)?'
_FIELD = (r'(?:`[^`\s]+`|(?=\w*[_0-9A-Z])\w+)(?:\s*[\[(]\s*' + _RANGE + r'(?:' + _SEP + _RANGE +
          r')*\s*[\])])?')
# The bit positions and field names of the entry's own subject: a list that "bit(s)" or "field(s)" introduces
# and that holds nothing but numbers or field names, each with at most its own bit range. They describe the
# subject, so they are not extra items on the line.
FIELD_LIST = re.compile(r'\bbits?(?:\s+positions?)?\b\s*:?\s*\[?' + _RANGE + r'\]?(?:' + _SEP + r'\[?' + _RANGE +
                        r'\]?)*|\bfields?\b\s*(?::|\bare\b|\bis\b)?\s*' + _FIELD + r'(?:' + _SEP + _FIELD + r')*',
                        re.I)
NUMLIST = re.compile(r'\b(?:0[xX][0-9a-fA-F]+|\d+)\b(?:\s*(?:,|;|\band\b|\bor\b)\s*\b(?:0[xX][0-9a-fA-F]+|\d+)\b)+')
ADDRESS_HEAD = ('offset', 'address', 'addr', 'entry', 'record')
IDENTITY_HEAD = ('address', 'addr', 'offset', 'slot', 'index', 'idx', 'entry', 'record', 'routine', 'ioctl',
                 'request', 'row', 'number', 'no.', '#')   # a column of a data table that says where the row is
DATA_CELL_WORDS = 5    # a cell of a data table holds a value, not a sentence: at most this many words
NUMBER_HEAD = ('ioctl', 'entry', 'record', 'routine', 'slot', 'request')
LEAD = re.compile(r'^\s*(?:(?:[-*+]|\d+\.)\s+)?[*_]*')


def bare_text(text):
    """The text without the targets of markdown links."""
    return re.sub(r'\]\([^)]*\)', ']', text)


def unit_keys(u):
    """The items a subject span names: identifiers, numbers and file names."""
    keys = set()
    for m in IDENT.finditer(u):
        nm = m.group(0).rstrip('.')
        if not re.fullmatch(r'[xX][0-9a-fA-F]+', nm):
            keys.add(('id', nm))
    for plus, h in HEXLIT.findall(u):
        keys.add(('hex', int(h, 16)))
    for m in DECLIT.finditer(u):
        keys.add(('dec', int(m.group(1))))
    for m in FILELIKE.finditer(u):
        keys.add(('file', m.group(0)))
    return keys


def leading_unit(text, bare_numbers=False):
    """The leading identifier of a list item or paragraph: a code span, a code-like word or a
    hex number at its start, after any bullet and emphasis. '' when it starts with prose."""
    t = bare_text(text)
    t = LEAD.sub('', t, count=1)
    t = re.sub(r'^\[(?=`)', '', t)
    m = re.match(r'`([^`]+)`', t)
    if m:
        return m.group(1)
    m = re.match(r'(\+?0[xX][0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_$.]*[A-Za-z0-9_$])(?![\w(])', t)
    if m and (m.group(0)[0] in '+0' or CODELIKE.match(m.group(0))):
        return m.group(0)
    m = re.match(r'([A-Za-z_][A-Za-z0-9_$]*)\(\)', t)
    if m:
        return m.group(1)
    return ''


def cell_unit(cell, head_cell=''):
    """The subject span of one table cell, or '' when the cell holds no identifier."""
    c = bare_text(cell).strip()
    m = re.search(r'`([^`]+)`', c)
    if m:
        return m.group(1)
    if re.fullmatch(r'[*_]*\+?0[xX][0-9a-fA-F]+[*_]*', c):
        return c.strip('*_')
    if re.fullmatch(r'[*_]*\d+[*_]*', c):
        return c.strip('*_') if any(w in head_cell for w in NUMBER_HEAD) else ''
    for w in c.replace('(', ' (').split():
        w = w.strip('*_,;:')
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$.]*[A-Za-z0-9_$]', w) and CODELIKE.match(w):
            return w
    return ''


def row_subject(text, head):
    """The subject span of a table row: its first cell that holds an identifier."""
    cells = [c.strip() for c in text.strip().strip('|').split('|')]
    if all(re.fullmatch(r':?-{2,}:?|', c) for c in cells):
        return ''
    for k, c in enumerate(cells):
        u = cell_unit(c, head[k] if head and k < len(head) else '')
        if u:
            return u
    return ''


def split_cells(text):
    return [c.strip() for c in bare_text(text).strip().strip('|').split('|')]


def value_cell(cell):
    """The normalised text of a table cell that holds a decoded value: short, with a digit or a code
    span in it (`60`, `0x2bdc`, `1280x1624`, `20 states`, `table at 0x2bdc`). '' for a cell that is
    empty, a dash, or text."""
    c = re.sub(r'[*_]+', '', cell.strip())
    if not c or re.fullmatch(r'[-\u2013\u2014 ]*', c):
        return ''
    if len(c.split()) > DATA_CELL_WORDS or re.search(r'[.!?;:]\s', c):
        return ''
    if re.search(r'\d', c) or '`' in c:
        return c.replace('`', '')
    return ''


def data_row(text, head, subj):
    """The decoded values a row of a structured data table states, as {(column, value)}, or None when
    the row is not one. A data table's rows are mostly values: at least MIN_DATA of the row's cells hold
    one and they are at least half of its cells. The subject's cell and the columns headed address,
    offset, slot or index say where the row is, not what it holds, so they give no value and do not count."""
    cells = split_cells(text)
    if not head or not text.strip().startswith('|') or all(re.fullmatch(r':?-{2,}:?|', c) for c in cells):
        return None
    sk = None
    for k, c in enumerate(cells):
        if cell_unit(c, head[k] if k < len(head) else ''):
            sk = k
            break
    vals, other = set(), 0
    for k, c in enumerate(cells):
        h = head[k] if k < len(head) else ''
        if k == sk or any(w in h for w in IDENTITY_HEAD) or not re.sub(r'[*_`\s]+', '', c):
            continue
        v = value_cell(c)
        if v:
            vals.add((k, v))
        else:
            other += 1
    if len(vals) < MIN_DATA or 2 * len(vals) < len(vals) + other:
        return None
    return vals


def own_values(cells, head=None, data=False):
    """The numbers a table row's own cells hold by themselves: its address, slot or index. They say
    where the row's subject is, so they are its identity, not a derivation of it."""
    own = set()
    for k, c in enumerate(cells or ()):
        h = head[k] if head and k < len(head) else ''
        if data and not any(w in h for w in IDENTITY_HEAD):
            continue
        m = re.fullmatch(r'[*_`]*\+?(?:0[xX]([0-9a-fA-F]+)|(\d+))[*_`]*', c.strip())
        if m:
            v = int(m.group(1), 16) if m.group(1) else int(m.group(2))
            own.add(v)
            own.add(v & 0xfffff)
    return own


def item_cite(text, subj, own=frozenset()):
    """True when the entry names an offset, address, callee or source file other than its own
    subject or the row's own address cells."""
    t = bare_text(text)
    for m in CITE_OFFSET.finditer(t):
        h = int(next(g for g in m.groups() if g), 16)
        if ('hex', h) not in subj and h not in own and (h & 0xfffff) not in own:
            return True
    for m in CALL_LIST.finditer(t):
        if any(('id', n.strip()) not in subj for n in re.findall(r'`([^`]+)`', m.group(1))):
            return True
    for m in CITE_PATH.finditer(t):
        if ('file', m.group(0)) not in subj:
            return True
    for m in CITE_SOURCE.finditer(t):
        if ('file', m.group(0)) not in subj and ('id', m.group(0)) not in subj:
            return True
    # a binary together with a routine of it other than the subject: where the derivation was read
    if CITE_BINARY.search(t):
        for sp in re.findall(r'`([^`]+)`', t):
            sp = sp.strip()
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]*', sp) and ('id', sp) not in subj:
                return True
    return False


def data_items(text, subj, own=frozenset()):
    """The items an entry states about its subject: numbers and code names other than the subject's
    own and the row's address cells."""
    t = bare_text(text)
    items = set()
    for plus, h in HEXLIT.findall(t):
        v = int(h, 16)
        if ('hex', v) not in subj and v not in own and (v & 0xfffff) not in own:
            items.add(('hex', v))
    for m in DECLIT.finditer(t):
        v = int(m.group(1))
        if v >= 2 and ('dec', v) not in subj and v not in own:
            items.add(('dec', v))
    for sp in re.findall(r'`([^`]+)`', t):
        sp = sp.strip()
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$.]*[A-Za-z0-9_$]', sp) and ('id', sp) not in subj:
            items.add(('id', sp))
    return items


def open_split(text):
    """The entry without the sentences that say something is unknown, and those sentences."""
    cells, dropped = [], []
    for cell in bare_text(text).split('|'):
        keep = []
        for sent in re.split(r'(?<=[.!?;])\s+', cell.strip()):
            if UNKNOWN.search(sent):
                dropped.append(sent)
            elif sent:
                keep.append(sent)
        cells.append(' ' + ' '.join(keep) + ' ' if keep else ' ')
    return '|'.join(cells), dropped


def row_items(text, subj, own, head):
    """The items an entry states about its subject. A row of a structured data table gets one item per
    cell that holds a decoded value (a pure integer included), unless the column says where the row is;
    the rest of the row is read as before."""
    vals = data_row(text, head, subj)
    if vals is None:
        return data_items(text, subj, own)
    cells = split_cells(text)
    keep = ['' if any(k == c for c, v in vals) else cells[k] for k in range(len(cells))]
    own = own_values(cells, head, True)
    return data_items('|'.join(' %s ' % c for c in keep), subj, own) | {('cell', k, v) for k, v in vals}


def stated(text, subj, own, head=None):
    return bool(LABEL.search(text) and len(role_words(text, subj)) >= MIN_ROLE_WORDS
                and len(row_items(text, subj, own, head)) >= MIN_DATA)


def computes_lead(text):
    """The first clause that follows the entry's label (established or inferred), or its first clause."""
    m = LABEL.search(text)
    rest = text[m.end():] if m else text
    return re.split(r'(?<=[.;:])\s', rest.strip(), maxsplit=1)[0]


def computes(text):
    """True when the entry names inputs and outputs and describes an operation on data. The input and output
    words are no credit by themselves: the operation words decide, and an entry that opens as a copy, store,
    load or dispatch needs two different ones, because one is usually address or counter bookkeeping."""
    if not (COMPUTES_IN.search(text) and COMPUTES_OUT.search(text)):
        return False
    text = COMPUTES_NEG.sub('', text)
    ops = {m.group(0).lower() for m in COMPUTES_OP.finditer(text)}
    if not ops:
        return False
    lead = computes_lead(text)
    if COMPUTES_MOVE.match(lead) and not COMPUTES_OP.search(lead):
        return len(ops) >= 2
    return True


# An entry that closes with this label says its facts were written quickly and not yet checked against the
# binary or the source: whatever else it says, it earns at most "located".
UNVERIFIED = re.compile(r'\bunverified\.(\s*\|?\s*)$', re.I)


def classify(text, subj=frozenset(), head=None):
    """The status of one entry (see classify_read). An entry that closes with the Unverified label is graded
    as if it closed with Inferred, so its content is read the same way and the hedge words do not read the
    label, and then capped at located."""
    bare = bare_text(text)
    if not UNVERIFIED.search(bare):
        return classify_read(text, subj, head)
    status, _ = classify_read(UNVERIFIED.sub(r'Inferred.\1', text), subj, head)
    return ('located' if status == 'understood' else status), False


def classify_read(text, subj=frozenset(), head=None):
    """The status one entry (a table row, a list item, a paragraph or a header comment)
    earns for its subject. The entry must carry a derivation citation specific to the item, one
    that is not the row's own address. Behaviour labelled unknown, or hedged as not derived, is
    located. With an established or inferred label, enough words of role that do not merely
    restate the subject's name, and at least MIN_DATA items stated about the subject, it is
    understood. An "unknown" about a sub-fact does not demote an entry whose role and effect, read without
    the sentences that say it, still qualify: it stays understood and is returned as open, so the summary
    can count it. The result is (status, open)."""
    t = bare_text(text)
    own = frozenset()
    if head is not None and t.strip().startswith('|'):
        own = own_values([c.strip() for c in t.strip().strip('|').split('|')])
    if not item_cite(t, subj, own):
        return 'named-only', False
    if HEDGE.search(t):
        return ('located' if LOCATED.search(t) else 'named-only'), False
    if UNKNOWN.search(t):
        rest, dropped = open_split(t)
        if (not any(ROLE_UNKNOWN.search(d) for d in dropped) and item_cite(rest, subj, own)
                and stated(rest, subj, own, head)):
            return identified('understood', rest, t), True
        return ('located' if LOCATED.search(t) else 'named-only'), False
    if stated(t, subj, own, head):
        return identified('understood', t, t), False
    return 'named-only', False


def match_only(text):
    """True when an entry identifies its item by a match alone (the public routine of the same name, size
    or number of calls) and says nothing of reading the body."""
    return bool(MATCH_ONLY.search(text)) and not BODY_READ.search(text)


def build_datum(text):
    """True when an entry states something read from the binary's own build: an offset, an immediate value
    or the address of a callee."""
    return bool(BUILD_DATUM.search(text))


def identified(status, text, whole):
    """The status of an entry that would be understood. One that identifies its item by a match alone
    and states no datum of its own build is a claim about the public routine, not a reading of this one:
    it locates the item."""
    if status == 'understood' and match_only(whole) and not build_datum(whole):
        return 'located'
    return status


def skeleton(text):
    """The sentence skeleton of an entry: identifiers, file names and numbers masked, punctuation
    and case dropped. Entries that differ only in the items they name share one."""
    t = bare_text(text)
    t = re.sub(r'`[^`]*`', ' ID ', t)
    t = FILELIKE.sub(' ID ', t)
    t = HEXLIT.sub(' ID ', t)
    t = re.sub(r'\b\w*[_0-9]\w*\b|\b\w+[a-z][A-Z]\w*\b', ' ID ', t)
    t = re.sub(r'[^A-Za-z]+', ' ', t)
    out = []
    for w in t.lower().split():
        if w == 'id' and out and out[-1] == 'id':
            continue
        out.append(w)
    return ' '.join(out)


# The words a generated frame varies from row to row without saying anything new: the data type, its
# signedness and the count of components ("from three signed bytes", "from four unsigned shorts").
TYPE_WORD = re.compile(r'\b(?:un)?signed\b|\b(?:bytes?|shorts?|integers?|ints?|floats?|doubles?)\b|'
                       r'\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|sixteen)\b', re.I)


def cap_key(text, short=False):
    """What the template cap compares. A sentence is its skeleton with the type and count words masked too, so
    one frame filled with different types is one sentence. A short cell of a data table is compared whole,
    as written: the same few words in many rows are one cell repeated, while the same words around
    different values (a register number, a bit) stay apart."""
    if short:
        return 'cell: ' + ' '.join(re.sub(r'[*_`]+', '', bare_text(text)).lower().split())
    out = []
    for w in skeleton(TYPE_WORD.sub(' TYPEWORD ', text)).split():
        if w == 'typeword' and out and out[-1] in ('typeword', 'id'):
            continue
        out.append(w)
    return ' '.join(out)


def sentences(text):
    """The sentences of an entry: each table cell, then each sentence inside it."""
    out = []
    for cell in bare_text(text).split('|'):
        for sent in re.split(r'(?<=[.!?;])\s+', cell.strip()):
            if sent.strip():
                out.append(sent.strip())
    return out


def sentence_cells(text):
    """(sentence, short) for each sentence of an entry: short is True for a sentence of a cell that is no
    more than a label or value (DATA_CELL_WORDS words)."""
    out = []
    for cell in bare_text(text).split('|'):
        short = len(re.sub(r'[*_`]+', '', cell).split()) <= DATA_CELL_WORDS
        for sent in re.split(r'(?<=[.!?;])\s+', cell.strip()):
            if sent.strip():
                out.append((sent.strip(), short))
    return out


class Entry:
    """One table row, list item, paragraph or header comment, with what it earns."""
    __slots__ = ('text', 'level', 'skel', 'capped', 'nsd_capped', 'keys', 'subj', 'sents', 'nsd_sents',
                 'open', 'computes', 'data', 'reused')

    def __init__(self, text, level, subj=frozenset(), open_=False, data=False):
        self.text, self.level, self.subj, self.open, self.data = text, level, subj, open_, data
        self.computes = level == 'understood' and computes(open_split(text)[0] if open_ else bare_text(text))
        self.skel = skeleton(text)
        self.capped = self.nsd_capped = self.reused = False
        self.keys = None
        # (skeleton, role words) of each sentence long enough to state anything; the sentences that
        # say no software depends on a fact are counted apart, for the no-dependency status
        self.sents, self.nsd_sents = [], []
        for sent, short in sentence_cells(text):
            if NSD_PHRASE.search(sent):
                self.nsd_sents.append(skeleton(sent))
            elif open_ and UNKNOWN.search(sent):
                continue                  # an open sub-fact is not one of the entry's role sentences
            elif plain_words(sent) >= 3:
                # a short cell of a data-table row counts only as the same cell repeated in other rows
                self.sents.append((cap_key(sent, data and short), len(role_words(sent, subj)),
                                   bool(EVIDENCE.search(sent))))

    def cap(self, count):
        """True when too much of the entry is a sentence that more than TEMPLATE_CAP entries share:
        most of its sentences are, or what is left of it has too few role words to state a role. In a row of
        a structured data table that states decoded values of its own, repeated words
        around different values are not one sentence repeated: a short cell of such a row is a template only
        when the same cell, word for word, recurs in more than TEMPLATE_CAP entries."""
        over = [n for sk, n, ev in self.sents if count[sk] > TEMPLATE_CAP]
        if not over:
            return False
        # the sentence that says how the entry was derived is judged on its own: a unique role sentence
        # beside a shared evidence sentence does not make the evidence the entry's own
        if any(ev and count[sk] > TEMPLATE_CAP for sk, n, ev in self.sents if sk is not None):
            return True
        left = sum(n for sk, n, ev in self.sents if count[sk] <= TEMPLATE_CAP)
        return 2 * len(over) > len(self.sents) or left < MIN_ROLE_WORDS

    def tokens(self):
        """The file and path names the entry writes, for the binaries it cites."""
        if self.keys is None:
            self.keys = frozenset(m.group(0) for m in PATHTOK.finditer(self.text.replace('`', ' ')))
        return self.keys


PATHTOK = re.compile(r'[\w.+@$-]+(?:/[\w.+@$-]+)*(?:\([\w.+@$-]+\))?')


def line_items(text, subj=frozenset()):
    """How many things one line names: distinct identifiers, plus numbers written as a list. For an entry
    with a subject, the bit positions and fields of that subject (FIELD_LIST) are not counted."""
    t = bare_text(text)
    if subj:
        t = FIELD_LIST.sub(' ', t)
    # a callee or caller is a citation of the subject, and a path says where its file is: neither is
    # another item the line documents
    t = CALL_LIST.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)], t)
    t = PATHLIKE.sub(' ', t)
    items = set()
    for sp in re.findall(r'`([^`]*)`', t):
        sp = sp.strip()
        if re.fullmatch(r'[+-]?(?:0[xX][0-9a-fA-F]+|\d+)', sp):
            continue
        if re.search(r'\s', sp):
            items.add(sp)
            continue
        for m in IDENT.finditer(sp):
            nm = m.group(0)
            if '.' not in nm.strip('.') and not re.fullmatch(r'[xX][0-9a-fA-F]+', nm):
                items.add(nm)
    rest = re.sub(r'`[^`]*`', ' ', t)
    rest = re.sub(r'\b\d\w*', ' ', rest)
    for m in IDENT.finditer(rest):
        nm = m.group(0).rstrip('.')
        if '.' in nm:
            continue
        if CODELIKE.match(nm) or rest[m.end():m.end() + 1] == '(':
            items.add(nm)
    n = len(items)
    for m in NUMLIST.finditer(t):
        n += len(re.findall(r'0[xX][0-9a-fA-F]+|\d+', m.group(0)))
    return n


def ctx_match(ctx, words):
    return any(re.search(r'\b' + re.escape(w.strip()), ctx) for w in words)


def dec_contexts(text, head=None):
    """(value, context) for each decimal number in a line: the three words before it and the
    one after, or, for a table cell that is only the number, the column heading."""
    out = []
    cells = None
    if head is not None and text.strip().startswith('|'):
        cells = [c.strip() for c in text.strip().strip('|').split('|')]
    for m in DECLIT.finditer(text):
        before = re.findall(r'[A-Za-z0-9_]+', text[:m.start()])[-3:]
        after = re.findall(r'[A-Za-z0-9_]+', text[m.end():])[:1]
        ctx = ' '.join(before + after).lower()
        if cells is not None:
            for k, c in enumerate(cells):
                if c.strip('`*') == m.group(1) and k < len(head):
                    ctx += ' ' + head[k]
                    break
        out.append((int(m.group(1)), ctx))
    return out


def role_signature(text):
    """The role clause of a list item or paragraph, masked for comparison across workspaces: the text
    after its heading ("`name` in path:") up to the first semicolon or sentence end and before "and it
    occupies"; code spans, numbers and case dropped. '' when it is too short to compare."""
    t = re.sub(r'^\s*(?:[-*+]|\d+\.)\s*', '', bare_text(text).strip())
    m = re.match(r'[^:;]{0,200}?:\s+', t)
    if m:
        t = t[m.end():]
    t = re.split(r';|(?<=[a-z0-9)])\.\s', t, maxsplit=1)[0]
    t = re.split(r',\s+and\s+(?:in\s+the\s+[^,;]*?\s+)?it\s+occupies', t, maxsplit=1)[0]
    t = re.sub(r'`[^`]*`', ' ID ', t)
    t = re.sub(r'\b(?:0[xX][0-9a-fA-F]+|\d+)\b', ' # ', t)
    t = ' '.join(re.sub(r'[^a-z# ]+', ' ', t.lower()).split())
    return t if len(t.split()) >= 4 else ''


def similar(a, b, cache):
    """True when two masked role texts are identical or at least SIMILAR alike."""
    if a == b:
        return True
    key = (a, b) if a < b else (b, a)
    if key not in cache:
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        cache[key] = (sm.real_quick_ratio() >= SIMILAR and sm.quick_ratio() >= SIMILAR
                      and sm.ratio() >= SIMILAR)
    return cache[key]


def load_siblings(cfg, given, tmp, problems, new_pins, skip=False, update=False):
    """(roles, used, skipped): the role texts of the sibling workspaces' entries, {function name:
    [masked role text]}, {name: commit} of the siblings that were read, and (name, why) of those that were
    not. A sibling is a checkout named in the config's `siblings` ({name: path from this repository}) or
    by --sibling NAME=PATH; a clone at .cache/siblings/NAME is the fallback for a run where ../NAME is not
    visible. What is read is the sibling's documents as of the commit recorded for it in SIBLING_PINS, taken
    from the commit and not from the working tree, so the result does not depend on what the checkout holds,
    where it is, or the order the workspaces are regenerated in. A sibling that is absent, lacks its commit,
    or is of this family (it would grade every entry as a copy of itself) is a problem, not a skip: only
    --skip-siblings skips, and it says so in the tables."""
    global REPO
    spec = dict(cfg.get('siblings', {}))
    spec.update(given)
    roles, used, skipped = collections.defaultdict(list), {}, []
    pins_path = os.path.join(REPO, SIBLING_PINS)
    pins = json.load(open(pins_path, encoding='utf-8')) if os.path.isfile(pins_path) else {}
    new_pins.update(pins)
    for name in sorted(spec):
        if skip:
            skipped.append((name, 'skipped by --skip-siblings'))
            continue
        cands = [spec[name], os.path.join('.cache', 'siblings', name)]
        found = next((c for c in cands if os.path.exists(os.path.join(REPO, c, '.git'))), None)
        if found is None:
            problems.append('sibling %s: no git checkout at %s (clone it there, or pass --sibling %s=PATH; '
                            '--skip-siblings runs without the cross-workspace check)' %
                            (name, ' or '.join(cands), name))
            continue
        src = os.path.normpath(os.path.join(REPO, found))
        if update:
            head = git(src, 'rev-parse', 'HEAD')
            if head.returncode:
                problems.append('sibling %s at %s: cannot read HEAD: %s' % (name, found, head.stderr.strip()))
                continue
            new_pins[name] = head.stdout.strip()
        commit = new_pins.get(name)
        if not commit:
            problems.append('sibling %s: no commit recorded in %s (run with --update-pins)' % (name, SIBLING_PINS))
            continue
        if git(src, 'cat-file', '-e', commit + '^{commit}').returncode:
            problems.append('sibling %s at %s does not have commit %s recorded in %s (fetch it, or run with '
                            '--update-pins)' % (name, found, commit[:12], SIBLING_PINS))
            continue
        cpath = 'scripts/inventory-config.json'
        shown = git(src, 'show', '%s:%s' % (commit, cpath))
        if shown.returncode:
            problems.append('sibling %s at %s has no %s at commit %s' % (name, found, cpath, commit[:12]))
            continue
        scfg = json.loads(shown.stdout)
        if scfg.get('family') == cfg.get('family'):
            problems.append('sibling %s at %s is of this workspace\'s own family (%s): the role check would '
                            'compare the workspace with itself' % (name, found, cfg.get('family')))
            continue
        dest = os.path.join(tmp, 'sibling-' + name)
        os.makedirs(dest)
        tar = subprocess.run(['git', '-c', 'safe.directory=*', '-C', src, 'archive', '--format=tar', commit, '--',
                              ':(glob)**/*.md', ':(glob)**/*.h', ':(glob)**/*.tsv', cpath],
                             capture_output=True)
        if tar.returncode:
            problems.append('sibling %s: git archive failed: %s' % (name, tar.stderr.decode('utf-8', 'replace').strip()))
            continue
        with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as tf:
            tf.extractall(dest, **({'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}))
        sdocs = scfg['docs']
        bad = [p for k in ('prose', 'headers', 'tables', 'dumps') for p in sdocs.get(k, [])
               if not p.endswith(('.md', '.h', '.tsv'))]
        if bad:
            problems.append('sibling %s reads %s, which a sibling export (*.md, *.h, *.tsv) does not carry' %
                            (name, ', '.join(bad)))
            continue
        problems += conflict_problems(dest, doc_files(scfg, dest), 'sibling %s' % name)
        old, REPO = REPO, dest
        try:
            sib = DocIndex(scfg, None)
        finally:
            REPO = old
        for e in sib.entries:
            if e.text.lstrip().startswith('|'):
                continue
            sig = role_signature(e.text)
            if sig:
                for k in e.subj:
                    if k[0] == 'id':
                        roles[k[1]].append(sig)
        used[name] = commit
    if not spec:
        skipped.append(('(none)', 'no sibling workspace configured'))
    return roles, used, skipped


def ambiguous(name):
    return len(name) <= 3 or re.fullmatch(r'[a-z]+', name) is not None


class Hit:
    __slots__ = ('file', 'line', 'ref', 'section', 'level', 'nsd', 'code', 'ctx', 'order', 'ent', 'path')

    def __init__(self, file, line, ref, section, level, nsd, code, ctx, order, ent=None, path=''):
        self.path = path
        self.file, self.line, self.ref, self.section = file, line, ref, section
        self.level, self.nsd, self.code, self.ctx, self.order, self.ent = level, nsd, code, ctx, order, ent

    def raw(self):
        return 'no-software-dependency' if self.nsd else self.level

    def templated(self):
        """True when the entry's sentence skeleton is shared by too many entries to be credited."""
        if self.ent is None:
            return False
        if self.nsd:
            return self.ent.nsd_capped
        return self.ent.capped and RANK[self.raw()] > RANK['located']

    def reused(self):
        """True when the entry's role text is the sibling workspace's text for the same function and the
        entry states no datum of its own build."""
        return (self.ent is not None and self.ent.reused and not self.nsd
                and RANK[self.raw()] > RANK['located'])

    def status(self):
        return 'located' if self.templated() or self.reused() else self.raw()


class DocIndex:
    """Where the repository's own text mentions each name and number."""

    def __init__(self, cfg, siblings=None):
        self.names = collections.defaultdict(list)
        self.files = collections.defaultdict(list)
        self.hexes = collections.defaultdict(list)     # value -> [(hit, plus)]
        self.decs = collections.defaultdict(list)
        self.defs = collections.defaultdict(list)      # value -> [hit] for header #define / enum values
        self.order = 0
        self.entries = []                              # every prose entry, for the template cap
        d = cfg['docs']
        index = set()
        for p in d.get('index', []):
            index.update(self.expand(p))
        skip = set()
        for p in d.get('skip', []):
            skip.update(self.expand(p))
        seen = set()
        for kind, pats in (('md', d.get('prose', [])), ('h', d.get('headers', []))):
            for pat in pats:
                for rel in self.expand(pat):
                    if rel in seen or rel in skip:
                        continue
                    seen.add(rel)
                    (self.read_md if kind == 'md' else self.read_header)(rel, rel in index)
        for rel in sorted(index):
            if rel not in seen and rel not in skip and os.path.isfile(os.path.join(REPO, rel)):
                seen.add(rel)
                self.read_md(rel, True)
        dumps = set()
        for p in d.get('dumps', []):
            dumps.update(self.expand(p))
        for pat in d.get('tables', []):
            for rel in self.expand(pat):
                if rel in seen or rel in skip or rel in dumps:
                    continue
                seen.add(rel)
                self.read_table(rel)
        count = collections.Counter(sk for e in self.entries for sk in {sk for sk, n, ev in e.sents if sk is not None})
        ncount = collections.Counter(sk for e in self.entries for sk in set(e.nsd_sents))
        for e in self.entries:
            e.capped = e.cap(count)
            e.nsd_capped = any(ncount[sk] > TEMPLATE_CAP for sk in e.nsd_sents)
        self.sibling_report = self.check_siblings(siblings)

    def check_siblings(self, siblings):
        """Mark each understood entry whose role text is, or is at least SIMILAR to, the sibling workspace's
        text for a function of the same name, when the entry states no datum of its own build: nobody
        showed that the text was read from this binary. Returns what was checked, for the headline."""
        roles, used, skipped = siblings if siblings is not None else ({}, {}, [('(none)', 'no sibling workspace configured')])
        report = {'siblings': sorted(used), 'commits': dict(used), 'skipped': skipped, 'compared': 0, 'reused': 0}
        if not used:
            return report
        cache = {}
        for e in self.entries:
            if e.level != 'understood' or e.text.lstrip().startswith('|'):
                continue
            sig = role_signature(e.text)
            if not sig:
                continue
            cands = [r for k in sorted(e.subj) if k[0] == 'id' for r in roles.get(k[1], ())]
            if not cands:
                continue
            report['compared'] += 1
            if not build_datum(e.text) and any(similar(sig, c, cache) for c in cands):
                e.reused = True
                report['reused'] += 1
        return report

    @staticmethod
    def expand(pat):
        out = []
        for p in sorted(glob.glob(os.path.join(REPO, pat), recursive=True)):
            if os.path.isfile(p):
                out.append(os.path.relpath(p, REPO))
        return out

    def hit(self, file, line, ref, section, level, nsd, code, ctx, ent=None, path=''):
        self.order += 1
        return Hit(file, line, ref, section, level, nsd, code, ctx, self.order, ent, path)

    def add_text(self, file, n, ref, section, text, level, nsd, code_spans, code_all, ctx, head=None,
                 subj=frozenset(), ent=None):
        """Index one line. code_spans are the parts written as code. level is what the
        entry holding the line earns, which a line naming many items does not get. Only the
        entry's subject (the keys in subj) earns it; every other item the line names is a mention."""
        if line_items(text, subj) > MAX_ITEMS:
            level, nsd = 'named-only', False

        def hit(k, code, c=ctx):
            if k in subj:
                return self.hit(file, n, ref, section, level, nsd, code, c, ent)
            return self.hit(file, n, ref, section, 'named-only', False, code, c, ent)
        code_text = ' '.join(code_spans)
        seen = set()
        for m in IDENT.finditer(code_text):
            nm = m.group(0).rstrip('.')
            if nm in seen:
                continue
            seen.add(nm)
            h = hit(('id', nm), True)
            if '/' in code_text[max(0, m.start() - 1):m.end() + 1]:
                # a name written as the end of a path: remember the path, for file rows that match by it
                h.path = next((t for t in PATHTOK.findall(code_text) if '/' in t and nm in t.split('/')[-1]), '')
            self.names[nm].append(h)
        if not code_all:
            for m in IDENT.finditer(re.sub(r'`[^`]*`', ' ', text)):
                nm = m.group(0).rstrip('.')
                if nm in seen:
                    continue
                call = text[m.end():m.end() + 1] == '('
                if not call and not CODELIKE.match(nm):
                    continue
                seen.add(nm)
                self.names[nm].append(hit(('id', nm), call))
        ftext = code_text if not code_all else text
        paths = [(m.start(), m.end(), m.group(0)) for m in PATHTOK.finditer(ftext)]
        for m in FILELIKE.finditer(ftext):
            # the path the document wrote around the file name: a file row is matched by it, not by the name
            wrote = next((t for a, b, t in paths if a <= m.start() and m.end() <= b), m.group(0))
            h = hit(('file', m.group(0)), True)
            h.path = wrote
            self.files[m.group(0)].append(h)
        for plus, h in set(HEXLIT.findall(text)):
            v = int(h, 16)
            self.hexes[v].append((hit(('hex', v), True), bool(plus)))
        for v, dctx in dec_contexts(text, head):
            self.decs[v].append(hit(('dec', v), True, dctx))

    def read_md(self, rel, index):
        lines = open(os.path.join(REPO, rel), encoding='utf-8', errors='replace').read().split('\n')
        if rel.endswith('coverage.md'):
            lines = strip_generated(lines)
        section, ref = '', rel
        fence = False
        # paragraphs carry the "no shipped software" label to every line in them
        paras, cur = [], []
        for i, ln in enumerate(lines):
            s = ln.strip()
            brk = (not s or s.startswith('```') or s.startswith('#') or s.startswith('|')
                   or re.match(r'([-*+]|\d+\.)\s', s))
            if brk and cur:
                paras.append(cur)
                cur = []
            if s:
                cur.append(i)
                if s.startswith('|') or s.startswith('#') or s.startswith('```'):
                    paras.append(cur)
                    cur = []
        if cur:
            paras.append(cur)
        nsd_line = set()
        for p in paras:
            ptext = ' '.join(lines[i] for i in p)
            if NSD_PHRASE.search(ptext) and NSD_ROUTES.search(ptext):
                nsd_line.update(p)
        # an entry is a table row, a list item with its continuation lines, or a paragraph
        entry_of, entries, cur, efence = {}, [], None, False
        for i, ln in enumerate(lines):
            s = ln.strip()
            if s.startswith('```'):
                efence, cur = not efence, None
                continue
            if efence:
                continue
            if not s or s.startswith('#'):
                cur = None
            elif s.startswith('|'):
                entries.append([i])
                entry_of[i] = len(entries) - 1
                cur = None
            else:
                if cur is None or re.match(r'([-*+]|\d+\.)\s', s):
                    entries.append([])
                    cur = len(entries) - 1
                entries[cur].append(i)
                entry_of[i] = cur
        entry_obj = {}
        head = None
        prev_table = False
        hunit = ''
        for i, ln in enumerate(lines):
            n = i + 1
            st = ln.strip()
            if st.startswith('```'):
                fence = not fence
                continue
            if not fence and re.match(r'#{1,6}\s', ln):
                section = re.sub(r'^#+\s*', '', ln).strip()
                ref = '%s#%s' % (rel, slug(section))
                hunit = cell_unit(section)
            is_table = not fence and st.startswith('|')
            is_head = is_table and not prev_table
            if is_head:
                head = [c.strip().lower() for c in st.strip('|').split('|')]
            prev_table = is_table
            subj, ent = frozenset(), None
            if fence:
                level = 'named-only'          # a listing restates its subject
                spans, code_all = [ln], True
            else:
                e = entry_of.get(i)
                if e is not None and e not in entry_obj:
                    etext = ' '.join(lines[j] for j in entries[e])
                    if is_table:
                        unit = '' if is_head else row_subject(ln, head)
                    else:
                        unit = leading_unit(lines[entries[e][0]]) or hunit
                    keys = frozenset(unit_keys(unit)) if unit else frozenset()
                    lvl, opn = (('named-only', False) if is_head
                                else classify(etext, keys, head if is_table else None))
                    dvals = data_row(etext, head, keys) if is_table and not is_head else None
                    entry_obj[e] = (Entry(etext, lvl, keys, opn, dvals is not None and len(dvals) >= MIN_DATA), keys)
                    if not is_head and not index:
                        self.entries.append(entry_obj[e][0])
                if e in entry_obj:
                    ent, subj = entry_obj[e]
                level = ent.level if ent is not None else 'named-only'
                spans, code_all = re.findall(r'`([^`]+)`', ln), False
            if index:
                level = 'named-only'
            nsd = (i in nsd_line) and not index
            ctx = (ln + ' ' + section).lower()
            self.add_text(rel, n, ref, section, ln, level, nsd, spans, code_all, ctx,
                          head if is_table else None, subj, ent)

    def read_header(self, rel, index):
        lines = open(os.path.join(REPO, rel), encoding='utf-8', errors='replace').read().split('\n')
        # split each line into code and comment; a standalone comment line has no code
        parts = []
        incomment = False
        for ln in lines:
            code, comment = ln, ''
            if incomment:
                if '*/' in ln:
                    comment, code = ln.split('*/', 1)
                    incomment = False
                else:
                    comment, code = ln, ''
            if not incomment:
                while True:
                    m = re.search(r'/\*(.*?)(\*/|$)', code)
                    if not m:
                        break
                    comment += ' ' + m.group(1)
                    code = code[:m.start()] + ' ' + code[m.end():]
                    if not m.group(2):
                        incomment = True
                        break
                m2 = re.search(r'//(.*)$', code)
                if m2:
                    comment += ' ' + m2.group(1)
                    code = code[:m2.start()]
            text = comment.strip().lstrip('*').strip()
            parts.append((code, comment, text, not code.strip()))
        # paragraphs of standalone comment lines carry their word count and label to each line
        para = [None] * len(lines)
        i = 0
        while i < len(lines):
            if parts[i][3] and parts[i][2] and not re.fullmatch(r'[-=*/ ]*', parts[i][2]):
                j = i
                while j < len(lines) and parts[j][3] and parts[j][2] and not re.fullmatch(r'[-=*/ ]*', parts[j][2]):
                    j += 1
                text = ' '.join(parts[k][2] for k in range(i, j))
                info = (text, bool(NSD_PHRASE.search(text) and NSD_ROUTES.search(text)), j - 1)
                for k in range(i, j):
                    para[k] = info
                i = j
            else:
                i += 1
        section = ''
        banner = False
        last_para = None
        for i, ln in enumerate(lines):
            n = i + 1
            code, comment, c, standalone = parts[i]
            if re.match(r'\s*/\*\s*=+', ln):
                banner = True
            m = re.match(r'^[-=]{2,}\s*(\S.*?)\s*[-=]*$', c)
            if m and m.group(1) and not re.fullmatch(r'[-=*/ ]*', m.group(1)):
                section = m.group(1)[:80]
            elif banner and re.match(r'\d+\.\s+\S', c):
                section = c[:80]
                banner = False
            ref = '%s:%d' % (rel, n)
            ctx = (ln + ' ' + section).lower()
            if para[i] is not None:
                last_para = para[i]
            if standalone:
                if c:
                    # a comment on its own line has no subject: what it names is mentioned
                    self.add_text(rel, n, ref, section, comment, 'named-only', False,
                                  re.findall(r'`([^`]+)`', comment), False, ctx)
                continue
            above = last_para if (last_para and last_para[2] == i - 1) else None
            ctext = ' '.join(x for x in (above[0] if above else '', comment.strip()) if x)
            nsd = (bool(NSD_PHRASE.search(comment) and NSD_ROUTES.search(comment)) or
                   (above is not None and above[1])) and not index
            if comment.strip():
                self.add_text(rel, n, ref, section, comment, 'named-only', False,
                              re.findall(r'`([^`]+)`', comment), False, ctx)
            d = (re.match(r'\s*#\s*define\s+(\w+)\s+\(?\s*(-?0[xX][0-9a-fA-F]+|-?\d+)[uUlL]*\b', code) or
                 re.match(r'\s*(\w+)\s*=\s*\(?\s*(-?0[xX][0-9a-fA-F]+|-?\d+)[uUlL]*\)?\s*,?\s*$', code))
            if d:
                name, val = d.group(1), num(re.sub(r'[uUlL]+$', '', d.group(2)))
                # the definition is the subject of the comment above it and the one beside it
                skey = {('id', name), ('hex', val & 0xffffffffffffffff)}
                commented, opn = ('named-only', False) if index else classify(ctext, skey)
                ent = Entry(ctext, commented, frozenset(skey), opn)
                if ctext and not index:
                    self.entries.append(ent)
                h = self.hit(rel, n, ref, section, commented, nsd, True, ctx, ent)
                self.names[name].append(h)
                self.defs[val & 0xffffffffffffffff].append(h)
            else:
                for m in IDENT.finditer(code):
                    nm = m.group(0).rstrip('.')
                    self.names[nm].append(self.hit(rel, n, ref, section, 'named-only', False, True, ctx))
                for plus, h in set(HEXLIT.findall(code)):
                    v = int(h, 16)
                    self.hexes[v].append((self.hit(rel, n, ref, section, 'named-only', False, True, ctx), bool(plus)))

    def read_table(self, rel):
        for n, ln in enumerate(open(os.path.join(REPO, rel), encoding='utf-8', errors='replace'), 1):
            if ln.startswith('#'):
                continue
            for cell in ln.rstrip('\n').split('\t'):
                cell = cell.strip()
                if IDENT.fullmatch(cell):
                    self.names[cell].append(self.hit(rel, n, rel, '', 'named-only', False, True, ''))
                for plus, h in HEXLIT.findall(cell):
                    self.hexes[int(h, 16)].append((self.hit(rel, n, rel, '', 'named-only', False, True, ''), bool(plus)))

    # ---------------------------------------------------------------- queries

    @staticmethod
    def best(hits, demote=None):
        """(status, doc, section, skeleton, templated, open, computes) of the best hit; first in index
        order on a tie. A hit that demote() names earns at most located. open and computes describe the
        entry behind an understood status."""
        top, tst = None, None
        for h in hits:
            st = h.status()
            if demote is not None and RANK[st] > RANK['located'] and demote(h):
                st = 'located'
            if top is None or RANK[st] > RANK[tst] or (RANK[st] == RANK[tst] and h.order < top.order):
                top, tst = h, st
        if tst == 'understood':
            # an entry with no open sub-fact is the better witness of an understood row
            clean = [h for h in hits if h.status() == 'understood' and not (h.ent is not None and h.ent.open)
                     and not (demote is not None and demote(h))]
            if top.ent is not None and top.ent.open and clean:
                top = min(clean, key=lambda h: h.order)
        if top is None:
            return ('undocumented', '', '', '', False, False, False, False)
        full = tst == 'understood' and top.ent is not None and top.level == 'understood'
        return (tst, top.ref, top.section, top.ent.skel if top.ent is not None else '', top.templated(),
                full and top.ent.open, full and top.ent.computes, top.reused() and not top.templated())

    def name_hits(self, name):
        hits = self.names.get(name, [])
        if ambiguous(name):
            hits = [h for h in hits if h.code]
        return hits

    def by_name(self, *names, demote=None):
        hits = []
        for n in names:
            if n:
                hits += self.name_hits(n)
        return self.best(hits, demote)

    def by_file(self, names, accept):
        """Hits for a file row. A mention counts by the path the document wrote, not by the file name:
        accept(path) says whether that path names this file and no other. A mention that is a bare name
        is the path of that name alone."""
        hits = []
        for n in names:
            if n:
                cand = list(self.files.get(n, []))
                if '.' not in n:
                    # an extensionless file name reads like any other name, with the same
                    # rules for names that are also English words
                    cand += self.name_hits(n)
                hits += [h for h in cand if accept(h.path or n)]
        return self.best(hits)

    def value_hits(self, values, files=None, context=None, plus_ok=True, bare=True, absolute=(), exclude=()):
        """Hits for numbers, in the files the table's namespace allows: `files` when the config
        lists them, otherwise every document except those `exclude` names (another table's chapters)."""
        out = []
        for v in values:
            for h in self.defs.get(v & 0xffffffffffffffff, []):
                if in_files(h.file, files) and not (files is None and globs_match(h.file, exclude)) \
                        and h.file.endswith('.h'):
                    out.append(h)
            for h, plus in self.hexes.get(v, []):
                if not in_files(h.file, files) or (files is None and globs_match(h.file, exclude)):
                    continue
                if plus and plus_ok:
                    out.append(h)
                elif bare and (context is None or any(c in h.ctx for c in context)):
                    out.append(h)
        for a in absolute:
            for h, plus in self.hexes.get(a, []):
                out.append(h)
            for h in self.defs.get(a, []):
                out.append(h)
        return out

    def pair_hits(self, values, subj_keys, files=None):
        """Hits for numbers written in an entry whose subject is one of subj_keys, at what the
        entry earns. A command word stored to a register is a pair: the register is the entry's
        subject and the word is the datum it states for it."""
        out = []
        for v in values:
            for h, plus in self.hexes.get(v, []):
                if h.ent is not None and (h.ent.subj & subj_keys) and in_files(h.file, files):
                    out.append(Hit(h.file, h.line, h.ref, h.section, h.ent.level, False, True, h.ctx, h.order, h.ent))
        return out

    def slot_hits(self, index, anchors):
        """Hits from entries whose subject is the number `index` and that name the table's program
        or the handler it points to. A pointer table's row is credited only by an entry of its own."""
        out = []
        for h in self.decs.get(index, []):
            if h.ent is not None and ('dec', index) in h.ent.subj and any(a in h.ent.text for a in anchors if a):
                out.append(h)
        for h, plus in self.hexes.get(index, []):
            if h.ent is not None and ('hex', index) in h.ent.subj and any(a in h.ent.text for a in anchors if a):
                out.append(h)
        return out

    def dec_hits(self, values, files=None, context=None):
        out = []
        for v in values:
            for h in self.decs.get(v, []):
                if in_files(h.file, files) and (context is None or ctx_match(h.ctx, context)):
                    out.append(h)
        return out


def in_files(f, files):
    return files is None or globs_match(f, files)


def strip_generated(lines):
    out, skip = [], False
    for ln in lines:
        if MARK_BEGIN in ln or any(p.search(ln) for p in OLD_MARKS):
            skip = True
        if not skip:
            out.append(ln)
        else:
            out.append('')
        if MARK_END in ln:
            skip = False
    return out


# ===================================================================== inputs

ROOT_MANIFEST = 'scripts/inventory-root.sha256'
SIBLING_PINS = 'scripts/inventory-siblings.json'
CONFLICT = re.compile(r'^(?:<{7}|>{7}|\|{7})(?: |$)', re.M)
SHOWN = 20


def git(path, *args):
    return subprocess.run(['git', '-c', 'safe.directory=*', '-C', path] + list(args), capture_output=True,
                          text=True, encoding='utf-8', errors='replace')


def config_strings(x, key=''):
    """(key, string) for every string of the config outside `binaries`, whose paths scope() resolves."""
    if isinstance(x, str):
        yield key, x
    elif isinstance(x, dict):
        for k, v in x.items():
            if k not in ('binaries', 'scope'):
                yield from config_strings(v, k)
    elif isinstance(x, list):
        for v in x:
            yield from config_strings(v, key)


def doc_files(cfg, base):
    """Paths under `base` of every file the documents index reads, the config and the hand-kept inputs
    (the hand-written audits, the coverage page, the pinned manifests), and the repository files the config
    names."""
    d = cfg['docs']
    out = {'scripts/inventory-config.json', ROOT_MANIFEST, SIBLING_PINS, 'docs/coverage.md',
           'docs/inventory/audits.tsv'}
    for k in ('prose', 'headers', 'tables', 'index', 'dumps'):
        for pat in d.get(k, []):
            out.update(os.path.relpath(p, base) for p in glob.glob(os.path.join(base, pat), recursive=True))
    for key, s in config_strings(cfg):
        if key in ('file', 'path') and '{tmp}' not in s:
            out.add(s)
    return sorted(p for p in out if os.path.isfile(os.path.join(base, p)))


def generated_span(text):
    """(start, end) of the generated block of the coverage page, first begin marker to last end marker."""
    i, j = text.find(MARK_BEGIN), text.rfind(MARK_END)
    if i < 0:
        i = next((m.start() for m in (p.search(text) for p in OLD_MARKS) if m), -1)
    return (i, j + len(MARK_END)) if i >= 0 and j > i else None


def conflict_problems(base, rels, label):
    """Problems for files with unresolved merge-conflict markers. The generated block of the coverage page
    is rewritten whole, so markers inside it are not an input."""
    out = []
    for rel in rels:
        text = open(os.path.join(base, rel), encoding='utf-8', errors='replace').read()
        if rel == 'docs/coverage.md':
            span = generated_span(text)
            if span:
                text = text[:span[0]] + text[span[1]:]
        m = CONFLICT.search(text)
        if m:
            out.append('%s: %s has an unresolved merge conflict (line %d); resolve it first, and regenerate '
                       'tables instead of merging them' % (label, rel, text.count('\n', 0, m.start()) + 1))
    return out


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def root_check(cfg, docs, update, problems):
    """Check every file the run reads from root/ against ROOT_MANIFEST (`sha256  path` lines, sorted): the
    files of the configured binaries, the root files the config names, and any indexed document that is a
    link into root/. Returns (manifest hash, new manifest text when updating, file count); with `update`
    the manifest is the files as they are, and build() writes it only if nothing else is wrong. The manifest, not the checkout, then says what
    the tables were made from, so a symlinked root/, a copy of it and a shared checkout agree, and a file
    that is missing or differs fails the run."""
    root = os.path.join(REPO, 'root')
    real_root = os.path.realpath(root)
    need = {rel: real for rel, real, g in scope_files(cfg)}
    for key, s in config_strings(cfg):
        s = s.replace('{root}/', 'root/')
        if s.startswith('root/') and '{tmp}' not in s:
            hits = [h for h in glob.glob(os.path.join(root, s[5:]), recursive=True) if os.path.isfile(h)]
            if not hits:
                problems.append('root/%s is named by the config and is missing (or a dangling link)' % s[5:])
            for h in hits:
                need[os.path.relpath(h, root)] = h
    for rel in docs:
        real = os.path.realpath(os.path.join(REPO, rel))
        if real.startswith(real_root + os.sep) and os.path.isfile(real):
            need[os.path.relpath(real, real_root)] = real
    have = {rel: file_sha256(real) for rel, real in sorted(need.items())}
    mpath = os.path.join(REPO, ROOT_MANIFEST)
    if update:
        return None, ''.join('%s  %s\n' % (h, rel) for rel, h in sorted(have.items())), len(have)
    if not os.path.isfile(mpath):
        problems.append('%s is missing (write it from a complete root/ with --update-root-manifest)' % ROOT_MANIFEST)
        return '', None, 0
    want = {}
    for ln in open(mpath, encoding='utf-8').read().split('\n'):
        if ln:
            h, rel = ln.split('  ', 1)
            want[rel] = h
    def shown(label, items):
        if items:
            more = ' (and %d more)' % (len(items) - SHOWN) if len(items) > SHOWN else ''
            problems.append('root/ %s: %s%s' % (label, ', '.join(items[:SHOWN]), more))
    shown('lacks files the manifest lists', sorted(set(want) - set(have)))
    shown('has files in scope that the manifest does not list', sorted(set(have) - set(want)))
    shown('has files whose sha256 differs from the manifest', sorted(r for r in have if r in want and have[r] != want[r]))
    return hashlib.sha256(open(mpath, 'rb').read()).hexdigest(), None, len(want)


# ===================================================================== scope

def unpack_ar(data):
    if data[:8] != b'!<arch>\n':
        return []
    names, pos, mem = b'', 8, []
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode('latin1').strip()
        size = int(hdr[48:58])
        body = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
        if name == '//':
            names = body
            continue
        if name in ('/', '/SYM64/', '__.SYMDEF', '__.SYMDEF SORTED'):
            continue
        if name.startswith('/') and name[1:].isdigit():
            end = names.index(b'\n', int(name[1:]))
            name = names[int(name[1:]):end].decode('latin1')
        elif name.startswith('#1/'):
            k = int(name[3:])
            name, body = body[:k].decode('latin1').rstrip('\0'), body[k:]
        mem.append((name.rstrip('/'), body))
    return mem


def scope_files(cfg):
    """[(path under root/, real path, group)] for every file the config puts in scope, sorted by path."""
    root = os.path.join(REPO, 'root')
    excl = cfg.get('exclude', [])
    files = []
    claimed = set()
    for g in cfg['binaries']:
        for pat in g['paths']:
            hits = sorted(glob.glob(os.path.join(root, pat), recursive=True))
            for p in hits:
                cands = []
                if os.path.isdir(p):
                    for dp, dn, fn in os.walk(p):
                        dn.sort()
                        for f in sorted(fn):
                            cands.append(os.path.join(dp, f))
                else:
                    cands.append(p)
                for c in cands:
                    rel = os.path.relpath(c, root)
                    if rel in claimed or globs_match(rel, excl) or not os.path.isfile(c):
                        continue
                    claimed.add(rel)
                    files.append((rel, c, g))
    files.sort(key=lambda x: x[0])
    return files


def apply_scope(cfg, imgs, rows, touch):
    """Mark each function row out of scope when a rule of the config's `scope` list names it.

    A rule is {"binaries": [globs], "names": [exact names], "patterns": [regexes], "reason": "one line"}, and
    `binaries` matches a binary's label, its path or the label of a byte-identical copy. Only the rule decides:
    nothing is inferred from the documents. Every rule needs a reason and at least one name or pattern, and
    every name and pattern has to match a function of its binaries, so a stale rule fails the run. A rule that
    would exclude a function that reaches a register window, a token or an ioctl (the access sites the script
    resolved, an access it could not resolve, an ioctl handler) fails the run too: such a function stays in
    scope. Returns (rule report, problems); a row gets `scope` = `in` or `out:<rule number>`."""
    rules = cfg.get('scope', [])
    problems, report = [], []
    names_of = {}
    for img in imgs:
        for lab in [img['label']] + img['copies']:
            names_of[lab] = img
    by_label = collections.defaultdict(list)
    for r in rows:
        by_label[r['binary']].append(r)
    for r in rows:
        r['scope'] = 'in'
    for n, rule in enumerate(rules, 1):
        where = 'scope rule %d' % n
        if not str(rule.get('reason', '')).strip():
            problems.append('%s has no reason' % where)
        names, pats = set(rule.get('names', [])), rule.get('patterns', [])
        if not names and not pats:
            problems.append('%s lists no names and no patterns' % where)
        if not rule.get('binaries'):
            problems.append('%s names no binaries' % where)
            continue
        cands = [r for r in rows if r['scope'] == 'in' and any(
            globs_match(x, rule['binaries']) for x in [r['binary'], names_of[r['binary']]['path']] +
            names_of[r['binary']]['copies'])]
        hit = [r for r in cands if r['name'] in names or any(re.fullmatch(p, r['name']) for p in pats)]
        for nm in sorted(names - {r['name'] for r in hit}):
            problems.append('%s: name %s matches no function of its binaries' % (where, nm))
        for p in pats:
            if not any(re.fullmatch(p, r['name']) for r in hit):
                problems.append('%s: pattern %s matches no function of its binaries' % (where, p))
        for r in hit:
            if (r['binary'], r['name']) in touch:
                problems.append('%s excludes %s in %s, which reaches a register window, a token or an ioctl' %
                                (where, r['name'], r['binary']))
            r['scope'] = 'out:%d' % n
            r['_out'] = True
        report.append({'rule': n, 'binaries': ', '.join(rule['binaries']), 'rows': len(hit),
                       'reason': str(rule.get('reason', '')).strip()})
    return report, problems


def scope(cfg):
    """[(label, member, group, data)] for every file in scope, plus the copies map."""
    files = scope_files(cfg)
    images = []
    by_sha = {}
    for rel, real, g in files:
        data = open(real, 'rb').read()
        if data[:8] == b'!<arch>\n':
            want = g.get('members')
            for name, body in unpack_ar(data):
                if want and not any(fnmatch.fnmatch(name, w) for w in want):
                    continue
                images.append(('%s(%s)' % (rel, name), rel, name, g, body))
        else:
            images.append((rel, rel, '', g, data))
    out = []
    for label, path, member, g, data in images:
        h = hashlib.sha256(data).hexdigest()
        if h in by_sha:
            by_sha[h]['copies'].append(label)
            continue
        e = {'label': label, 'path': path, 'member': member, 'group': g, 'data': data, 'sha': h, 'copies': [],
             'size': len(data)}
        by_sha[h] = e
        out.append(e)
    return out


# ===================================================================== ELF symbols

def elf_of(data):
    from elftools.elf.elffile import ELFFile
    return ELFFile(io.BytesIO(data))


def abi_of(elf):
    if elf.elfclass == 64:
        return 'n64'
    return 'n32' if elf.header['e_flags'] & 0x20 else 'o32'


def kind_of(data, elf):
    if elf is None:
        return 'data'
    t = elf.header['e_type']
    return {'ET_REL': 'object', 'ET_EXEC': 'executable', 'ET_DYN': 'shared-object'}.get(t, 'elf')


def mdebug_procs(elf, data):
    sec = elf.get_section_by_name('.mdebug')
    if sec is None:
        return []
    e = '<' if elf.little_endian else '>'
    d = sec.data()
    if len(d) < 96:
        return []
    h = struct.unpack(e + '2H23I', d[:96])
    cbpd, cbsym, cbss, ifd, cbfd = h[8], h[10], h[16], h[19], h[20]
    out = []
    try:
        for i in range(ifd):
            o = cbfd + 72 * i
            fd = struct.unpack(e + '10I2H', data[o:o + 44])
            issbase, isymbase, ipdfirst, cpd = fd[2], fd[4], fd[10], fd[11]
            for p in range(ipdfirst, ipdfirst + cpd):
                po = cbpd + 52 * p
                adr, isym = struct.unpack(e + 'Ii', data[po:po + 8])
                so = cbsym + 12 * (isymbase + isym)
                iss, value = struct.unpack(e + 'iI', data[so:so + 8])
                a = cbss + issbase + iss
                b = data.index(b'\0', a)
                name = data[a:b].decode('latin1')
                if name:
                    out.append((name, value))
    except (struct.error, ValueError):
        pass
    return out


def debug_funcnames(elf):
    sec = elf.get_section_by_name('.debug_funcnames')
    if sec is None:
        return []
    data = sec.data()
    names, pos = [], 0
    while pos + 14 <= len(data):
        ln, = struct.unpack('>I', data[pos:pos + 4])
        if ln == 0 or ln > len(data):
            break
        end = pos + 4 + ln
        p = pos + 14
        while p + 4 < end:
            off, = struct.unpack('>I', data[p:p + 4])
            if off == 0:
                break
            q = data.index(b'\0', p + 4)
            names.append(data[p + 4:q].decode('latin1'))
            p = q + 1
        pos = end
    return names


def dwarf_subprograms(path):
    dd = shutil.which(os.environ.get('DWARFDUMP', 'dwarfdump'))
    if not dd:
        return []
    txt = subprocess.run([dd, '-i', path], capture_output=True, text=True, encoding='utf-8', errors='replace').stdout
    out, cur = [], None
    for line in txt.splitlines():
        if 'DW_TAG_' in line:
            if cur and cur.get('name') and 'lo' in cur:
                out.append((cur['name'], cur['lo'], cur.get('hi', 0)))
            cur = {} if 'DW_TAG_subprogram' in line else None
            continue
        if cur is None:
            continue
        m = re.match(r'\s+DW_AT_(name|low_pc|high_pc)\s+(\S+)', line)
        if m:
            k, v = m.groups()
            if k == 'name':
                cur['name'] = line.split(None, 1)[1].strip()
            elif k == 'low_pc':
                cur['lo'] = int(v, 16)
            else:
                cur['hi'] = int(v, 16) if v.startswith('0x') else 0
    if cur and cur.get('name') and 'lo' in cur:
        out.append((cur['name'], cur['lo'], cur.get('hi', 0)))
    return out


def functions_of(img, elf, path):
    """({name: [elf_section, address, size, sources, code_sha]}, info) for one image. code_sha is the
    first 12 hex digits of the hash of the function's bytes, empty when they are not known.

    A function's address comes from one source, chosen for the binary: the ELF symbol tables (.symtab,
    .dynsym) first, then the .mdebug procedure table for names the symbol tables lack, and DWARF only for
    names neither has, and only when DWARF can be trusted. DWARF is not trusted in a binary where any
    function it names sits at an address the symbol tables do not give it (the library was relinked after
    the debug information was written): its addresses are then dropped and its names kept without one.
    info holds `address_source` (which sources gave this binary's addresses), `multi_unit` (names with
    several definitions at different addresses, one per compilation unit) and `shared_address` (names
    that share an address with another name)."""
    g = img['group']
    if g.get('string_names'):
        names = sorted({m.decode('latin1') for m in re.findall(g['string_names'].encode(), img['data'])})
        return {n: ['', 0, 0, {'strings'}, ''] for n in names}, {'address_source': 'strings', 'multi_unit': set(),
                                                                 'shared_address': set()}
    if elf is None:
        return {}, {'address_source': '', 'multi_unit': set(), 'shared_address': set()}
    funcs = {}
    execsec = {i for i, s in enumerate(elf.iter_sections()) if s['sh_flags'] & 4}

    def secname(idx):
        if isinstance(idx, int) and idx < elf.num_sections():
            return elf.get_section(idx).name
        return ''

    # every definition each source gives: source -> name -> [(address, size, elf_section)]
    defs = collections.defaultdict(lambda: collections.defaultdict(list))
    for sn, src in (('.symtab', 'symtab'), ('.dynsym', 'dynsym')):
        sec = elf.get_section_by_name(sn)
        if sec is None or not hasattr(sec, 'iter_symbols'):
            continue
        for s in sec.iter_symbols():
            t = s['st_info']['type']
            if not s.name or s['st_shndx'] in ('SHN_UNDEF', 'SHN_ABS', 'SHN_COMMON'):
                continue
            if t == 'STT_FUNC' or (t == 'STT_NOTYPE' and s['st_shndx'] in execsec and
                                   s['st_info']['bind'] == 'STB_GLOBAL'):
                defs[src][s.name].append((s['st_value'], s['st_size'], secname(s['st_shndx'])))
    for name, addr in mdebug_procs(elf, img['data']):
        defs['mdebug'][name].append((addr, 0, '.text'))
    for name in debug_funcnames(elf):
        defs['funcnames'][name].append((None, 0, ''))
    if elf.get_section_by_name('.debug_info') is not None:
        for name, lo, hi in dwarf_subprograms(path):
            if not lo and elf['e_type'] != 'ET_REL':
                continue
            defs['dwarf'][name].append((lo, (hi - lo) if hi > lo else 0, '.text'))
    symbols = collections.defaultdict(list)
    for src in ('symtab', 'dynsym'):
        for name, ds in defs[src].items():
            symbols[name] += ds
    sym_addrs = {n: {a for a, _, _ in ds if a is not None} for n, ds in symbols.items()}
    stale = any(da and sym_addrs.get(n) and not da <= sym_addrs[n]
                for n, da in ((n, {a for a, _, _ in ds if a is not None}) for n, ds in defs['dwarf'].items()))
    names = set()
    for src in defs:
        names |= set(defs[src])
    used, multi = set(), set()
    for name in names:
        tiers = [('symtab' if name in defs['symtab'] else 'dynsym', symbols.get(name, [])),
                 ('mdebug', defs['mdebug'].get(name, [])), ('dwarf', [] if stale else defs['dwarf'].get(name, []))]
        src, ds = next(((sr, [d for d in dd if d[0] is not None]) for sr, dd in tiers if any(d[0] is not None for d in dd)), ('', []))
        srcs = {sr for sr in defs if name in defs[sr] and not (stale and sr == 'dwarf' and ds)}
        if ds:
            used.add(src)
            # the lowest definition, as the one row of the name; several at different addresses means
            # the name is defined in more than one compilation unit
            addr, size, sec = min(ds, key=lambda d: (d[0], d[1]))
            size = size or next((d[1] for d in sorted(ds) if d[0] == addr and d[1]), 0)
            if len({d[0] for d in ds}) > 1:
                multi.add(name)
        else:
            addr, size, sec = None, 0, ''
        funcs[name] = [sec, addr, size, srcs]
    at = collections.defaultdict(set)
    for name, e in funcs.items():
        if e[1] is not None:
            at[(e[0], e[1])].add(name)
    shared = {n for ns in at.values() if len(ns) > 1 for n in ns}
    label = '+'.join(x for x in ('symtab', 'dynsym', 'mdebug', 'dwarf') if x in used) or 'none'
    if stale:
        label += ' (dwarf addresses stale, dropped)'
    # a missing size runs to the next function of the same section
    by = collections.defaultdict(list)
    for name, e in funcs.items():
        if e[1] is not None:
            by[e[0]].append(e[1])
    ends = {}
    for sec in by:
        by[sec] = sorted(set(by[sec]))
        s = elf.get_section_by_name(sec) if sec else None
        ends[sec] = (s['sh_addr'] + s['sh_size']) if s is not None else None
    for name, e in funcs.items():
        if not e[2] and e[1] is not None:
            a = by[e[0]]
            i = bisect.bisect_right(a, e[1])
            nxt = a[i] if i < len(a) else ends.get(e[0])
            if nxt and nxt > e[1]:
                e[2] = nxt - e[1]
    secdata = {}
    segs = None
    for name, e in funcs.items():
        sha = ''
        sec = elf.get_section_by_name(e[0]) if e[0] else None
        if sec is not None and e[2] and sec['sh_type'] != 'SHT_NOBITS':
            if e[0] not in secdata:
                secdata[e[0]] = sec.data()
            off = e[1] - sec['sh_addr']
            if 0 <= off and off + e[2] <= len(secdata[e[0]]):
                sha = hashlib.sha256(secdata[e[0]][off:off + e[2]]).hexdigest()[:12]
        elif sec is None and e[1] is not None and e[2]:
            # no section headers: find the loadable segment that holds the address
            if segs is None:
                segs = [(sg['p_vaddr'], sg['p_filesz'], sg.data()) for sg in elf.iter_segments()
                        if sg['p_type'] == 'PT_LOAD']
            for va, fsz, data in segs:
                if va <= e[1] and e[1] + e[2] <= va + fsz:
                    sha = hashlib.sha256(data[e[1] - va:e[1] - va + e[2]]).hexdigest()[:12]
                    break
        e.append(sha)
    return funcs, {'address_source': label, 'multi_unit': multi, 'shared_address': shared}


# ===================================================================== disassembly

INSN = re.compile(r'^\s*([0-9a-f]+):\t(\S+)\t?(.*)$')
FUNC = re.compile(r'^([0-9a-f]+) <(.+)>:$')
RELOC = re.compile(r'^\s*([0-9a-f]+): (R_MIPS\w*)\s+(\S+)\s*$')
REG = re.compile(r'^\$(\d+)$')
MEMOP = re.compile(r'^(-?(?:0x)?[0-9a-fA-F]+)\(\$(\d+)\)$')
LOADS = {'lb': 1, 'lbu': 1, 'lh': 2, 'lhu': 2, 'lw': 4, 'lwu': 4, 'ld': 8, 'll': 4, 'lld': 8,
         'lwl': 4, 'lwr': 4, 'ldl': 8, 'ldr': 8, 'lwc1': 4, 'ldc1': 8, 'lwc2': 4, 'ldc2': 8}
STORES = {'sb': 1, 'sh': 2, 'sw': 4, 'sd': 8, 'sc': 4, 'scd': 8, 'swl': 4, 'swr': 4, 'sdl': 8, 'sdr': 8,
          'swc1': 4, 'sdc1': 8, 'swc2': 4, 'sdc2': 8}
FPMEM = {'lwc1', 'ldc1', 'lwc2', 'ldc2'}
CALLS = {'jal', 'jalr', 'bal', 'bgezal', 'bltzal', 'bgezall', 'bltzall', 'jalx'}
LIKELY = {'beql', 'bnel', 'blezl', 'bgtzl', 'bltzl', 'bgezl', 'bc1tl', 'bc1fl', 'bc0tl', 'bc0fl',
          'bc2tl', 'bc2fl', 'bgezall', 'bltzall'}
NO_DEST = set('''mult multu dmult dmultu div divu ddiv ddivu madd maddu msub msubu mtc0 dmtc0 mtc1 dmtc1 ctc1
mtc2 dmtc2 ctc2 mthi mtlo nop sync break syscall cache teq tne tlt tltu tge tgeu teqi tnei tlti tltiu tgei
tgeiu tlbwi tlbwr tlbp tlbr eret pref prefx ssnop deret wait c.f c.un c.eq c.ueq c.olt c.ult c.ole c.ule
c.sf c.ngle c.seq c.ngl c.lt c.nge c.le c.ngt'''.split())
CALLER_SAVED = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 31]
ARG_REGS = (4, 5, 6, 7, 8, 9, 10, 11)


def is_branch(mn):
    return mn in ('j', 'jr', 'jal', 'jalr', 'jalx', 'jr.hb', 'jalr.hb') or \
        (mn.startswith('b') and mn not in ('break',))


def run_objdump(path):
    """[(name, [(addr, mnemonic, [operands], reloc)])] in address order."""
    out = subprocess.run([toolchain_objdump(), '-d', '-r', '-w', '-M', 'no-aliases,gpr-names=numeric',
                          '--no-show-raw-insn', path],
                         capture_output=True, text=True, encoding='utf-8', errors='replace').stdout
    funcs, cur = [], None
    last = None
    for ln in out.split('\n'):
        m = FUNC.match(ln)
        if m:
            cur = [m.group(2), []]
            funcs.append(cur)
            last = None
            continue
        m = RELOC.match(ln)
        if m:
            if last is not None and last[3] is None and m.group(2) != 'R_MIPS_NONE' and \
                    int(m.group(1), 16) == last[0]:
                last[3] = parse_reloc(m.group(2), m.group(3))
            continue
        m = INSN.match(ln)
        if not m:
            continue
        rest = m.group(3).split('\t')
        opstr = rest[0]
        sym = None
        mm = re.search(r'<([^>+]+)(?:\+0x[0-9a-f]+)?>', opstr)
        if mm:
            sym = mm.group(1)
        opstr = re.sub(r'\s*<[^>]*>', '', opstr).split('#')[0].strip()
        rel = None
        if len(rest) >= 3:
            r = re.match(r'\s*[0-9a-f]+: (R_MIPS\w*)$', rest[1])
            if r and r.group(1) != 'R_MIPS_NONE':
                rel = parse_reloc(r.group(1), rest[2].strip())
        ops = [o.strip() for o in opstr.split(',')] if opstr else []
        last = [int(m.group(1), 16), m.group(2), ops, rel, sym]
        if cur is None:
            cur = ['', []]
            funcs.append(cur)
        cur[1].append(last)
    return funcs


def split_runs(runs, table):
    """objdump's runs cut at the function boundaries of the image's function table ({name: [section,
    address, size, ...]}, from functions_of). objdump labels only the symbols it reads, so in a stripped
    image a static routine's code runs on under the last exported label before it, and its register
    accesses would be credited to that routine. A run is cut where a known function starts and where the
    labelled function's size ends; code past the end that no table names becomes a run of its own, named
    by its address (`routine@0x...`). A boundary that a branch of the run reaches is not cut: the code past
    it is a tail the routine shares and enters with its registers live, as compilers emit for a common
    slow path, so its accesses keep the routine's state."""
    starts, ends = {}, {}
    for name, e in sorted(table.items()):
        if e[1] is not None:
            starts.setdefault(e[1], name)
            if e[2]:
                ends[name] = e[1] + e[2]
    out = []
    for name, insns in runs:
        cur = [name, []]
        end = ends.get(name) if insns and table.get(name, [None, None])[1] == insns[0][0] else None
        reached = {branch_target(i) for i in insns if is_branch(i[1]) and i[1] not in CALLS}
        for ins in insns:
            a = ins[0]
            if cur[1] and a in reached and (a in starts or (end is not None and a >= end)):
                end = ends.get(starts[a]) if a in starts else None
            elif cur[1] and a in starts and starts[a] != cur[0]:
                out.append(cur)
                cur = [starts[a], []]
                end = ends.get(cur[0])
            elif cur[1] and end is not None and a >= end:
                out.append(cur)
                cur = ['routine@0x%x' % a, []]
                end = None
            cur[1].append(ins)
        out.append(cur)
    return out


def parse_reloc(rtype, target):
    m = re.match(r'^(.*?)(?:([+-])0x([0-9a-f]+))?$', target)
    name = m.group(1)
    add = int(m.group(3), 16) * (-1 if m.group(2) == '-' else 1) if m.group(3) else 0
    return (rtype, name, add)


class ImageInfo:
    """What the replay needs from the ELF image: GOT, stubs, constant memory, gp0."""

    def __init__(self, elf):
        self.elf = elf
        self.rel = elf.header['e_type'] == 'ET_REL'
        self.got_names = {}
        self.got_local = {}
        self.stubs = {}
        self.ro = []        # (lo, hi, data) read-only sections by address (linked images)
        self.secdata = {}   # name -> data (relocatable images)
        self.gp0 = 0
        self.gsz = 8 if elf.elfclass == 64 else 4
        try:
            self.load()
        except Exception:
            pass

    def load(self):
        e = self.elf
        for s in e.iter_sections():
            name = s.name
            ro = (s['sh_flags'] & 2) and not (s['sh_flags'] & 1) and s['sh_type'] == 'SHT_PROGBITS' \
                and not (s['sh_flags'] & 4)
            if ro:
                if self.rel:
                    self.secdata[name] = s.data()
                elif s['sh_addr']:
                    self.ro.append((s['sh_addr'], s['sh_addr'] + s['sh_size'], s.data()))
        self.ro.sort()
        if self.rel:
            ri = e.get_section_by_name('.reginfo')
            if ri is not None and len(ri.data()) >= 24:
                self.gp0 = struct.unpack('>i', ri.data()[20:24])[0]
            op = e.get_section_by_name('.MIPS.options')
            if op is not None:
                d = op.data()
                p = 0
                while p + 8 <= len(d):
                    kind, size = d[p], d[p + 1]
                    if size == 0:
                        break
                    if kind == 1:
                        if e.elfclass == 64 and size >= 40:
                            self.gp0 = struct.unpack('>q', d[p + 32:p + 40])[0]
                        elif size >= 32:
                            self.gp0 = struct.unpack('>i', d[p + 28:p + 32])[0]
                    p += size
            return
        dyn = e.get_section_by_name('.dynamic')
        dsym = e.get_section_by_name('.dynsym')
        if dyn is None or dsym is None:
            return
        tags = {}
        for t in dyn.iter_tags():
            tags[t.entry.d_tag] = t.entry.d_val
        names = [s.name for s in dsym.iter_symbols()]
        if 'DT_PLTGOT' in tags and 'DT_MIPS_LOCAL_GOTNO' in tags and 'DT_MIPS_GOTSYM' in tags:
            gotaddr, local, gotsym = tags['DT_PLTGOT'], tags['DT_MIPS_LOCAL_GOTNO'], tags['DT_MIPS_GOTSYM']
            gotdata = None
            for s in e.iter_sections():
                if s['sh_addr'] == gotaddr and s['sh_type'] == 'SHT_PROGBITS':
                    gotdata = s.data()
            fmt = '>Q' if self.gsz == 8 else '>I'
            n = (len(gotdata) // self.gsz) if gotdata else 0
            for i in range(n):
                off = i * self.gsz - 0x7ff0
                if i >= local:
                    k = gotsym + i - local
                    if k < len(names):
                        self.got_names[off] = names[k]
                else:
                    self.got_local[off] = struct.unpack(fmt, gotdata[i * self.gsz:(i + 1) * self.gsz])[0]
        sec = e.get_section_by_name('.MIPS.stubs')
        if sec is not None:
            d = sec.data()
            base = sec['sh_addr']
            for off in range(0, len(d) - 3, 4):
                w, = struct.unpack('>I', d[off:off + 4])
                if (w >> 16) in (0x2418, 0x6418) and (w & 0xffff) < len(names):
                    self.stubs[base + off - 12] = names[w & 0xffff]

    def read(self, addr, width):
        i = bisect.bisect_right(self.ro, (addr, float('inf'), b'')) - 1
        if i >= 0:
            lo, hi, d = self.ro[i]
            if lo <= addr and addr + width <= hi:
                return int.from_bytes(d[addr - lo:addr - lo + width], 'big', signed=True)
        return None

    def read_sec(self, name, off, width):
        d = self.secdata.get(name)
        if d is not None and 0 <= off and off + width <= len(d):
            return int.from_bytes(d[off:off + width], 'big', signed=True)
        return None


# ===================================================================== replay

class Model:
    """The family's windows, base-pointer sources, sinks and decoders, from the config."""

    def __init__(self, cfg):
        self.windows = {}
        for w in cfg.get('windows', []):
            w = dict(w)
            w['size'] = num(w.get('size', 1 << 40))
            w['regions'] = [dict(r, lo=num(r['lo']), hi=num(r['hi'])) for r in w.get('regions', [])]
            self.windows[w['name']] = w
        self.bases = cfg.get('bases', [])
        self.accessors = cfg.get('accessors', [])
        self.aliases = [dict(a, lo=num(a['lo']), hi=num(a['hi']), bit=num(a['bit']))
                        for a in cfg.get('aliases', [])]
        self.decoders = cfg.get('decoders', [])
        tk = cfg.get('tokens', {})
        self.sinks = [s for s in tk.get('sources', []) if s['type'] == 'stores']
        self.families = tk.get('families', [])
        io_ = cfg.get('ioctls', {})
        self.ioctl_send = io_.get('send_functions', [])
        self.ioctl_ranges = [(num(a), num(b)) for a, b in io_.get('ranges', [])]
        self.ioctl_const = io_.get('constants')
        self.ioctl_compare = [d for d in io_.get('dispatchers', []) if d['type'] == 'compare']

    def region(self, win, off):
        w = self.windows[win]
        for r in w['regions']:
            if r['lo'] <= off < r['hi']:
                return r['name']
        return win

    def family(self, w):
        for f in self.families:
            if all(cond_ok(c, w) for c in f['when']):
                return f
        return None


def cond_ok(c, w):
    v = (w >> c.get('shift', 0)) & num(c.get('mask', '0xffffffff'))
    if 'in' in c:
        return v in [num(x) for x in c['in']]
    if 'range' in c:
        return num(c['range'][0]) <= v <= num(c['range'][1])
    return v == num(c['eq'])


def translate(cfgb, v):
    """Physical address of a kernel-segment or XKPHYS constant, if the rule asks for it."""
    v &= (1 << 64) - 1
    if not cfgb.get('translate'):
        return v
    hi32 = v >> 32
    if hi32 == 0xffffffff and (v & 0xe0000000) in (0x80000000, 0xa0000000):
        return v & 0x1fffffff
    if v >> 62 == 2:
        return v & 0xffffffffff
    if hi32 == 0 and (v & 0xe0000000) in (0x80000000, 0xa0000000):
        return v & 0x1fffffff
    return v


class Unit:
    """Replay of every function of one file in scope (an archive's members together)."""

    def __init__(self, model, cfg, images):
        self.m = model
        self.cfg = cfg
        self.images = images
        self.out_mmio = {}
        self.unresolved = collections.Counter()
        self.sites = collections.Counter()
        self.tokens = {}
        self.ioctl = {}
        self.touch = set()
        self.recording = False
        self.mode = 'record'
        self.shadow = {}

    # ------------------------------------------------------------ helpers

    def applies(self, rule, img, func=None):
        bins = rule.get('binaries')
        if bins and not (globs_match(img['label'], bins) or globs_match(img['path'], bins)):
            return False
        fns = rule.get('functions')
        if fns and func is not None and not any(re.fullmatch(f, func) for f in fns):
            return False
        return True

    def run(self):
        # parse every image once
        self.code = []
        for img in self.images:
            if img['elf'] is None or img['group'].get('scan') is False:
                continue
            info = ImageInfo(img['elf'])
            funcs = split_runs(run_objdump(img['tmp']), img.get('functab', {}))
            self.code.append((img, info, funcs))
        # the routine each run starts, by address: a call into a routine objdump did not label names the
        # routine, not the label before it
        self.entry_names = {id(img): {insns[0][0]: name for name, insns in funcs if name and insns}
                            for img, info, funcs in self.code}
        defined = collections.defaultdict(list)
        for k, (img, info, funcs) in enumerate(self.code):
            for j, (name, insns) in enumerate(funcs):
                if name:
                    defined[name].append((k, j))
        self.defined = defined
        seeds_arg, seeds_ret = {}, {}
        for p in range(4):
            self.calls = collections.defaultdict(list)
            self.rets = collections.defaultdict(list)
            self.reset()
            for k, (img, info, funcs) in enumerate(self.code):
                for j, (name, insns) in enumerate(funcs):
                    self.replay(img, info, name, insns, seeds_arg.get((k, j), {}), seeds_ret)
            na, nr = self.derive_seeds()
            if na == seeds_arg and nr == seeds_ret:
                break
            seeds_arg, seeds_ret = na, nr
        return self

    def reset(self):
        self.out_mmio, self.tokens, self.ioctl, self.touch = {}, {}, {}, set()
        self.unresolved, self.sites = collections.Counter(), collections.Counter()

    def derive_seeds(self):
        na = {}
        for callee, sites in sorted(self.calls.items()):
            targets = self.defined.get(callee)
            if not targets:
                continue
            seed = {}
            for r in ARG_REGS:
                vals = [s.get(r) for s in sites]
                if vals and all(v and v[0] == 'w' for v in vals) and len({v[1] for v in vals}) == 1:
                    offs = {v[2] for v in vals}
                    seed[r] = ('w', vals[0][1], offs.pop() if len(offs) == 1 else None, 'caller argument')
            if seed:
                for t in targets:
                    na[t] = seed
        nr = {}
        for name, vals in sorted(self.rets.items()):
            if vals and all(v and v[0] == 'w' for v in vals) and len({v[1] for v in vals}) == 1:
                offs = {v[2] for v in vals}
                nr[name] = ('w', vals[0][1], offs.pop() if len(offs) == 1 else None, 'callee return')
        return na, nr

    # ------------------------------------------------------------ the replay

    def replay(self, img, info, fname, insns, seed, seeds_ret):
        """Data flow over the function's basic blocks to a fixed point, then one recording pass.
        A register or stack slot keeps a value at a join only when every path into it agrees."""
        m = self.m
        entry = {}
        for b in m.bases:
            if b['type'] == 'argument' and self.applies(b, img) and re.fullmatch(b['function'], fname or ''):
                entry[int(b['reg'])] = ('w', b['window'], num(b.get('offset', 0)), b.get('label', 'argument'))
        entry.update(seed)
        self.img, self.info, self.fname = img, info, fname
        self.compare_rules = [d for d in m.ioctl_compare
                              if self.applies(d, img) and re.search(d['functions'], fname or '')]
        n = len(insns)
        if not n:
            return
        index = {ins[0]: i for i, ins in enumerate(insns)}
        leaders = {0}
        for i, ins in enumerate(insns):
            mn = ins[1]
            if is_branch(mn) and mn not in CALLS:
                leaders.add(i + 2)
                t = branch_target(ins)
                if t is not None and t in index:
                    leaders.add(index[t])
        starts = sorted(x for x in leaders if x < n)
        blocks = []
        for k, st in enumerate(starts):
            blocks.append((st, starts[k + 1] if k + 1 < len(starts) else n))
        bindex = {st: k for k, (st, en) in enumerate(blocks)}
        preds = collections.defaultdict(int)
        for k, (st, en) in enumerate(blocks):
            for succ, _ in self.block_succ(insns, index, bindex, st, en, None):
                preds[succ] += 1
        IN = [None] * len(blocks)
        IN[0] = dict(entry)
        FIRST = [None] * len(blocks)
        FIRST[0] = dict(entry)
        for k in range(1, len(blocks)):
            st, en = blocks[k]
            if not preds[k] and not (en - st == 1 and not is_branch(insns[st][1])):
                # unreached, so a switch target or dead code. A lone instruction nothing reaches is
                # a nop pad or a copy of a branch's delay slot placed before its target; it would
                # feed an empty state into the block after it and lose every window base there
                IN[k] = {}
        self.recording = False
        work = sorted(k for k in range(len(blocks)) if IN[k] is not None)
        queued = set(work)
        rounds = 0
        while work and rounds < 50 * len(blocks):
            rounds += 1
            k = work.pop(0)
            queued.discard(k)
            st, en = blocks[k]
            for succ, state in self.block_succ(insns, index, bindex, st, en, dict(IN[k]), seeds_ret):
                old = IN[succ]
                if old is None:
                    new = dict(state)
                    FIRST[succ] = dict(state)
                else:
                    new = {}
                    for q, v in old.items():
                        mv = meet(v, state.get(q))
                        if mv is not None:
                            new[q] = mv
                if new != old:
                    IN[succ] = new
                    if succ not in queued:
                        queued.add(succ)
                        bisect.insort(work, succ)
        # The first pass into a loop gives the offsets of its first iteration: an access the
        # converged state cannot place uses them, and still counts as unresolved.
        self.recording = True
        self.mode = 'shadow'
        self.shadow = collections.defaultdict(list)
        for k, (st, en) in enumerate(blocks):
            if FIRST[k] is not None and FIRST[k] != IN[k]:
                for _ in self.block_succ(insns, index, bindex, st, en, dict(FIRST[k]), seeds_ret):
                    pass
        self.mode = 'record'
        self.first_store = set()
        for k, (st, en) in enumerate(blocks):
            for _ in self.block_succ(insns, index, bindex, st, en, dict(IN[k] or {}), seeds_ret):
                pass

    def block_succ(self, insns, index, bindex, st, en, regs, seeds_ret=None):
        """Run one block; yield (successor block, state on that edge). With regs None, only
        the successors."""
        i = st
        while i < en:
            addr, mn, ops, rel, sym = insns[i]
            if regs is not None and self.recording and self.mode == 'record' and self.compare_rules:
                self.compare(mn, ops, addr, self.compare_rules)
            if not is_branch(mn):
                if regs is not None:
                    self.step(regs, addr, mn, ops, rel, seeds_ret)
                i += 1
                continue
            likely = mn in LIKELY
            pre = dict(regs) if (likely and regs is not None) else None
            callee = self.callee(mn, ops, rel, sym, regs) if (mn in CALLS and regs is not None) else None
            if i + 1 < len(insns) and regs is not None:
                s = insns[i + 1]
                if self.recording and self.mode == 'record' and self.compare_rules:
                    self.compare(s[1], s[2], s[0], self.compare_rules)
                self.step(regs, s[0], s[1], s[2], s[3], seeds_ret)
            nxt = bindex.get(i + 2)
            if mn in CALLS:
                if regs is not None:
                    self.after_call(regs, callee, addr, seeds_ret)
                i += 2
                continue
            if mn in ('jr', 'jr.hb'):
                if regs is not None and self.recording and self.mode == 'record' and ops and ops[0] == '$31':
                    self.rets[self.fname].append(regs.get(2))
                return
            t = branch_target(insns[i])
            tb = bindex.get(index.get(t)) if t is not None else None
            uncond = mn == 'j' or (mn == 'beq' and ops[:2] == ['$0', '$0']) or (mn in ('bgez', 'bgezl') and ops[:1] == ['$0'])
            if tb is not None:
                yield tb, regs
            if not uncond and nxt is not None:
                yield nxt, (pre if likely else regs)
            return
        nxt = bindex.get(en)
        if nxt is not None:
            yield nxt, regs

    def callee(self, mn, ops, rel, sym, regs):
        if rel and rel[0] in ('R_MIPS_26', 'R_MIPS_CALL16', 'R_MIPS_JALR', 'R_MIPS_PC16'):
            return rel[1]
        if mn in ('jalr', 'jalr.hb'):
            r = REG.match(ops[-1]) if ops else None
            v = regs.get(int(r.group(1))) if r else None
            if v and v[0] == 's':
                return v[1]
            return None
        if ops:
            try:
                t = int(ops[-1], 16)
            except ValueError:
                return sym
            if t in self.info.stubs:
                return self.info.stubs[t]
            if t in self.entry_names.get(id(self.img), {}):
                return self.entry_names[id(self.img)][t]
        if sym and not sym.startswith('.'):
            return sym
        return None

    def after_call(self, regs, callee, addr, seeds_ret):
        m = self.m
        if callee:
            if self.recording and self.mode == 'record':
                self.calls[callee].append({r: regs.get(r) for r in ARG_REGS})
            for a in m.accessors:
                if a['function'] == callee and self.applies(a, self.img):
                    v = regs.get(int(a['address_reg']))
                    val = regs.get(int(a['value_reg'])) if 'value_reg' in a else None
                    self.access(v, 0, a['access'], int(a.get('width', 4)), addr, val,
                                'accessor ' + callee, force=True)
            if callee in m.ioctl_send:
                v = regs.get(5)
                if v and v[0] == 'c':
                    c = v[1] & 0xffffffff
                    if any(lo <= c <= hi for lo, hi in m.ioctl_ranges):
                        self.note_ioctl(c, 'sent', addr)
        for r in CALLER_SAVED:
            regs.pop(r, None)
        if callee and callee in seeds_ret:
            regs[2] = seeds_ret[callee]
        for b in m.bases:
            if b['type'] == 'return' and callee and re.fullmatch(b['function'], callee) and \
                    self.applies(b, self.img):
                regs[2] = ('w', b['window'], num(b.get('offset', 0)), b.get('label', 'return of ' + callee))

    def compare(self, mn, ops, addr, rules):
        if len(ops) != 3:
            return
        role = None
        if mn in ('addiu', 'daddiu', 'ori') and ops[1] == '$0':
            role = 'handled'
        elif mn in ('sltiu', 'slti'):
            role = 'boundary'
        if role is None:
            return
        try:
            v = num(ops[2]) & 0xffff
        except ValueError:
            return
        for d in rules:
            lo, hi = num(d['range'][0]), num(d['range'][1])
            if lo <= v <= hi:
                self.note_ioctl(v, role, addr)

    def note_ioctl(self, v, role, addr):
        if not self.recording or self.mode == 'shadow':
            return
        e = self.ioctl.setdefault(v, {'roles': set(), 'funcs': set(), 'bins': set(), 'ex': None})
        e['roles'].add(role)
        self.touch.add((self.img['label'], self.fname))
        e['funcs'].add(self.fname)
        e['bins'].add(self.img['label'])
        ex = '%s:%s' % (self.img['label'], self.fname)
        if e['ex'] is None or ex < e['ex']:
            e['ex'] = ex

    def const(self, v, addr):
        if not self.recording or self.mode == 'shadow':
            return
        c = self.m.ioctl_const
        if c and self.applies(c, self.img):
            w = v & 0xffffffff
            if w & num(c['mask']) == num(c['value']):
                self.note_ioctl(w, 'constant', addr)

    def classify(self, v, computed=False):
        """(window, offset, rule) of a constant address, or None. A computed address (a constant
        plus an unknown) counts only for rules that say the constant can only be an address."""
        for b in self.m.bases:
            if b['type'] != 'constant' or not self.applies(b, self.img):
                continue
            if computed and not b.get('computed'):
                continue
            p = translate(b, v)
            lo, hi = num(b['lo']), num(b['hi'])
            if lo <= p < hi:
                return b['window'], p - lo + num(b.get('offset', 0)), b.get('label', 'constant address')
        return None

    def access(self, base, disp, acc, width, addr, value, how=None, force=False):
        """Record a load or store whose address is base + disp."""
        if not self.recording:
            return
        if base is None:
            if force:
                self.unres('unknown window')
            return
        if base[0] == 'w':
            win, off, ev = base[1], base[2], how or base[3]
            if off is None:
                if self.mode == 'shadow':
                    return
                self.unres(win)
                for args in self.shadow.get(addr, ()):
                    self.place(*args)
                return
            off += disp
        elif base[0] == 'c':
            c = self.classify(base[1] + disp)
            if c is None:
                if force:
                    self.unres('unknown window')
                return
            win, off, ev = c
            if how:
                ev = how
        elif base[0] == 'cu':
            c = self.classify(base[1] + disp, computed=True)
            if c is not None:
                self.unres(c[0])
            elif force:
                self.unres('unknown window')
            return
        else:
            if force:
                self.unres('unknown window')
            return
        if self.mode == 'shadow':
            self.shadow[addr].append((win, off, acc, width, addr, value, ev))
            return
        self.place(win, off, acc, width, addr, value, ev)

    def unres(self, win):
        if self.mode != 'shadow':
            self.unresolved[(self.img['label'], win)] += 1
            self.touch.add((self.img['label'], self.fname))

    def place(self, win, off, acc, width, addr, value, ev):
        w = self.m.windows.get(win)
        if w is None or not (0 <= off < w['size']):
            return
        alias = False
        for a in self.m.aliases:
            if a['window'] == win and a['lo'] <= off < a['hi'] and off & a['bit']:
                off &= ~a['bit']
                alias = True
        self.sites[self.img['label']] += 1
        if value is not None and acc == 'w' and value[0] == 'c':
            self.sink(win, off, value[1], width, addr)
        for d in self.m.decoders:
            if d['window'] != win:
                continue
            if d['type'] == 'stride' and num(d['lo']) <= off < num(d['hi']):
                idx = (off - num(d['lo'])) // int(d['stride'])
                part = (off - num(d['lo'])) % int(d['stride'])
                self.record(d['to_window'], idx, acc, width, ev, addr, alias,
                            d.get('label', 'stride window') + (' +%d' % part if part else ''))
                return
            if d['type'] == 'port-field' and off == num(d['offset']) and acc == 'w' and value and value[0] == 'c':
                v = value[1] & ((1 << 64) - 1)
                word = v >> 32 if width == 8 else v & 0xffffffff
                if all(cond_ok(c, word) for c in d['when']):
                    f = d['field']
                    self.record(d['to_window'], (word >> f.get('shift', 0)) & num(f['mask']), acc, width,
                                ev, addr, False, d.get('label', 'port field'))
        self.record(win, off, acc, width, ev, addr, alias)

    def record(self, win, off, acc, width, ev, addr, alias, note=''):
        key = (self.m.region(win, off) if win in self.m.windows else win, off)
        e = self.out_mmio.get(key)
        if e is None:
            e = self.out_mmio[key] = {'acc': set(), 'sites': 0, 'funcs': set(), 'bins': set(), 'ev': set(),
                                      'ex': None}
        e['acc'].add('%s%d%s%s' % (acc, width, ' alias' if alias else '', ' ' + note if note else ''))
        e['sites'] += 1
        self.touch.add((self.img['label'], self.fname))
        e['funcs'].add(self.fname)
        e['bins'].add(self.img['label'])
        e['ev'].add(ev)
        ex = '%s:%s' % (self.img['label'], self.fname)
        if e['ex'] is None or ex < e['ex']:
            e['ex'] = ex

    def sink(self, win, off, v, width, addr):
        for s in self.m.sinks:
            if s.get('window') != win or not self.applies(s, self.img):
                continue
            lo, hi = num(s.get('lo', 0)), num(s.get('hi', 1 << 40))
            if not (lo <= off < hi):
                continue
            if s.get('first_store_only'):
                k = (win, lo)
                if k in self.first_store:
                    continue
                self.first_store.add(k)
            self.token(v, width, s, off if s.get('register') else None)

    def token(self, v, width, s, reg):
        if not self.recording or self.mode == 'shadow':
            return
        v &= (1 << 64) - 1
        if width == 8 and s.get('split64', True) and (v >> 32) not in (0, 0xffffffff):
            words = [v >> 32, v & 0xffffffff]
        else:
            words = [v & (0xffffffff if width <= 4 or not s.get('keep64') else (1 << 64) - 1)]
        for w in words:
            if 'value_mask' in s:
                w &= num(s['value_mask'])
            if s.get('families') and self.m.family(w) is None:
                continue
            key = (s.get('kind', 'word'), reg, w)
            e = self.tokens.get(key)
            if e is None:
                e = self.tokens[key] = {'sites': 0, 'bins': set(), 'ex': None, 'src': set(), 'known_only':
                                        bool(s.get('known_only'))}
            e['sites'] += 1
            self.touch.add((self.img['label'], self.fname))
            e['bins'].add(self.img['label'])
            e['src'].add(s.get('label', 'code'))
            ex = '%s:%s' % (self.img['label'], self.fname)
            if e['ex'] is None or ex < e['ex']:
                e['ex'] = ex

    # ------------------------------------------------------------ one instruction

    def step(self, regs, addr, mn, ops, rel, seeds_ret):
        n = len(ops)

        def val(tok):
            mm = REG.match(tok)
            if not mm:
                return None
            k = int(mm.group(1))
            return ('c', 0) if k == 0 else regs.get(k)

        def setr(tok, v):
            mm = REG.match(tok)
            if mm and int(mm.group(1)) != 0:
                k = int(mm.group(1))
                if v is None:
                    regs.pop(k, None)
                else:
                    regs[k] = v
                    if v[0] == 'c':
                        self.const(v[1], addr)

        if mn in LOADS or mn in STORES:
            mm = MEMOP.match(ops[-1]) if n >= 2 else None
            if not mm:
                if mn in LOADS and n and mn not in FPMEM:
                    setr(ops[0], None)
                return
            disp = num(mm.group(1))
            bk = int(mm.group(2))
            bv = ('c', 0) if bk == 0 else regs.get(bk)
            if bv and bv[0] == 'sp':
                # a frame pointer set to sp plus a constant: its slots are sp slots
                bk, disp, bv = 29, disp + bv[1], None
            width = LOADS.get(mn) or STORES[mn]
            if mn in STORES:
                value = val(ops[0]) if mn not in ('swc1', 'sdc1', 'swc2', 'sdc2') else None
                if bk == 29:
                    if value is not None:
                        regs[('m', disp)] = value
                    else:
                        regs.pop(('m', disp), None)
                    return
                self.access(bv, disp, 'w', width, addr, value)
                if value and value[0] == 'c' and bk != 29:
                    for s in self.m.sinks:
                        if s.get('any_store') and self.applies(s, self.img):
                            self.token(value[1], width, s, None)
                return
            # loads
            self.access(bv, disp, 'r', width, addr, None)
            if mn in FPMEM:
                return
            setr(ops[0], self.load_value(regs, bk, bv, disp, rel, width, mn))
            return
        if mn in NO_DEST or mn.startswith('c.') or not ops:
            return
        d = ops[0]
        v = None
        if mn == 'lui' and n == 2:
            if rel:
                v = ('s', rel[1], rel[2] + (num(ops[1]) << 16 if not rel[2] else 0))
            else:
                v = ('c', s32(num(ops[1]) << 16))
        elif mn in ('addiu', 'daddiu', 'addi', 'daddi') and n == 3:
            s = val(ops[1])
            imm = num(ops[2])
            if ops[1] == '$29' and not rel:
                v = ('sp', imm)
            elif rel and rel[0] in ('R_MIPS_LO16', 'R_MIPS_GOT_OFST', 'R_MIPS_GPREL16', 'R_MIPS_GOT_LO16'):
                if s and s[0] == 's' and s[1] == rel[1]:
                    v = ('s', rel[1], s[2] + imm + rel[2])
                else:
                    v = ('s', rel[1], imm + rel[2])
            elif s and s[0] == 'c':
                v = ('c', s32(s[1] + imm) if mn in ('addiu', 'addi') else s64(s[1] + imm))
            elif s and s[0] == 'sp':
                v = ('sp', s[1] + imm)
            elif s and s[0] == 'w':
                v = ('w', s[1], None if s[2] is None else s[2] + imm, s[3])
            elif s and s[0] in ('s', 'cu'):
                v = (s[0], s[1], s[2] + imm) if s[0] == 's' else ('cu', s[1] + imm)
        elif mn in ('li', 'dli') and n == 2:
            v = ('c', num(ops[1]))
        elif mn in ('ori', 'xori', 'andi') and n == 3:
            s = val(ops[1])
            imm = num(ops[2])
            if rel and mn == 'ori':
                v = ('s', rel[1], (s[2] if s and s[0] == 's' else 0) + imm + rel[2])
            elif s and s[0] == 'c':
                v = ('c', s[1] | imm if mn == 'ori' else (s[1] ^ imm if mn == 'xori' else s[1] & imm))
            elif s and s[0] == 'w' and mn == 'ori' and s[2] is not None:
                v = ('w', s[1], s[2] | imm, s[3])
            elif s and s[0] == 's' and mn == 'ori':
                v = ('s', s[1], s[2] + imm)
        elif mn in ('addu', 'daddu', 'add', 'dadd', 'or', 'xor', 'subu', 'dsubu', 'sub', 'dsub') and n == 3:
            a, c = val(ops[1]), val(ops[2])
            sub = mn in ('subu', 'dsubu', 'sub', 'dsub')
            if mn in ('or', 'addu', 'daddu') and ops[2] == '$0':
                v = a
            elif mn in ('or', 'addu', 'daddu') and ops[1] == '$0':
                v = c
            elif a and c and {a[0], c[0]} == {'cp', 'ci'} and a[1] == c[1] and mn in ('addu', 'daddu'):
                v = ('cq', a[1])
            elif a and c and a[0] == 'c' and c[0] == 'c':
                if mn == 'or':
                    r = a[1] | c[1]
                elif mn == 'xor':
                    r = a[1] ^ c[1]
                elif sub:
                    r = a[1] - c[1]
                else:
                    r = a[1] + c[1]
                v = ('c', s32(r) if mn in ('addu', 'add', 'subu', 'sub') else s64(r))
            elif mn != 'xor':
                if not sub and c and c[0] == 'w' and not (a and a[0] == 'w'):
                    a, c = c, a
                elif not sub and c and c[0] in ('s', 'cu') and a and a[0] == 'c':
                    a, c = c, a
                if a and a[0] == 'w':
                    if c and c[0] == 'c' and a[2] is not None:
                        v = ('w', a[1], a[2] - c[1] if sub else (a[2] | c[1] if mn == 'or' else a[2] + c[1]), a[3])
                    elif not (c and c[0] == 'w'):
                        v = ('w', a[1], None, a[3])
                elif a and a[0] == 's' and c and c[0] == 'c' and not sub:
                    v = ('s', a[1], a[2] + c[1])
                elif a and a[0] in ('c', 'cu') and not sub and not (c and c[0] in ('w', 's')):
                    v = ('cu', a[1])
        elif mn in ('sll', 'dsll', 'dsll32', 'srl', 'dsrl', 'dsrl32', 'sra', 'dsra', 'dsra32') and n == 3:
            s = val(ops[1])
            sa = num(ops[2]) + (32 if mn.endswith('32') else 0)
            if s and s[0] == 'c':
                u = s[1] & ((1 << 64) - 1)
                if mn == 'sll':
                    v = ('c', s32(u << sa))
                elif mn.startswith('dsll'):
                    v = ('c', s64(u << sa))
                elif mn == 'srl':
                    v = ('c', s32((u & 0xffffffff) >> sa))
                elif mn.startswith('dsrl'):
                    v = ('c', s64(u >> sa))
                elif mn == 'sra':
                    v = ('c', s32(s32(u) >> sa))
                else:
                    v = ('c', s64(s64(u) >> sa))
            elif s and s[0] == 's' and mn.startswith('dsll'):
                v = s
            elif s and s[0] == 'ci' and mn in ('sll', 'dsll'):
                v = s
        elif mn in ('movn', 'movz'):
            v = None
        setr(d, v)

    def load_value(self, regs, bk, bv, disp, rel, width, mn):
        info, img = self.info, self.img
        if bk == 29:
            return regs.get(('m', disp))
        # configured record chains
        for b in self.m.bases:
            if b['type'] != 'chain' or not self.applies(b, img, self.fname):
                continue
            if mn not in b.get('loads', ('lw', 'ld', 'lwu')):
                continue
            cid = b.get('label', 'chain')
            if bk not in (0, 29) and disp == num(b['index_disp']):
                return ('ci', cid)
            if disp == num(b['array_disp']) and bk not in (0, 29) and not (bv and bv[0] in ('c', 's')):
                return ('cp', cid)
            if bv and bv[0] == 'cq' and bv[1] == cid and disp == 0:
                return ('cr', cid)
            if bv and bv[0] == 'cr' and bv[1] == cid:
                for f in b['fields']:
                    if num(f['disp']) == disp:
                        return ('w', f['window'], num(f.get('offset', 0)), f.get('label', cid + ' +%d' % disp))
        # configured pointer fields and globals
        for b in self.m.bases:
            t = b['type']
            if t not in ('field', 'global') or not self.applies(b, img, self.fname):
                continue
            if b.get('loads') and mn not in b['loads']:
                continue
            if t == 'field':
                if num(b['disp']) == disp and bk not in (0, 28, 29) and not (bv and bv[0] in ('c', 's')):
                    return ('w', b['window'], num(b.get('offset', 0)), b.get('label', 'field +%d' % disp))
            else:
                g = None
                if bv and bv[0] == 's':
                    g = (bv[1], bv[2] + disp)
                elif rel and rel[0] in ('R_MIPS_GPREL16', 'R_MIPS_LO16', 'R_MIPS_LITERAL'):
                    g = (rel[1], rel[2] + (disp if bk != 28 else 0))
                if g and g[0] == b['symbol'] and g[1] == num(b.get('disp', 0)):
                    return ('w', b['window'], num(b.get('offset', 0)), b.get('label', 'global ' + b['symbol']))
        # GOT and literal pools
        if rel:
            rt, sym, add = rel
            if rt in ('R_MIPS_CALL16', 'R_MIPS_GOT16', 'R_MIPS_GOT_DISP', 'R_MIPS_GOT_PAGE', 'R_MIPS_CALL_LO16',
                      'R_MIPS_GOT_LO16'):
                return ('s', sym, add if rt != 'R_MIPS_GOT16' else add)
            if rt in ('R_MIPS_GPREL16', 'R_MIPS_LITERAL') and sym.startswith('.'):
                w = 8 if mn == 'ld' else 4
                c = info.read_sec(sym, disp + info.gp0 + add, w) if mn in ('ld', 'lw', 'lwu') else None
                return ('c', c) if c is not None else None
            if rt == 'R_MIPS_LO16' and bv and bv[0] == 's' and sym.startswith('.'):
                c = info.read_sec(sym, bv[2] + disp, 8 if mn == 'ld' else 4) if mn in ('ld', 'lw') else None
                return ('c', c) if c is not None else None
            return None
        if bk == 28 and not info.rel:
            nm = info.got_names.get(disp)
            if nm:
                return ('s', nm, 0)
            loc = info.got_local.get(disp)
            if loc is not None:
                return ('c', loc)
            return None
        if bv and bv[0] == 'c' and not info.rel and mn in ('ld', 'lw', 'lwu'):
            c = info.read(bv[1] + disp, 8 if mn == 'ld' else 4)
            if c is not None:
                return ('c', c)
        return None


def meet(a, b):
    """The value two paths agree on: equal values, or a window base with an untraced offset."""
    if a == b:
        return a
    if a and b and a[0] == 'w' and b[0] == 'w' and a[1] == b[1]:
        return ('w', a[1], None, a[3])
    return None


def branch_target(ins):
    try:
        return int(ins[2][-1], 16)
    except (ValueError, IndexError):
        return None


def dest_keys(ins):
    addr, mn, ops, rel, sym = ins
    if mn in CALLS:
        return set(CALLER_SAVED) | {2, 3}
    if mn in STORES:
        mm = MEMOP.match(ops[-1]) if len(ops) >= 2 else None
        if mm and mm.group(2) == '29':
            return {('m', num(mm.group(1)))}
        return set()
    if is_branch(mn) or mn in NO_DEST or not ops:
        return set()
    r = REG.match(ops[0])
    return {int(r.group(1))} if r else set()


# ===================================================================== ioctl tables

def jump_table(img, elf, funcs, d):
    """Slots of a switch table the named dispatcher indexes: [(number, handler)]."""
    sym = None
    sec = elf.get_section_by_name('.symtab')
    if sec is None:
        return []
    for s in sec.iter_symbols():
        if s.name == d['function'] and s['st_info']['type'] == 'STT_FUNC':
            sym = s
    if sym is None:
        return []
    lo, hi = sym['st_value'], sym['st_value'] + sym['st_size']
    rod = elf.get_section_by_name(d.get('section', '.rodata'))
    rel = elf.get_section_by_name('.rel' + d.get('section', '.rodata'))
    if rod is None or rel is None:
        return []
    data = rod.data()
    wsz = 8 if elf.elfclass == 64 else 4
    entries = []
    for r in rel.iter_relocations():
        off = r['r_offset']
        entries.append((off, int.from_bytes(data[off:off + wsz], 'big')))
    entries.sort()
    best, run = [], []
    for off, val in entries:
        if lo <= val < hi and (not run or off == run[-1][0] + wsz):
            run.append((off, val))
        else:
            if len(run) > len(best):
                best = run
            run = [(off, val)] if lo <= val < hi else []
    if len(run) > len(best):
        best = run
    if not best:
        return []
    insns = [x for name, ins in funcs if name == d['function'] for x in ins]
    base = num(d.get('base', 0))
    if d.get('base') is None:
        for a, mn, ops, rl, sy in insns:
            if mn in ('addiu', 'daddiu') and len(ops) == 3:
                try:
                    k = num(ops[2])
                except ValueError:
                    continue
                if k <= -int(d.get('min_base', 1000)):
                    base = -k
                    break
    targets = [v for _, v in best]
    default = collections.Counter(targets).most_common(1)[0][0]
    order = sorted(set(targets))
    idx = {ins[0]: i for i, ins in enumerate(insns)}
    out = []
    for slot, tgt in enumerate(targets):
        if tgt == default:
            continue
        handler = ''
        i = idx.get(tgt)
        j = bisect.bisect_right(order, tgt)
        stop = order[j] if j < len(order) else 1 << 62
        while i is not None and i < len(insns) and insns[i][0] < stop:
            a, mn, ops, rl, sy = insns[i]
            if mn in CALLS:
                handler = rl[1] if rl else (sy or '')
                break
            i += 1
        out.append((base + slot, handler))
    return out


def pointer_table(img, elf, d):
    """Entries of a table of handler pointers in a data section: [(number, handler)]."""
    sec = elf.get_section_by_name(d['section'])
    rel = elf.get_section_by_name('.rel' + d['section']) or elf.get_section_by_name('.rela' + d['section'])
    sym = elf.get_section_by_name('.symtab')
    if not (sec and rel and sym):
        return []
    data = sec.data()
    fmap = {s['st_value']: s.name for s in sym.iter_symbols() if s['st_info']['type'] == 'STT_FUNC' and s.name}
    relocs = []
    wid = 8 if elf.elfclass == 64 else 4
    for r in rel.iter_relocations():
        s = sym.get_symbol(r['r_info_sym'])
        off = r['r_offset']
        if s.name and not s.name.startswith('.'):
            nm = s.name
        else:
            nm = fmap.get(int.from_bytes(data[off:off + wid], 'big'), '')
            if not nm:
                continue
        relocs.append((off, nm))
    prefix = d.get('prefix', '')
    if d['start'] == 'auto':
        c = [o for o, n in relocs if n.startswith(prefix)]
        if not c:
            return []
        start = min(c)
    else:
        start = num(d['start'])
    stride, base = int(d['stride']), num(d['base'])
    out = []
    for off, nm in sorted(relocs):
        if off < start or (off - start) % stride or (off - start) // stride >= int(d['count']):
            continue
        if prefix and not nm.startswith(prefix):
            continue
        out.append((base + (off - start) // stride, nm))
    return out


# ===================================================================== worker

def analyse_unit(args):
    """Symbols, register accesses, tokens and ioctls of one file in scope."""
    cfg, imgs, tmpdir = args
    model = Model(cfg)
    res = {'funcs': {}, 'finfo': {}, 'abi': {}, 'kind': {}, 'tables': []}
    work = tempfile.mkdtemp(dir=tmpdir)
    try:
        for img in imgs:
            elf = None
            if img['data'][:4] == b'\x7fELF':
                try:
                    elf = elf_of(img['data'])
                except Exception as ex:
                    print('skip %s: %s' % (img['label'], ex), file=sys.stderr)
            img['elf'] = elf
            path = os.path.join(work, '%d.elf' % len(res['abi']))
            with open(path, 'wb') as f:
                f.write(img['data'])
            img['tmp'] = path
            res['abi'][img['label']] = abi_of(elf) if elf else '-'
            res['kind'][img['label']] = kind_of(img['data'], elf)
            res['funcs'][img['label']], res['finfo'][img['label']] = functions_of(img, elf, path)
            img['functab'] = res['funcs'][img['label']]
        u = Unit(model, cfg, imgs).run()
        # kernel dispatch tables
        for d in cfg.get('ioctls', {}).get('dispatchers', []):
            for img in imgs:
                if img['elf'] is None or not u.applies(d, img):
                    continue
                if d.get('member') and img['member'] != d['member']:
                    continue
                rows = []
                if d['type'] == 'jump-table':
                    funcs = next((f for (i2, info, f) in u.code if i2 is img), [])
                    rows = jump_table(img, img['elf'], funcs, d)
                elif d['type'] == 'pointer-table':
                    rows = pointer_table(img, img['elf'], d)
                for number, handler in rows:
                    res['tables'].append((d['name'], number, handler, img['label'], d.get('strip', '')))
                    if handler:
                        u.touch.add((img['label'], handler))
        res['mmio'] = u.out_mmio
        res['unresolved'] = dict(u.unresolved)
        res['sites'] = dict(u.sites)
        res['tokens'] = u.tokens
        res['ioctl'] = u.ioctl
        res['touch'] = u.touch
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for img in imgs:
        img.pop('elf', None)
        img.pop('data', None)
    return res


# ===================================================================== external tables

def fmt(s, tmp):
    return s.replace('{tmp}', tmp).replace('{root}', os.path.join(REPO, 'root'))


def read_tsv(path):
    rows, head = [], None
    for ln in open(path, encoding='utf-8', errors='replace'):
        if ln.startswith('#') or not ln.strip():
            continue
        c = ln.rstrip('\n').split('\t')
        if head is None:
            head = c
            continue
        rows.append(dict(zip(head, c)))
    return rows


def table_rows(src, tmp):
    path = os.path.join(REPO, fmt(src['file'], tmp))
    if not os.path.exists(path):
        return []
    if src.get('header', True):
        rows = read_tsv(path)
    else:
        rows = []
        for ln in open(path, encoding='utf-8', errors='replace'):
            if ln.startswith('#') or not ln.strip():
                continue
            c = ln.rstrip('\n').split('\t')
            rows.append({str(i): x for i, x in enumerate(c)})
    out = []
    for r in rows:
        if any(r.get(k) != v for k, v in src.get('where', {}).items()):
            continue
        if any(r.get(k) in v for k, v in src.get('where_not', {}).items()):
            continue
        out.append(r)
    return out


# ===================================================================== inventories

def tsv_cell(x):
    return str(x).replace('\t', ' ').replace('\n', ' ')


def write_tsv(path, table, rows):
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\t'.join(COLUMNS[table]) + '\n')
        for r in rows:
            f.write('\t'.join(tsv_cell(r.get(c, '')) for c in COLUMNS[table]) + '\n')


def short_list(items, k=6):
    items = sorted(items)
    s = ';'.join(items[:k])
    return s + (';+%d more' % (len(items) - k) if len(items) > k else '')


def image_keys(label):
    """The ways a document can write a binary's name: its path from any directory down, and for an
    archive member the member alone or after the archive."""
    path, member = label, ''
    if label.endswith(')') and '(' in label:
        path, member = label[:-1].split('(', 1)
    comps = path.split('/')
    keys = set()
    for i in range(len(comps)):
        suf = '/'.join(comps[i:])
        keys.add(suf)
        if member:
            keys.add('%s(%s)' % (suf, member))
    if member:
        keys.add(member)
    return keys


def put_status(row, st):
    st = tuple(st) + (False,) * (8 - len(st))
    row['status'], row['doc'], row['section'], row['_skel'], row['_templated'] = st[:5]
    row['_open'], row['_computes'], row['_reused'] = st[5], st[6], st[7]


def window_files(cfg, win):
    for w in cfg.get('windows', []):
        if w['name'] == win:
            return w.get('docs')
        for r in w.get('regions', []):
            if r['name'] == win:
                return r.get('docs', w.get('docs'))
    return None


def window_forms(cfg, win, off):
    """The numbers a document may write for an offset: the offset, its value within the
    region, and the full physical address."""
    vals, absolute = [off], []
    for w in cfg.get('windows', []):
        regs = [r for r in w.get('regions', []) if r['name'] == win]
        if w['name'] == win or regs:
            if regs and num(regs[0]['lo']):
                vals.append(off - num(regs[0]['lo']))
            if w.get('physical') is not None:
                absolute.append(num(w['physical']) + off)
    return vals, absolute


def best_of(*sts):
    top = ('undocumented', '', '', '', False, False, False)
    for s in sts:
        if RANK[s[0]] > RANK[top[0]]:
            top = s
    return top


def other_namespace(cfg, table):
    """The documents that belong to another table: the token chapters when the table is a register
    window, the register chapters when it is tokens. A bare number in one of them names a command
    word or a register of that other table, not this table's item. Only tables whose config lists no
    documents of their own are restricted by it."""
    pats = []
    if table == 'registers':
        pats += cfg.get('tokens', {}).get('docs') or []
    else:
        for w in cfg.get('windows', []):
            pats += w.get('docs') or []
            for r in w.get('regions', []):
                pats += r.get('docs') or []
    return pats


def context_words(cfg, key):
    return cfg.get('docs', {}).get('context', {}).get(key)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--config', default=os.path.join(REPO, 'scripts', 'inventory-config.json'))
    ap.add_argument('--out', default=os.path.join(REPO, 'docs', 'inventory'))
    ap.add_argument('--no-coverage', action='store_true')
    ap.add_argument('--sibling', action='append', default=[], metavar='NAME=PATH',
                    help='read the sibling workspace NAME from PATH instead of the config\'s path')
    ap.add_argument('--skip-siblings', action='store_true',
                    help='run without the cross-workspace role check; the tables say it was skipped')
    ap.add_argument('--update-pins', action='store_true',
                    help='record the HEAD of each sibling checkout in %s' % SIBLING_PINS)
    ap.add_argument('--update-root-manifest', action='store_true',
                    help='rewrite %s from the files under root/' % ROOT_MANIFEST)
    ap.add_argument('--jobs', type=int, default=min(16, os.cpu_count() or 1))
    a = ap.parse_args()
    a.sibling = dict(x.split('=', 1) for x in a.sibling)
    os.chdir(REPO)
    cfg = json.load(open(a.config, encoding='utf-8'))
    os.makedirs(a.out, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix='inventory-')
    try:
        for cmd in cfg.get('prepare', []):
            r = subprocess.run([sys.executable if c == 'python3' else fmt(c, tmp) for c in cmd],
                               capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=REPO,
                               env=dict(os.environ, PYTHONHASHSEED='0'))
            if r.returncode:
                sys.exit('inventory: prepare %s failed: %s' % (' '.join(cmd), r.stderr.strip()[-500:]))
        build(cfg, a, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build(cfg, a, tmp):
    problems = []
    files = doc_files(cfg, REPO)
    problems += conflict_problems(REPO, files, 'this workspace')
    manifest, new_manifest, nroot = root_check(cfg, files, a.update_root_manifest, problems)
    pins = {}
    siblings = load_siblings(cfg, a.sibling, tmp, problems, pins, a.skip_siblings, a.update_pins)
    if problems:
        sys.exit('inventory: refusing to write tables from inputs that are not what they should be:\n  ' +
                 '\n  '.join(problems))
    if new_manifest is not None:
        with open(os.path.join(REPO, ROOT_MANIFEST), 'w', encoding='utf-8', newline='\n') as f:
            f.write(new_manifest)
        manifest = hashlib.sha256(new_manifest.encode('utf-8')).hexdigest()
    if a.update_pins:
        with open(os.path.join(REPO, SIBLING_PINS), 'w', encoding='utf-8', newline='\n') as f:
            json.dump(pins, f, indent=2, sort_keys=True)
            f.write('\n')
    docs = DocIndex(cfg, siblings)
    sibrep = docs.sibling_report
    inputs = [{'table': 'input root manifest', 'rows': nroot, 'input': manifest}]
    inputs += [{'table': 'input sibling ' + n, 'input': c} for n, c in sorted(sibrep['commits'].items())]
    inputs += [{'table': 'input sibling ' + n, 'input': 'skipped'} for n, why in sibrep['skipped']
               if n != '(none)']
    for name, why in sibrep['skipped']:
        print('WARNING: cross-workspace role check skipped for %s: %s' % (name, why), file=sys.stderr)
    imgs = scope(cfg)
    print('%d distinct images in scope (%d byte-identical copies folded)' %
          (len(imgs), sum(len(i['copies']) for i in imgs)), file=sys.stderr)
    units = collections.OrderedDict()
    for img in imgs:
        units.setdefault(img['path'], []).append(img)
    meta = {i['label']: i for i in imgs}
    jobs = [(cfg, [dict(i) for i in u], tmp) for u in units.values()]
    jobs.sort(key=lambda j: -sum(len(i['data']) for i in j[1]))
    if a.jobs > 1:
        with multiprocessing.get_context('fork').Pool(a.jobs) as pool:
            results = pool.map(analyse_unit, jobs, chunksize=1)
    else:
        results = [analyse_unit(j) for j in jobs]

    funcs, finfo, abi, kinds = {}, {}, {}, {}
    mmio, unresolved, sites, tokens_code, ioctl_code, tables = {}, collections.Counter(), collections.Counter(), {}, {}, []
    touch = set()       # (binary, function) pairs that reach a register window, a token or an ioctl
    for r in results:
        touch |= r['touch']
        funcs.update(r['funcs'])
        finfo.update(r['finfo'])
        abi.update(r['abi'])
        kinds.update(r['kind'])
        for k, e in r['mmio'].items():
            t = mmio.setdefault(k, {'acc': set(), 'sites': 0, 'funcs': set(), 'bins': set(), 'ev': set(), 'ex': None})
            t['acc'] |= e['acc']
            t['sites'] += e['sites']
            t['funcs'] |= e['funcs']
            t['bins'] |= e['bins']
            t['ev'] |= e['ev']
            t['ex'] = min(x for x in (t['ex'], e['ex']) if x is not None)
        unresolved.update(r['unresolved'])
        sites.update(r['sites'])
        for k, e in r['tokens'].items():
            t = tokens_code.setdefault(k, {'sites': 0, 'bins': set(), 'ex': None, 'src': set(),
                                           'known_only': e['known_only']})
            t['sites'] += e['sites']
            t['bins'] |= e['bins']
            t['src'] |= e['src']
            t['ex'] = min(x for x in (t['ex'], e['ex']) if x is not None)
        for k, e in r['ioctl'].items():
            t = ioctl_code.setdefault(k, {'roles': set(), 'funcs': set(), 'bins': set(), 'ex': None})
            t['roles'] |= e['roles']
            t['funcs'] |= e['funcs']
            t['bins'] |= e['bins']
            t['ex'] = min(x for x in (t['ex'], e['ex']) if x is not None)
        tables += r['tables']

    out = {}
    # ---------------------------------------------------------------- spec registers
    spec = []
    for src in cfg.get('spec_registers', []):
        if src['type'] == 'rows':
            for r in src['rows']:
                row = dict(zip(src.get('columns', ['table', 'page', 'window', 'offset', 'name', 'count', 'stride',
                                                   'width', 'rw']), r))
                row['spec'] = src['spec']
                row['offset'] = num(row['offset'])
                spec.append(row)
        elif src['type'] == 'table':
            for r in table_rows(src, tmp):
                c = src['columns']
                off = num(r[c['offset']])
                spec.append({'spec': src['spec'], 'table': src.get('table', ''), 'page': '',
                             'window': src['window'], 'offset': off + num(src.get('offset_bias', 0)),
                             'name': r[c['name']].strip(), 'count': 1, 'stride': 0,
                             'width': src.get('width', ''), 'rw': ''})
    spec.sort(key=lambda r: (r['spec'], r['window'], r['offset'], r['name']))
    spec_by_win = collections.defaultdict(list)
    for r in spec:
        r['span'] = max(1, int(r['count'] or 1)) * (int(r['stride'] or 0) or (8 if str(r['width']) == '64' else 4))
        spec_by_win[r['window']].append(r)

    def spec_names(win, off):
        return [r for r in spec_by_win.get(win, []) if r['offset'] <= off < r['offset'] + r['span']]

    def reg_name_status(r):
        base = r['name'].split('[')[0]
        names = {base, base.split('.')[-1], re.sub(r'\W+', '_', base)}
        return docs.by_name(*sorted(n for n in names if n and IDENT.fullmatch(n)))

    def offset_status(win, off, extra_names=()):
        vals, absolute = window_forms(cfg, win, off)
        files = window_files(cfg, win)
        hits = docs.value_hits(vals, files, context_words(cfg, 'registers') or REG_CONTEXT, absolute=absolute,
                               exclude=other_namespace(cfg, 'registers'))
        st = docs.best(hits)
        for r in spec_names(win, off):
            st = best_of(st, reg_name_status(r))
        if extra_names:
            st = best_of(st, docs.by_name(*extra_names))
        return st

    # ---------------------------------------------------------------- mmio
    rows = []
    for (win, off), e in sorted(mmio.items()):
        names = [r['name'] for r in spec_names(win, off)]
        row = {'window': win, 'offset': '0x%x' % off, 'name': ';'.join(sorted(set(names))),
               'access': ','.join(sorted(e['acc'])), 'sites': e['sites'], 'binaries': len(e['bins']),
               'functions': short_list(e['funcs']), 'evidence': ';'.join(sorted(e['ev'])), 'example': e['ex']}
        put_status(row, offset_status(win, off))
        rows.append(row)
    out['mmio'] = rows
    reached = collections.defaultdict(list)
    for (win, off) in mmio:
        reached[win].append(off)

    rows = []
    for r in spec:
        st = best_of(reg_name_status(r), offset_status(r['window'], r['offset']))
        n = sum(1 for o in reached.get(r['window'], []) if r['offset'] <= o < r['offset'] + r['span'])
        row = {k: r[k] for k in ('spec', 'table', 'page', 'window', 'name', 'count', 'stride', 'width', 'rw')}
        row['offset'] = '0x%x' % r['offset']
        row['reached_in_code'] = n
        put_status(row, st)
        rows.append(row)
    out['spec-registers'] = rows

    # ---------------------------------------------------------------- tokens
    tk = cfg.get('tokens', {})
    toks = collections.OrderedDict()

    def tok(kind, reg, value):
        k = (kind, reg, value)
        if k not in toks:
            toks[k] = {'names': [], 'detail': [], 'src': set(), 'sites': 0, 'bins': set(), 'ex': None}
        return toks[k]

    for src in tk.get('sources', []):
        if src['type'] == 'table':
            c = src['columns']
            for r in table_rows(src, tmp):
                v = r.get(c['value'], '')
                if not re.fullmatch(r'0x[0-9a-fA-F]+|\d+', v.strip()):
                    continue
                e = tok(src.get('kind', 'token'), None, num(v))
                if c.get('name') and r.get(c['name']):
                    e['names'].append(r[c['name']].strip())
                for col, lab in sorted(c.get('detail', {}).items()):
                    if r.get(col):
                        e['detail'].append('%s=%s' % (lab, r[col]))
                e['src'].add(src['label'])
        elif src['type'] == 'header':
            for f in sorted(glob.glob(os.path.join(REPO, src['file']))):
                for ln in open(f, encoding='utf-8', errors='replace'):
                    m = re.match(src['pattern'], ln)
                    if m:
                        e = tok(src.get('kind', 'token'), None, num(m.group(2)))
                        e['names'].append(m.group(1))
                        e['src'].add(src['label'])
    known_values = {k[2] for k in toks}
    for (kind, reg, w), e in sorted(tokens_code.items(), key=lambda x: (x[0][0], -1 if x[0][1] is None else x[0][1], x[0][2])):
        if e['known_only']:
            if w not in known_values:
                continue
            kk = next(k for k in toks if k[2] == w)
            t = toks[kk]
        else:
            t = tok(kind, reg, w)
        t['src'] |= e['src']
        t['sites'] += e['sites']
        t['bins'] |= e['bins']
        t['ex'] = min(x for x in (t['ex'], e['ex']) if x is not None)
    model = Model(cfg)
    for g in tk.get('groups', []):
        members = collections.defaultdict(list)
        for (kind, reg, w), e in list(toks.items()):
            f = model.family(w) if kind == 'word' else None
            if f is not None and f['name'] == g['family']:
                members[(w >> g.get('shift', 0)) & num(g['mask'])].append(e)
        for gid in sorted(members):
            t = tok(g['kind'], None, gid)
            t['detail'] = ['words=%d' % len(members[gid])]
            for e in members[gid]:
                t['src'] |= e['src']
                t['sites'] += e['sites']
                t['bins'] |= e['bins']
                if e['ex']:
                    t['ex'] = min(x for x in (t['ex'], e['ex']) if x is not None)
    model = Model(cfg)
    rows = []
    vw = tk.get('value_width', 8)
    for (kind, reg, w), e in sorted(toks.items(), key=lambda x: (x[0][0], -1 if x[0][1] is None else x[0][1], x[0][2])):
        names = sorted(set(e['names']))
        alt = []
        for n in names:
            for p in tk.get('name_prefixes', []):
                alt.append(p + n)
        detail = list(e['detail'])
        if kind == 'word':
            f = model.family(w)
            if f:
                detail = [f['name']] + ['%s=0x%x' % (fl['name'], (w >> fl.get('shift', 0)) & num(fl['mask']))
                                        for fl in f.get('fields', [])] + detail
        st = docs.by_name(*(names + alt))
        if st[0] != 'understood':
            files = tk.get('docs')
            if reg is not None:
                keys = {('hex', reg)} | {('id', r['name'].split('[')[0]) for r in spec_names(tk.get('window', ''), reg)}
                st = best_of(st, docs.best(docs.pair_hits([w], keys, files)))
            elif kind in tk.get('value_match', []):
                ctx = tk.get('context', {}).get(kind) or REG_CONTEXT
                st = best_of(st, docs.best(docs.value_hits([w], files, ctx, exclude=other_namespace(cfg, 'tokens'))))
        row = {'kind': kind, 'value': ('0x%0' + str(tk.get('widths', {}).get(kind, vw)) + 'x') % w,
               'name': ';'.join(names), 'register': '' if reg is None else '0x%x' % reg,
               'detail': ' '.join(detail), 'sources': ','.join(sorted(e['src'])), 'sites': e['sites'],
               'binaries': len(e['bins']), 'example': e['ex'] or ''}
        put_status(row, st)
        rows.append(row)
    out['tokens'] = rows

    # ---------------------------------------------------------------- ioctls
    ic = cfg.get('ioctls', {})
    ioc = {}
    for name, number, handler, label, strip in tables:
        e = ioc.setdefault(number, {'tables': set(), 'handlers': set(), 'ev': set(), 'senders': set(),
                                    'bins': set(), 'ex': None, 'strip': set()})
        e['tables'].add(name)
        if handler:
            e['handlers'].add(handler)
        e['ev'].add('table')
        e['bins'].add(label)
        if strip:
            e['strip'].add(strip)
    for number, c in ioctl_code.items():
        e = ioc.setdefault(number, {'tables': set(), 'handlers': set(), 'ev': set(), 'senders': set(),
                                    'bins': set(), 'ex': None, 'strip': set()})
        e['ev'] |= c['roles']
        if c['roles'] & {'sent', 'constant'}:
            e['senders'] |= c['funcs']
        else:
            e['handlers'] |= c['funcs']
        e['bins'] |= c['bins']
        e['ex'] = min(x for x in (e['ex'], c['ex']) if x is not None)
    rows = []
    for number in sorted(ioc):
        e = ioc[number]
        tname = ';'.join(sorted(e['tables']))
        if not tname:
            for c in ic.get('classes', []):
                if num(c['lo']) <= number <= num(c['hi']):
                    tname = c['name']
                    break
        names = sorted(e['handlers'])
        for h in list(names):
            for s in e['strip']:
                if h.startswith(s):
                    names.append(h[len(s):])
        st = docs.by_name(*names)
        files = ic.get('docs')
        ctx = context_words(cfg, 'ioctls') or IOCTL_CONTEXT
        if number >= int(ic.get('min_decimal', 100)):
            st = best_of(st, docs.best(docs.dec_hits([number], files, ctx)))
        st = best_of(st, docs.best(docs.value_hits([number], files, ctx, absolute=())))
        row = {'number': number, 'hex': '0x%x' % number, 'table': tname, 'handler': short_list(e['handlers'], 4),
               'evidence': ','.join(sorted(e['ev'])), 'senders': short_list(e['senders'], 4),
               'binaries': len(e['bins']), 'example': e['ex'] or ''}
        put_status(row, st)
        rows.append(row)
    out['ioctls'] = rows

    # ---------------------------------------------------------------- ucode
    rows = []
    labels = {}
    truncated = []
    for src in cfg.get('ucode', []):
        t = src['type']
        if t == 'table':
            c = src['columns']
            for r in table_rows(src, tmp):
                name = r.get(c['name'], '').strip() if c.get('name') else ''
                kind = src.get('kind', 'symbol')
                for pat, k in src.get('kind_by_name', {}).items():
                    if re.search(pat, name):
                        kind = k
                detail = ' '.join('%s=%s' % (d, r[d]) for d in c.get('detail', []) if r.get(d))
                row = {'program': src['program'], 'kind': kind, 'address': r.get(c['address'], ''),
                       'name': name, 'detail': detail, '_names': [name]}
                if src.get('pointer'):
                    row['_pointer'] = (src['program'], r.get(c['address'], ''), name, False)
                    row['_names'] = []
                rows.append(row)
        elif t == 'symbols':
            p = os.path.join(REPO, fmt(src['file'], tmp))
            if not os.path.exists(p):
                continue
            for ln in open(p, encoding='utf-8', errors='replace'):
                parts = ln.split()
                if len(parts) == 2 and re.fullmatch(r'(0x)?[0-9a-fA-F]+', parts[1]):
                    labels.setdefault((src['program'], int(parts[1], 16)), []).append(parts[0])
                    rows.append({'program': src['program'], 'kind': src.get('kind', 'label'), 'address': parts[1],
                                 'name': parts[0], 'detail': '', '_names': [parts[0]]})
        elif t == 'u16-table':
            p = os.path.join(REPO, fmt(src['file'], tmp))
            if not os.path.exists(p):
                continue
            d = open(p, 'rb').read()
            take = min(len(d) // 2, int(src.get('limit', 1 << 30)))
            if take < len(d) // 2:
                truncated.append('%s: %d of %d entries' % (src['program'], take, len(d) // 2))
            for k in range(take):
                v = struct.unpack('>H', d[2 * k:2 * k + 2])[0]
                name = labels.get((src['labels'], v), [''])[0]
                rows.append({'program': src['program'], 'kind': src.get('kind', 'dispatch slot'), 'address': str(k),
                             'name': name, 'detail': 'handler 0x%x' % v, '_names': [],
                             '_pointer': (src['program'], str(k), name, v == 0)})
        elif t == 'records':
            rows += record_routines(src)
    for r in rows:
        ptr = r.pop('_pointer', None)
        if ptr is not None:
            st = pointer_status(docs, *ptr)
            r.pop('_names', None)
            put_status(r, st)
            continue
        st = docs.by_name(*[n for n in r.pop('_names', []) if n])
        rec = r.pop('_record', None)
        if rec is not None and st[0] != 'understood':
            st = best_of(st, record_status(docs, rec, cfg))
        put_status(r, st)
    out['ucode'] = rows

    # ---------------------------------------------------------------- functions and binaries
    # A name that several builds define with different code is understood in the build an entry
    # cites. Builds whose code is the same (equal code_sha) share the credit; any other build is
    # at most located. A name with one code in every build needs no citation.
    name_rows = code_groups(funcs, out['ucode'])
    token_images = collections.defaultdict(set)     # path written in a document -> binaries it names
    for img in imgs:
        for lab in [img['label']] + img['copies']:
            for k in image_keys(lab):
                token_images[k].add(img['label'])
    cited = {}

    def cited_groups(ent, name):
        k = (id(ent), name)
        if k not in cited:
            rows_of, out = name_rows[name], set()
            for t in ent.tokens():
                t = re.sub(r'^(?:\./|/)+', '', t.strip('.,;:'))
                t = t[5:] if t.startswith('root/') else t
                got = {rows_of[b] for b in token_images.get(t, ()) if b in rows_of}
                if len(got) == 1:
                    out |= got
            cited[k] = out
        return cited[k]

    rows = []
    brows = []
    for img in imgs:
        lab = img['label']
        g = img['group']
        fl = funcs.get(lab, {})
        for name in sorted(fl, key=lambda n: (fl[n][1] or 0, n)):
            sec, addr, size, srcs, csha = fl[name]
            addr = 0 if addr is None else addr
            row = {'binary': lab, 'role': g['role'], 'abi': abi.get(lab, '-'), 'elf_section': sec,
                   'address': '0x%x' % addr, 'size': size or '', 'name': name, 'source': '+'.join(sorted(srcs)),
                   'code_sha': csha}
            grp = name_rows[name][lab]
            demote = None
            if len(set(name_rows[name].values())) > 1:
                demote = lambda h, name=name, grp=grp: h.ent is None or grp not in cited_groups(h.ent, name)
            # a name defined in several compilation units cannot be tied to one function by name: only an
            # entry that cites an address inside this row's function credits it. Several names at one
            # address are rejected outright, at most named-only
            fi = finfo.get(lab, {})
            row['_multi'] = name in fi.get('multi_unit', ())
            row['_shared'] = name in fi.get('shared_address', ())
            row['rejected'] = '+'.join(w for w, f in (('multi-unit', row['_multi']), ('shared-address', row['_shared'])) if f)
            hits = docs.name_hits(name)
            if row['_multi']:
                hits = [h for h in hits if h.ent is not None and cites_range(h.ent.text, addr, size)]
            put_status(row, docs.best(hits, demote))
            if row['_multi'] and row['status'] == 'undocumented' and docs.name_hits(name):
                row['status'] = 'named-only'
            if row['_shared'] and RANK[row['status']] > RANK['named-only']:
                row['status'], row['_open'], row['_computes'] = 'named-only', False, False
            rows.append(row)
        base = os.path.basename(img['path'])
        mine = set()
        for l in [lab] + img['copies']:
            mine |= image_keys(l)

        def accept(path, lab=lab, mine=mine):
            path = re.sub(r'^(?:\./|/)+', '', path.strip('.,;:'))
            path = path[5:] if path.startswith('root/') else path
            return path in mine and token_images.get(path) == {lab}
        st = docs.by_file([img['member'] or base] + ([base] if img['member'] else []), accept)
        unr = sum(v for (b, w), v in unresolved.items() if b == lab)
        row = {'binary': lab, 'group': g['group'], 'role': g['role'], 'kind': kinds.get(lab, 'data'),
               'abi': abi.get(lab, '-'), 'bytes': meta[lab].get('size', ''), 'sha256': img['sha'][:16],
               'copies': ';'.join(img['copies']), 'functions': len(fl),
               'address_source': finfo.get(lab, {}).get('address_source', ''), 'access_sites': sites.get(lab, 0),
               'unresolved_sites': unr}
        put_status(row, st)
        brows.append(row)
    scope_report, scope_problems = apply_scope(cfg, imgs, rows, touch)
    if scope_problems:
        sys.exit('inventory: refusing to write tables, the scope rules are wrong:\n  ' + '\n  '.join(scope_problems))
    out['functions'] = rows
    out['binaries'] = brows

    for t in TABLES:
        write_tsv(os.path.join(a.out, t + '.tsv'), t, out[t])
    # ---------------------------------------------------------------- summary
    total_unres = sum(unresolved.values())
    resolved_sites = sum(e['sites'] for e in mmio.values())
    audits = read_audits(os.path.join(a.out, 'audits.tsv'))
    srows = []
    for t in TABLES:
        srows.append(summary_row(t, out[t], total_unres if t == 'mmio' else '',
                                 sum(1 for r in out[t] if r.get('_out'))))
        if t == 'ucode':
            srows[-1]['truncated'] = '; '.join(truncated)
            srows[-1]['computes'] = sum(1 for r in out[t] if r['status'] == 'understood' and r.get('_computes'))
        if t == 'functions':
            best = {}
            for r in out['functions']:
                if r.get('_out'):
                    continue
                if r['name'] not in best or RANK[r['status']] > RANK[best[r['name']]['status']]:
                    best[r['name']] = r
            out_names = {r['name'] for r in out['functions'] if r.get('_out')} - set(best)
            srows.append(summary_row('functions (distinct names)', list(best.values()), '', len(out_names)))
            srows[-1]['multi_unit'] = srows[-1]['shared_address'] = ''
    for r in srows:
        au = audits.get(r['table'])
        if au:
            r['audited_real_pct'], r['audited_sample'], r['audited_date'] = au['pct'], au['n'], au['date']
    for t in truncated:
        print('WARNING: table read in part, %s' % t, file=sys.stderr)
    # one row per binary that has functions, after the tables
    by_bin = collections.OrderedDict()
    for r in out['functions']:
        by_bin.setdefault(r['binary'], []).append(r)
    bin_rows = [summary_row('functions in ' + b, rs, '', sum(1 for r in rs if r.get('_out')))
                for b, rs in by_bin.items()]
    write_tsv(os.path.join(a.out, 'summary.tsv'), 'summary', srows + inputs + bin_rows)
    for r in srows:
        print('%-28s %7s  out-of-scope %5s  understood %6s (%5s%%, %s with open, %s distinct, %s templated)  '
              'located-or-better %5s%%  mentioned %5s%%  nsd %5s' %
              (r['table'], r['rows'], r['out_of_scope'], r['understood'], r['pct_understood'], r['understood_with_open'],
               r['understood_distinct'], r['templated'], r['pct_located_or_better'], r['pct_mentioned'], r['no_software_dependency']),
              file=sys.stderr)
    by_win = collections.Counter()
    for (b, w), v in unresolved.items():
        by_win[w] += v
    print('register access sites: %d resolved, %d unresolved (%s)' %
          (resolved_sites, total_unres, ', '.join('%s %d' % kv for kv in sorted(by_win.items()))), file=sys.stderr)
    if not a.no_coverage:
        update_coverage(cfg, srows, imgs, kinds, resolved_sites, total_unres, by_win, sibrep, inputs, scope_report)


REG_CONTEXT = ('register', 'offset', 'pio', 'window', 'fifo', 'port', 'status', 'flag', 'store', 'load',
               'read', 'write', 'address', 'field', 'word', 'command', 'block', 'bit', 'mask', 'interrupt',
               'dma', 'reset', 'base', 'map', 'token')
IOCTL_CONTEXT = ('ioctl',)


def cites_range(text, addr, size):
    """True when the text writes an absolute address inside [addr, addr + size): the citation that ties an
    entry to one of several same-named functions. An offset (+0x...) is not an address."""
    if not addr or not size:
        return False
    return any(not m.group(1) and addr <= int(m.group(2), 16) < addr + size for m in HEXLIT.finditer(text))


def code_groups(funcs, ucode_rows):
    """{name: {binary or program: code group}} for the per-build credit of the functions table. Builds with
    equal code share a group. A microcode program that defines the same name (an arm1.u symbol and an
    ELF function both called nic_setup) is a group of its own, so an entry about the microcode routine
    does not credit the ELF function: the entry has to cite the binary, as for any other second build."""
    groups = collections.defaultdict(dict)
    for lab, fl in funcs.items():
        for name, e in fl.items():
            groups[name][lab] = e[4] or 'L:' + lab
    for r in ucode_rows:
        if r.get('name') and r['name'] in groups:
            groups[r['name']].setdefault('U:' + r['program'], 'U:' + r['program'])
    return groups


def record_routines(src):
    """Routines of a fixed-record microcode image: one starts at record 0, a fixed distance after
    each end-mark record and at every host entry point."""
    import importlib
    mod = importlib.import_module(src['module']) if src.get('module') else None

    def attr(k, default=None):
        v = src.get(k)
        if isinstance(v, str) and v.startswith('module.'):
            return getattr(mod, v[7:])
        return default if v is None else v
    entries = set(attr('entries', []))
    ram = attr('ram_records')
    rows = []
    seen = set()
    for img in src['images']:
        p = os.path.join(REPO, img['path'])
        if not os.path.exists(p):
            continue
        data = open(p, 'rb').read()
        h = hashlib.sha256(data).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        size = int(src['record_bytes'])
        n = len(data) // size
        recs = [int.from_bytes(data[i * size:(i + 1) * size], 'big') for i in range(n)]
        ends = [i for i, w in enumerate(recs) if (w & num(src['end_mask'])) in [num(x) for x in src['end_values']]]
        ent = set()
        ins_at, ins_len = attr('insert_at'), attr('insert_len')
        for e in entries:
            if img.get('kernel_copy') and ins_at is not None and e >= ins_at:
                if e < ins_at + ins_len:
                    continue
                e -= ins_len
            ent.add(e)
        after = int(src['start_after_end'])
        starts = {0} | {i + after for i in ends if i + after < n} | {e for e in ent if e < n}
        prog = os.path.basename(p)
        for s in sorted(starts):
            k = bisect.bisect_left(ends, s)
            end = ends[k] if k < len(ends) else -1
            kind = 'host entry' if s in ent else ('image start' if s == 0 else 'follows end mark')
            detail = 'end_mark=%d records=%d' % (end, (end - s + 1) if end >= 0 else 0)
            if ram is not None:
                detail += ' beyond_ram=%s' % ('yes' if s >= ram else 'no')
            rows.append({'program': prog, 'kind': kind, 'address': str(s), 'name': '', 'detail': detail,
                         '_names': [], '_record': s})
    return rows


def pointer_status(docs, program, index, target, zero):
    """A row of a pointer table (a slot, an entry, a command that names a handler) is credited only
    by an entry whose subject is that slot. What its handler is documented as is a mention of the
    handler, not of the slot; an entry that holds 0 points nowhere and is located by the file."""
    k = num(index) if re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|\d+)', str(index).strip()) else None
    st = docs.best(docs.slot_hits(k, (program, target))) if k is not None else ('undocumented', '', '', '', False)
    if RANK[st[0]] < RANK['located'] and zero:
        return ('located', '', '', '', False)
    if st[0] == 'undocumented' and target and docs.by_name(target)[0] != 'undocumented':
        return ('named-only', '', '', '', False)
    return st


def record_status(docs, v, cfg):
    words = cfg.get('docs', {}).get('context', {}).get('ucode') or ('entry', 'entries', 'routine', 'record')
    return docs.best([h for h in docs.decs.get(v, []) if ctx_match(h.ctx, words)])


def read_audits(path):
    """The latest independent audit of each table, from docs/inventory/audits.tsv: the sampled rows
    graded real, shallow or wrong by someone who did not write them. The last row of a table with the
    latest date wins."""
    got = {}
    if not os.path.exists(path):
        return got
    for r in read_tsv(path):
        try:
            n, real = int(r['sample']), int(r['real'])
        except (KeyError, ValueError):
            continue
        t = r.get('table', '')
        if n > 0 and (t not in got or r['date'] >= got[t]['date']):
            got[t] = {'date': r['date'], 'n': n, 'real': real, 'pct': '%.1f' % (100.0 * real / n),
                      'shallow': r.get('shallow', ''), 'wrong': r.get('wrong', '')}
    return got


def summary_row(name, rows, unresolved, out_of_scope=0):
    """The counts of one table. Rows a scope rule excluded (`_out`) are left out of every count and are
    reported in `out_of_scope`, so the denominator never hides them."""
    rows = [r for r in rows if not r.get('_out')]
    c = collections.Counter(r['status'] for r in rows)
    distinct = len({r.get('_skel', '') for r in rows if r['status'] == 'understood'})
    templated = sum(1 for r in rows if r.get('_templated'))
    n = len(rows)

    def pct(x):
        return '%.1f' % (100.0 * x / n) if n else '0.0'
    nsd = c['no-software-dependency']
    opened = sum(1 for r in rows if r['status'] == 'understood' and r.get('_open'))
    flagged = any('_multi' in r for r in rows)
    return {'reused': sum(1 for r in rows if r.get('_reused')),
            'multi_unit': sum(1 for r in rows if r.get('_multi')) if flagged else '',
            'shared_address': sum(1 for r in rows if r.get('_shared')) if flagged else '',
            'table': name, 'rows': n, 'out_of_scope': out_of_scope, 'understood': c['understood'], 'understood_with_open': opened,
            'understood_distinct': distinct,
            'templated': templated, 'located': c['located'],
            'named_only': c['named-only'], 'undocumented': c['undocumented'], 'no_software_dependency': nsd,
            'pct_understood': pct(c['understood']),
            'pct_located_or_better': pct(c['understood'] + c['located'] + nsd),
            'pct_mentioned': pct(n - c['undocumented']),
            'pct_done': pct(c['understood'] + nsd), 'unresolved_sites': unresolved}


def update_coverage(cfg, srows, imgs, kind, resolved, unres, by_win, sib, inputs, scope_report=()):
    path = os.path.join(REPO, 'docs', 'coverage.md')
    if not os.path.exists(path):
        return
    text = open(path, encoding='utf-8').read()
    elf = sum(1 for i in imgs if kind.get(i['label'], 'data') != 'data')
    lines = [MARK_BEGIN, '## Measured coverage', '',
             'Generated by `scripts/inventory.py` from %d distinct files in scope, %d of them ELF images. '
             'The rows are in [docs/inventory/](inventory/README.md), which defines every column and status. '
             'The headline is the share **understood**: an entry that states a role and hardware effect, '
             'labelled established or inferred, with a derivation specific to its subject. A mention alone '
             '(named only) is not understanding, and an entry credits only its subject. A row is done when it '
             'is understood or labelled as having no software dependency. "Distinct" counts the differently '
             'worded entries behind the understood rows, so templated bulk shows.'
             % (len(imgs), elf), '',
             '| Table | Rows | Out of scope | % understood | % located or better | % mentioned | Understood | '
             'With open | Distinct | Located | No software dependency | Named only | Undocumented |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in srows:
        link = r['table'] if r['table'] in TABLES else None
        label = '[%s](inventory/%s.tsv)' % (link, link) if link else r['table']
        lines.append('| %s | %d | %d | %s | %s | %s | %d | %d | %d | %d | %d | %d | %d |' % (
            label, r['rows'], r['out_of_scope'], r['pct_understood'], r['pct_located_or_better'], r['pct_mentioned'],
            r['understood'], r['understood_with_open'], r['understood_distinct'], r['located'], r['no_software_dependency'],
            r['named_only'], r['undocumented']))
    if scope_report:
        total = sum(x['rows'] for x in scope_report)
        every = next((r['rows'] + r['out_of_scope'] for r in srows if r['table'] == 'functions'), 0)
        lines += ['', '### Scope', '',
                  '%d of the %d function rows (%.1f%%) are out of scope: the rules of the config\'s `scope` list '
                  'name them, one reason each, and `functions.tsv` marks them `out:<rule>` in `scope`. The rows, '
                  'percentages and counts of every other column leave them out; the `Out of scope` column and '
                  'the table below keep the excluded rows in view. A function that reaches a register window, a '
                  'token or an ioctl cannot be excluded: the run fails.' %
                  (total, every, 100.0 * total / every if every else 0.0), '',
                  '| Rule | Binaries | Rows | Reason |', '|---:|---|---:|---|']
        for x in scope_report:
            lines.append('| %d | %s | %d | %s |' % (x['rule'], x['binaries'].replace('|', '\\|'), x['rows'],
                                                  x['reason'].replace('|', '\\|')))
    audited = [r for r in srows if r.get('audited_date')]
    if audited:
        lines += ['', '### Audited', '',
                  'The share of understood rows that an independent audit found real when it re-derived a '
                  'random sample from the binaries ([docs/inventory/audits.tsv](inventory/audits.tsv); the '
                  'sample is small, so read the sample size). The percentages above are what the entries claim; '
                  'this is how often the claim held up.', '',
                  '| Table | Audited real | Sample | Date |', '|---|---:|---:|---|']
        for r in audited:
            lines.append('| %s | %s%% | %s | %s |' % (r['table'], r['audited_real_pct'], r['audited_sample'],
                                                    r['audited_date']))
    checks = ['Cross-workspace role check: ' + (
        'compared %d entries with the entries of %s for the same function and capped %d at located (the role '
        'text is the sibling\'s, at least %d%% alike, and states no offset, immediate value or callee address '
        'of its own build).' % (sib['compared'], ' and '.join(sib['siblings']), sib['reused'], round(100 * SIMILAR))
        if sib['siblings'] else 'skipped.')]
    for name, why in sib['skipped']:
        checks.append('Skipped: sibling %s (%s). Rows are graded without it.' % (name, why))
    checks.append('Inputs (also in [summary.tsv](inventory/summary.tsv)): ' + '; '.join(
        '%s %s' % (r['table'][6:], (r['input'][:16] + (', %d files' % r['rows'] if r.get('rows') else ''))
                   if r['table'] == 'input root manifest' else r['input'][:12]) for r in inputs) + '.')
    fr = next((r for r in srows if r['table'] == 'functions'), None)
    if fr is not None and fr.get('multi_unit') != '':
        checks.append('Function rows rejected as ambiguous, at most named-only: %s whose name is defined in several '
                      'compilation units, %s whose address another name shares (a row can be in both).'
                      % (fr['multi_unit'], fr['shared_address']))
    lines += ['', '\n\n'.join(checks)]
    notes = [r for r in srows if r.get('truncated')]
    for r in notes:
        lines += ['', 'Read in part: %s (%s).' % (r['table'], r['truncated'])]
    tot = resolved + unres
    lines += ['',
              'Register access sites: %d found, %d resolved to an offset and %d (%s%%) unresolved, where the base '
              'is a known register window but the offset could not be traced.%s' % (
                  tot, resolved, unres, ('%.1f' % (100.0 * unres / tot)) if tot else '0.0',
                  (' Unresolved by window: %s.' % ', '.join('%s %d' % kv for kv in sorted(by_win.items())))
                  if by_win else ''),
              '', MARK_END]
    block = '\n'.join(lines)
    span = generated_span(text)
    if span:
        text = text[:span[0]] + block + text[span[1]:]
    else:
        i = text.find('\n## ')
        text = (text[:i] + '\n\n' + block + '\n' + text[i:]) if i >= 0 else text + '\n' + block + '\n'
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


if __name__ == '__main__':
    main()
