#!/usr/bin/env python3
"""Field tables for the kernel structures named in docs/inventory/structs.tsv.

Usage: scripts/struct_fields.py [--list] [--max N]

Run it from the repository root with root/ populated, inside the toolchain container
(tools/re-run python3 scripts/struct_fields.py). For each in-scope structure name (the rows of
docs/inventory/structs.tsv whose scope is `in`) it reads the DWARF definition of that structure in
each linked kernel, root/*/unix.IP*, and writes docs/structs/<name>.md: one row per member with its
byte offset, size, name and type spelling.

A structure is documented only when two linked kernels agree on it: the same byte size, and the
same members in the same order with the same offsets, sizes and type spellings. The table comes
from the first agreeing kernel in sorted order, and the page names every kernel that agreed. A
kernel with a different definition is named with its size and is not shown. A name defined in only
one kernel, or with two different definitions inside one kernel, is not documented and gets no page.

A structure that the linked kernels define only once (or not at all) is tried again against the
kernel objects of the primary release, root/<primary>/usr/cpu/sysgen/IP*boot/*.o, under the same
rule: two objects must agree, and the page names the objects. Objects of other releases are not
used, so a fact from one release never fills a gap in another.

The DWARF is read from dwarfdump's text, as scripts/os_tables.py reads it. pyelftools rejects the
DWARF of these kernels (a zero address size in a unit header). The source file of a declaration
(DW_AT_decl_file) is never read or written.

--list prints the decision for every in-scope name and writes nothing. --max N writes at most N
pages in this run, skipping pages that already match, so a run can be committed in batches.
Pages whose name no longer qualifies are reported as stale and left alone.
"""
import collections
import glob
import os
import re
import subprocess
import sys

# The workspace comes from the current directory (tools/_workspace.py), not from this file's path.
TOOLS = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, TOOLS)
from _workspace import find_workspace  # noqa: E402
REPO = find_workspace()

DIE_RE = re.compile(r'^<\s*(\d+)><0x([0-9a-fA-F]+)>\s+DW_TAG_(\w+)\s*$')
ATTR_RE = re.compile(r'^\s+DW_AT_(\w+)\s*(.*?)\s*$')
OP_RE = re.compile(r'^\s+DW_OP_(\w+)(?:\s+(-?\d+))?\s*$')
REF_RE = re.compile(r'<0x([0-9a-fA-F]+)>')
QUALIFIERS = {'const_type': 'const', 'volatile_type': 'volatile', 'restrict_type': 'restrict'}


class Die:
    __slots__ = ('off', 'tag', 'attr', 'kids', 'parent', 'cu')

    def __init__(self, off, tag, parent, cu):
        self.off, self.tag, self.parent, self.cu = off, tag, parent, cu
        self.attr, self.kids = {}, []


def parse_dies(text):
    """Return every DIE of a dwarfdump -i listing, one {offset: DIE} map per unit.

    The offsets in the listing restart in each unit, so a reference resolves inside the unit
    that holds it.
    """
    units, stack, cur, pending, cu = [], [], None, None, None
    for line in text.splitlines():
        m = DIE_RE.match(line)
        if m:
            depth, off = int(m.group(1)), int(m.group(2), 16)
            if depth == 0:
                cu = {}
                units.append(cu)
            del stack[depth:]
            parent = stack[depth - 1] if depth else None
            cur = Die(off, m.group(3), parent, cu)
            if parent is not None:
                parent.kids.append(cur)
            stack.append(cur)
            cu[off] = cur
            pending = None
            continue
        if cur is None:
            continue
        if pending is not None:
            om = OP_RE.match(line)
            if om:
                cur.attr[pending].append((om.group(1), om.group(2)))
                continue
            pending = None
        am = ATTR_RE.match(line)
        if am:
            name, val = am.group(1), am.group(2)
            if val.startswith('len '):
                cur.attr[name] = []
                pending = name
            else:
                cur.attr[name] = val
    return units


def num(die, name, default=None):
    if name not in die.attr:
        return default
    return int(die.attr[name].split()[0], 0)


def text(die, name):
    return die.attr.get(name)


def ref(die, name):
    if name not in die.attr:
        return None
    m = REF_RE.search(die.attr[name])
    if not m:
        raise ValueError('no reference in DW_AT_%s of 0x%x' % (name, die.off))
    off = int(m.group(1), 16)
    if off not in die.cu:
        raise ValueError('dangling reference 0x%x from 0x%x' % (off, die.off))
    return die.cu[off]


def member_offset(die):
    if 'data_member_location' not in die.attr:
        return 0
    v = die.attr['data_member_location']
    if isinstance(v, str):
        return int(v.split()[0], 0)
    if len(v) != 1:
        raise ValueError('member expression with %d operations' % len(v))
    op, arg = v[0]
    if op in ('consts', 'constu', 'plus_uconst'):
        return int(arg)
    if op.startswith('lit'):
        return int(op[3:])
    raise ValueError('unhandled member location DW_OP_%s' % op)


def array_dims(t):
    dims = []
    for k in t.kids:
        if k.tag != 'subrange_type':
            continue
        if 'count' in k.attr:
            dims.append(num(k, 'count'))
        elif 'upper_bound' in k.attr:
            ub = num(k, 'upper_bound')
            if 0x80000000 <= ub < 0x100000000:
                ub -= 1 << 32
            dims.append(ub + 1)
        else:
            dims.append(None)
    base = ref(t, 'type')
    if base is not None and base.tag == 'array_type':
        inner, base = array_dims(base)
        dims += inner
    return dims, base


def type_size(t):
    if t is None:
        return 0
    if 'byte_size' in t.attr:
        return num(t, 'byte_size')
    if t.tag in QUALIFIERS or t.tag == 'typedef':
        return type_size(ref(t, 'type'))
    if t.tag == 'array_type':
        dims, base = array_dims(t)
        if None in dims:
            return 0
        n = 1
        for d in dims:
            n *= d
        return n * type_size(base)
    if t.tag == 'subroutine_type':
        return 0
    raise ValueError('no size for DW_TAG_%s at 0x%x' % (t.tag, t.off))


def type_name(t):
    if t is None:
        return 'void'
    if t.tag in ('base_type', 'typedef', 'unspecified_type'):
        return text(t, 'name')
    if t.tag in ('structure_type', 'union_type', 'enumeration_type'):
        word = {'structure_type': 'struct', 'union_type': 'union', 'enumeration_type': 'enum'}[t.tag]
        name = text(t, 'name')
        return '%s %s' % (word, name) if name else '%s (unnamed)' % word
    if t.tag in QUALIFIERS:
        inner = ref(t, 'type')
        if inner is not None and inner.tag == 'pointer_type':
            return type_name(inner) + ' ' + QUALIFIERS[t.tag]
        return '%s %s' % (QUALIFIERS[t.tag], type_name(inner))
    if t.tag == 'pointer_type':
        inner = ref(t, 'type')
        if inner is None:
            return 'void *'
        if inner.tag == 'array_type':
            dims, base = array_dims(inner)
            return '%s (*)%s' % (type_name(base), ''.join('[%s]' % ('' if d is None else d) for d in dims))
        if inner.tag == 'subroutine_type':
            return 'function pointer'
        if inner.tag == 'pointer_type':
            return type_name(inner) + '*'
        return type_name(inner) + ' *'
    if t.tag == 'array_type':
        dims, base = array_dims(t)
        return type_name(base) + ''.join('[%s]' % ('' if d is None else d) for d in dims)
    if t.tag == 'subroutine_type':
        return 'function'
    raise ValueError('no type spelling for DW_TAG_%s at 0x%x' % (t.tag, t.off))


def layout(s):
    """(byte size, members) of a structure DIE; a member is (bit_offset_or_None, byte_offset, size, name, type)."""
    members = []
    for m in s.kids:
        if m.tag != 'member':
            continue
        t = ref(m, 'type')
        name = text(m, 'name') or '(unnamed)'
        tname = type_name(t)
        if 'bit_size' in m.attr:
            storage = num(m, 'byte_size') or type_size(t)
            bit = num(m, 'bit_offset')
            if bit is None:
                raise ValueError('bit field without DW_AT_bit_offset in 0x%x' % m.off)
            members.append((bit, member_offset(m), num(m, 'bit_size'), name, tname, storage))
        else:
            members.append((None, member_offset(m), type_size(t), name, tname, None))
    return num(s, 'byte_size'), tuple(members)


def definitions(path, keep=None):
    """Structure name -> set of layouts for the named, complete definitions in one kernel or object.

    With keep, only those names are returned.
    """
    out = subprocess.run(['dwarfdump', '-i', path], capture_output=True, text=True, errors='replace').stdout
    found = collections.defaultdict(set)
    for unit in parse_dies(out):
        for s in unit.values():
            if s.tag != 'structure_type' or 'declaration' in s.attr or 'byte_size' not in s.attr:
                continue
            name = text(s, 'name')
            if name and (keep is None or name in keep):
                found[name].add(layout(s))
    return found


PRIMARY_RELEASE = '6.5.30'


def kernels():
    return sorted(glob.glob(os.path.join(REPO, 'root', '*', 'unix.IP*')))


def objects():
    return sorted(glob.glob(os.path.join(REPO, 'root', PRIMARY_RELEASE, 'usr', 'cpu', 'sysgen', 'IP*boot', '*.o')))


def in_scope_names():
    import json
    scope = json.load(open(os.path.join(REPO, 'scripts', 'scope.json')))
    spre = re.compile('(?:%s)' % '|'.join(scope['structure_prefixes']))
    path = os.path.join(REPO, 'docs', 'inventory', 'structs.tsv')
    with open(path, encoding='utf-8') as f:
        heads = f.readline().rstrip('\n').split('\t')
        rows = [ln.rstrip('\n').split('\t') for ln in f]
    ni, si = heads.index('name'), heads.index('scope')
    return sorted({r[ni] for r in rows if r[si] == 'in' and spre.match(r[ni])})


def decide(name, per_image):
    """Return (status, primary label, agreeing labels, other labels) for one structure name."""
    groups = collections.defaultdict(list)
    conflicts = []
    for label, found in per_image:
        defs = found.get(name)
        if not defs:
            continue
        if len(defs) > 1:
            conflicts.append(label)
            continue
        groups[next(iter(defs))].append(label)
    if not groups:
        return 'no-definition', None, [], conflicts
    ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[1][0]))
    best_layout, best = ranked[0]
    if len(best) < 2:
        return 'one-kernel', None, [], [l for _, ls in ranked for l in ls] + conflicts
    if len(ranked) > 1 and len(ranked[1][1]) >= 2:
        return 'disagree', None, [], [l for _, ls in ranked for l in ls] + conflicts
    others = [l for lay, ls in ranked[1:] for l in ls] + conflicts
    return 'documented', (best_layout, best), best, others


def choose(name, images):
    """(status, chosen, agreed, others, sizes) for one name over one set of (label, definitions) images."""
    status, chosen, agreed, others = decide(name, images)
    sizes = {}
    if status == 'documented':
        for label, found in images:
            if label in others and name in found and len(found[name]) == 1:
                sizes[label] = next(iter(found[name]))[0]
    return status, chosen, agreed, others, sizes


def render(name, layout_, agreed, others, per_image_layouts, kind):
    size, members = layout_
    lines = ['# `%s`' % name, '']
    lines.append('Object: `%s`, %s. Layout: %d bytes, %d member%s.'
                 % (agreed[0], kind, size, len(members), '' if len(members) == 1 else 's'))
    lines.append('Checked against: %s. Same size, members, offsets, sizes and type spellings.'
                 % ', '.join('`%s`' % a for a in agreed[1:]))
    for label in others:
        osize = per_image_layouts.get(label)
        if osize is None:
            lines.append('Not the same: `%s` has no single definition here; not shown.' % label)
        else:
            lines.append('Not the same: `%s` is %d bytes with a different member list; not shown.' % (label, osize))
    if any(m[0] is not None for m in members):
        lines.append('Bit fields: the bit offset counts from the most significant bit of the storage unit, '
                     'as DW_AT_bit_offset does.')
    lines += ['', 'Generated by scripts/struct_fields.py from the DWARF definition. Do not edit.', '',
              '| Offset | Size | Member | Type |', '|---:|---:|---|---|']
    for bit, off, size, mname, tname, storage in members:
        if bit is None:
            lines.append('| %d (0x%x) | %d | `%s` | `%s` |' % (off, off, size, mname, tname))
        else:
            lines.append('| %d bit %d | %d bits | `%s` | `%s` |' % (off, bit, size, mname, tname))
    return '\n'.join(lines) + '\n'


def main():
    args = sys.argv[1:]
    list_only = '--list' in args
    limit = int(args[args.index('--max') + 1]) if '--max' in args else None
    imgs = kernels()
    if not imgs:
        sys.exit('no linked kernels under root/*/unix.IP*')
    per_image = []
    for k in imgs:
        label = os.path.relpath(k, os.path.join(REPO, 'root'))
        per_image.append((label, definitions(k)))
    outdir = os.path.join(REPO, 'docs', 'structs')
    names = in_scope_names()
    linked = {name: choose(name, per_image) for name in names}
    # Only a name the linked kernels leave alone (no definition, or one kernel) is tried against objects.
    fallback = {name for name, c in linked.items() if c[0] in ('no-definition', 'one-kernel')}
    per_object = []
    for o in objects() if fallback else []:
        label = os.path.relpath(o, os.path.join(REPO, 'root'))
        per_object.append((label, definitions(o, fallback)))
    written, wanted = 0, set()
    for name in names:
        status, chosen, agreed, others, sizes = linked[name]
        kind = 'a linked kernel'
        if name in fallback:
            ostatus, ochosen, oagreed, oothers, osizes = choose(name, per_object)
            if list_only and ostatus != 'documented':
                print('%-40s %s  (linked kernels: %s)' % (name, ostatus, status))
            if ostatus == 'documented':
                status, chosen, agreed, others, sizes = ostatus, ochosen, oagreed, oothers, osizes
                kind = 'a kernel object'
        if status != 'documented':
            if list_only and name not in fallback:
                print('%-40s %s' % (name, status))
            continue
        wanted.add(name)
        if list_only:
            print('%-40s documented  %s  others=%s' % (name, ','.join(agreed), ','.join(others) or '-'))
            continue
        page = render(name, chosen[0], agreed, others, sizes, kind)
        path = os.path.join(outdir, name + '.md')
        if os.path.exists(path) and open(path, encoding='utf-8').read() == page:
            continue
        if limit is not None and written >= limit:
            continue
        os.makedirs(outdir, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(page)
        written += 1
        print('wrote docs/structs/%s.md (%s)' % (name, ', '.join(agreed)))
    if not list_only and os.path.isdir(outdir):
        for p in sorted(glob.glob(os.path.join(outdir, '*.md'))):
            n = os.path.basename(p)[:-3]
            if n not in wanted:
                print('stale: docs/structs/%s.md no longer qualifies; left in place' % n)
    print('done %d, pending %d' % (written, len([n for n in wanted if not os.path.exists(os.path.join(outdir, n + '.md'))])))


if __name__ == '__main__':
    main()
