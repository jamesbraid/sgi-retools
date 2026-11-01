#!/usr/bin/env python3
"""Compare the controller firmware across the four shipped sets.

Usage: tools/re-run python3 scripts/version_diff.py [--out docs/version-diffs]

Three measurements, each written as TSV under docs/version-diffs/:

  l1-routines.tsv       routines of the Origin 300 L1 package (Fuel/PE, package 1) that
                        are added, removed or changed between consecutive sets
  l1-request-codes.tsv  the general request codes each set accepts, with the handler
                        address and whether its body matches the 1.44.0 handler
  l2-bytes.tsv          the L2 kernel and cramfs as byte measurements (no routine split yet)

Routine entries are link.w a6 prologues, absolute jsr and bsr targets and vector-table
handlers. A routine runs from its entry to the next entry. Text is decoded with capstone
(68040 mode, the ColdFire subset the compiler emitted) and in-image addresses are masked,
so a routine that only moved still matches. Pairing across a set boundary is by sequence
alignment of routine fingerprints; unmatched runs are paired by instruction-multiset
similarity at 0.5 or more and reported as changed, otherwise as removed and added.

Run in the toolchain container (capstone is not on the host).
"""
import bisect
import collections
import difflib
import hashlib
import json
import os
import re
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sysco_tables as st  # noqa: E402
import capstone  # noqa: E402

OUT = os.path.join(st.REPO, 'docs', 'version-diffs')
if '--out' in sys.argv:
    OUT = os.path.abspath(sys.argv[sys.argv.index('--out') + 1])

L1_SETS = [('1.24.8', '6.5.22'), ('1.32.15', 'patches/SG0005762'), ('1.44.0', '6.5.30'), ('1.48.1', 'patches/SG0007149')]
L2_SETS = [('1.24.1', '6.5.22'), ('1.32.4', 'patches/SG0005762'), ('1.44.0', '6.5.30'), ('1.48.0', 'patches/SG0007149')]
MIRROR = 0x70000          # the body holds the program twice, this far apart
SPAN = 0x200              # dispatch chain: branches that stay within this many bytes are local
THRESH = 0.5
ADDR_RE = re.compile(r'\$?ffe[0-9a-f]{5}\b')
RAM_RE = re.compile(r'\$?30[0-9a-f]{6}\b')
MD = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_M68K_040)
M = 0xffffffff


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fuel_package(rel):
    data = open(os.path.join(st.ROOT, rel, st.FW, 'l1.bin'), 'rb').read()
    for p in st.l1_packages(data):
        if not p['linux'] and 'Fuel/PE' in p['label']:
            return p
    raise SystemExit('no Fuel/PE package in ' + rel)


# ---- routines -------------------------------------------------------------------------

def decode(body, base, start, end):
    out, pos = [], start
    while pos < end:
        got = list(MD.disasm(body[pos:min(pos + 16, end)], base + pos, count=1))
        if got:
            i = got[0]
            out.append((i.address, i.size, i.mnemonic, i.op_str))
            pos += i.size
        else:
            out.append((base + pos, 2, 'dc.w', '$%04x' % int.from_bytes(body[pos:pos + 2], 'big')))
            pos += 2
    return out


def call_targets(insns, lo, hi):
    t = set()
    for _, _, mn, ops in insns:
        if mn.startswith(('bsr', 'jsr')):
            m = re.fullmatch(r'\$([0-9a-f]+)', ops.strip())
            if m and lo <= int(m.group(1), 16) < hi and int(m.group(1), 16) % 2 == 0:
                t.add(int(m.group(1), 16))
    return t


def routines(p):
    body, base = p['body'], p['load']
    n, lo, hi = len(body), p['load'], p['load'] + len(body)
    cands = {}
    for off in range(0, n - 1, 2):
        if body[off:off + 2] == b'\x4e\x56':
            cands.setdefault(off, set()).add('prologue')
    for m in re.finditer(b'\x4e\xb9', body):
        o = m.start()
        if o % 2 == 0 and o + 6 <= n:
            t = int.from_bytes(body[o + 2:o + 6], 'big')
            if lo <= t < hi and t % 2 == 0:
                cands.setdefault(t - base, set()).add('jsr')
    for o in range(0, 0x400, 4):
        t = int.from_bytes(body[o:o + 4], 'big')
        if lo <= t < hi and t % 2 == 0:
            cands.setdefault(t - base, set()).add('vector')
    for _ in range(6):
        offs = sorted(cands)
        new = set()
        for i, o in enumerate(offs):
            e = offs[i + 1] if i + 1 < len(offs) else n
            new |= {t - base for t in call_targets(decode(body, base, o, e), lo, hi)} - set(cands)
        if not new:
            break
        for o in new:
            cands.setdefault(o, set()).add('call')
    offs = sorted(cands)
    rows = []
    for i, o in enumerate(offs):
        e = offs[i + 1] if i + 1 < len(offs) else n
        ins = decode(body, base, o, e)
        norm = [('dc.w ' + ops) if mn == 'dc.w' else (mn + ' ' + ADDR_RE.sub('ADDR', ops)).strip()
                for _, _, mn, ops in ins]
        rows.append({'addr': base + o, 'end': base + e, 'bank': 'lo' if o < MIRROR else 'hi',
                     'len': e - o, 'nins': len(ins), 'raw_sha': sha(body[o:e]),
                     'norm_sha': sha('\n'.join(norm).encode()), 'norm': norm})
    return rows


def ram_norm(norm):
    return [RAM_RE.sub('RAM', s) for s in norm]


def jaccard(a, b):
    ca, cb = collections.Counter(a), collections.Counter(b)
    inter = sum((ca & cb).values())
    uni = sum((ca | cb).values())
    return inter / uni if uni else 1.0


def first_difference(a, b):
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    return i


def pair_routines(A, B):
    """Return (pairs, removed, added); pairs are (a, b, kind, similarity)."""
    sm = difflib.SequenceMatcher(None, [r['norm_sha'] for r in A], [r['norm_sha'] for r in B], autojunk=False)
    pairs, removed, added = [], [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for k in range(i2 - i1):
                ra, rb = A[i1 + k], B[j1 + k]
                kind = 'same-bytes' if ra['raw_sha'] == rb['raw_sha'] else 'same-code-moved'
                pairs.append((ra, rb, kind, 1.0))
            continue
        ra_, rb_ = A[i1:i2], B[j1:j2]
        cand = []
        for x, ra in enumerate(ra_):
            for y, rb in enumerate(rb_):
                if min(ra['nins'], rb['nins']) / max(ra['nins'], rb['nins'], 1) < 0.5:
                    continue
                s = jaccard(ra['norm'], rb['norm'])
                if s >= THRESH:
                    cand.append((s, x, y))
        cand.sort(key=lambda t: -t[0])
        ua, ub = set(), set()
        for s, x, y in cand:
            if x in ua or y in ub:
                continue
            ua.add(x)
            ub.add(y)
            pairs.append((ra_[x], rb_[y], 'changed', s))
        removed += [ra_[x] for x in range(len(ra_)) if x not in ua]
        added += [rb_[y] for y in range(len(rb_)) if y not in ub]
    return pairs, removed, added


def classify(ra, rb):
    if ra['raw_sha'] == rb['raw_sha']:
        return 'same-bytes'
    if ra['norm_sha'] == rb['norm_sha']:
        return 'same-code-moved'
    if ram_norm(ra['norm']) == ram_norm(rb['norm']):
        return 'changed-ram-address-only'
    return 'changed'


def routine_report(routine_rows):
    tsv = [['step', 'change', 'from_bank', 'from_addr', 'from_len', 'to_bank', 'to_addr', 'to_len',
            'similarity', 'first_difference_from', 'first_difference_to']]
    summary = collections.OrderedDict()
    for (a, pa), (b, pb) in zip(L1_SETS, L1_SETS[1:]):
        A, B = routine_rows[a], routine_rows[b]
        pairs, removed, added = pair_routines(A, B)
        cnt = collections.Counter()
        step = '%s -> %s' % (a, b)
        for ra, rb, _, s in pairs:
            kind = classify(ra, rb)
            cnt[kind] += 1
            if kind in ('same-bytes', 'same-code-moved'):
                continue
            i = first_difference(ra['norm'], rb['norm'])
            tsv.append([step, kind, ra['bank'], '%x' % ra['addr'], ra['len'], rb['bank'], '%x' % rb['addr'],
                        rb['len'], '%.3f' % s, ra['norm'][i] if i < len(ra['norm']) else '',
                        rb['norm'][i] if i < len(rb['norm']) else ''])
        for r in removed:
            cnt['removed'] += 1
            tsv.append([step, 'removed', r['bank'], '%x' % r['addr'], r['len'], '', '', '', '', '', ''])
        for r in added:
            cnt['added'] += 1
            tsv.append([step, 'added', '', '', '', r['bank'], '%x' % r['addr'], r['len'], '', '', ''])
        summary[step] = dict(cnt)
    return tsv, summary


def l1_routines():
    rows = {}
    for ver, rel in L1_SETS:
        p = fuel_package(rel)
        rows[ver] = routines(p)
    return rows


# ---- dispatch -------------------------------------------------------------------------

class Unmodelled(Exception):
    pass


def s32(v):
    v &= M
    return v - (1 << 32) if v & 0x80000000 else v


def reg_index(tok):
    t = tok.strip()
    if t == 'sp':
        return 15
    m = re.fullmatch(r'([da])([0-7])', t)
    if not m:
        raise Unmodelled(t)
    return int(m.group(2)) + (8 if m.group(1) == 'a' else 0)


def immediate(tok):
    t = tok.strip()
    if not t.startswith('#'):
        raise Unmodelled(t)
    return int(t[1:].replace('$', ''), 16) & M


def run_chain(body, base, entry, code):
    """Interpret the compare chain from the request-code load with d0..a7 = code."""
    d = [code & M] * 16
    Z = N = C = V = False
    pc = entry
    for _ in range(400):
        if not (entry <= pc < entry + SPAN):
            return ('handler', pc)
        ins = next(iter(MD.disasm(body[pc - base:pc - base + 16], pc, count=1)), None)
        if ins is None:
            raise Unmodelled('undecodable at %x' % pc)
        mn, ops = ins.mnemonic, ins.op_str
        bmn = mn.split('.')[0]
        nxt = pc + ins.size
        if bmn == 'move' and mn.endswith('.l'):
            a, b = [x.strip() for x in ops.split(',')]
            v = immediate(a) if a.startswith('#') else d[reg_index(a)]
            d[reg_index(b)] = v & M
            Z, N, C, V = (v & M) == 0, bool(v & 0x80000000), False, False
        elif bmn == 'moveq':
            a, b = [x.strip() for x in ops.split(',')]
            v = int(a[1:].replace('$', ''), 16)
            v = (v - 256 if v >= 128 else v) & M
            d[reg_index(b)] = v
            Z, N, C, V = v == 0, bool(v & 0x80000000), False, False
        elif bmn in ('cmp', 'cmpi', 'sub', 'subq', 'subi', 'add', 'addq', 'addi'):
            if (mn.split('.')[1] if '.' in mn else 'l') != 'l':
                raise Unmodelled(mn)
            a, b = [x.strip() for x in ops.split(',')]
            rn = reg_index(b)
            x = d[rn]
            y = immediate(a) if a.startswith('#') else d[reg_index(a)]
            if bmn in ('cmp', 'cmpi', 'sub', 'subq', 'subi'):
                r = (x - y) & M
                C, V = x < y, bool((x ^ y) & (x ^ r) & 0x80000000)
            else:
                r = (x + y) & M
                C, V = (x + y) > M, bool(~(x ^ y) & (x ^ r) & 0x80000000)
            if bmn not in ('cmp', 'cmpi'):
                d[rn] = r
            Z, N = r == 0, bool(r & 0x80000000)
        elif bmn == 'ext':
            rn = reg_index(ops)
            w = d[rn] & 0xffff
            d[rn] = (w - 0x10000 if w & 0x8000 else w) & M
            Z, N, C, V = d[rn] == 0, bool(d[rn] & 0x80000000), False, False
        elif bmn == 'move' and mn.endswith('.w') and '(pc' in ops:
            ext = struct.unpack('>H', body[pc - base + 2:pc - base + 4])[0]
            disp = ext & 0xff
            disp = disp - 256 if disp >= 128 else disp
            ea = (pc + 2) + disp + (1 << ((ext >> 9) & 3)) * s32(d[(ext >> 12) & 15])
            w = struct.unpack('>h', body[ea - base:ea - base + 2])[0]
            rn = reg_index(ops.split(',')[-1])
            d[rn] = (d[rn] & 0xffff0000) | (w & 0xffff)
            Z, N, C, V = (d[rn] & 0xffff) == 0, bool(w & 0x8000), False, False
        elif bmn == 'jmp' and '(pc' in ops:
            ext = struct.unpack('>H', body[pc - base + 2:pc - base + 4])[0]
            disp = ext & 0xff
            disp = disp - 256 if disp >= 128 else disp
            return ('jump-table', (pc + 2) + disp + (1 << ((ext >> 9) & 3)) * s32(d[(ext >> 12) & 15]))
        elif bmn in ('beq', 'bne', 'bhi', 'bls', 'bcs', 'bcc', 'bgt', 'bge', 'blt', 'ble', 'bra', 'bmi', 'bpl'):
            cc = mn[1:].split('.')[0]
            tgt = int(ops.strip().lstrip('$'), 16)
            taken = {'ra': True, 'eq': Z, 'ne': not Z, 'hi': not C and not Z, 'ls': C or Z,
                     'cs': C, 'cc': not C, 'gt': not Z and N == V, 'ge': N == V, 'lt': N != V,
                     'le': Z or N != V, 'mi': N, 'pl': not N}[cc]
            pc = tgt if taken else nxt
            continue
        else:
            raise Unmodelled('%s %s' % (mn, ops))
        pc = nxt
    raise Unmodelled('no exit')


def chain_entries(body, base):
    """Each compare chain: the request-code load (move.l) before cmp.l #$1003,d0."""
    found = []
    pat = bytes.fromhex('b0bc00001003')
    o = body.find(pat)
    while o >= 0:
        if body[o + 6] == 0x6e and b'\xb0\xbc\x00\x00\x10\x01' in body[o:o + 40]:
            c = base + o
            for back in (2, 4):
                m = next(iter(MD.disasm(body[o - back:o - back + 16], c - back, count=1)), None)
                if m and m.address + m.size == c and m.mnemonic.startswith('move.l'):
                    found.append(c - back)
                    break
        o = body.find(pat, o + 1)
    return found


def dispatch_catalogue(p):
    body, base = p['body'], p['load']
    entries = chain_entries(body, base)
    if not entries:
        return None, {}
    entry = entries[0]
    codes = {}
    for code in range(0, 0x8000):
        r = run_chain(body, base, entry, code)
        codes[code] = r
    # the unknown-code handler is the target most codes reach, whether by a branch or a table jump
    unknown = collections.Counter(t for _, t in codes.values()).most_common(1)[0][0]
    valid = {code: t for code, (_, t) in codes.items() if t != unknown}
    return unknown, valid


def handler_text(p, routine_list, target, valid_targets):
    body, base = p['body'], p['load']
    starts = [r['addr'] for r in routine_list]
    i = bisect.bisect_right(starts, target) - 1
    e = routine_list[i]['end']
    nxt = [x for x in valid_targets if x > target]
    if nxt:
        e = min(e, nxt[0])
    text = []
    pos = target
    while pos < e:
        ins = next(iter(MD.disasm(body[pos - base:pos - base + 16], pos, count=1)), None)
        if ins:
            text.append((ins.mnemonic + ' ' + ADDR_RE.sub('ADDR', ins.op_str)).strip())
            pos += ins.size
        else:
            text.append('dc.w $%04x' % int.from_bytes(body[pos - base:pos - base + 2], 'big'))
            pos += 2
    return sha('\n'.join(text).encode()), e - target


def request_report(rows):
    cats, texts = {}, {}
    for ver, rel in L1_SETS:
        p = fuel_package(rel)
        unknown, valid = dispatch_catalogue(p)
        cats[ver] = (unknown, valid)
        vt = sorted(set(valid.values()))
        texts[ver] = {}
        for code, t in valid.items():
            texts[ver][code] = handler_text(p, rows[ver], t, vt) + (t,)
    ref = '1.44.0'
    codes = sorted(set().union(*[set(cats[v][1]) for v in cats]))
    table = [['code'] + ['%s handler' % v for v, _ in L1_SETS] + ['%s vs 1.44.0' % v for v, _ in L1_SETS]]
    summary = collections.OrderedDict()
    for v, _ in L1_SETS:
        summary[v] = {'unknown_target': '%x' % cats[v][0], 'codes': len(cats[v][1])}
    for code in codes:
        row = ['%x' % code]
        for v, _ in L1_SETS:
            t = cats[v][1].get(code)
            row.append('%x' % t if t is not None else '-')
        for v, _ in L1_SETS:
            if code not in cats[v][1]:
                row.append('absent')
            elif code not in cats[ref][1]:
                row.append('absent in 1.44.0')
            elif texts[v][code][0] == texts[ref][code][0]:
                row.append('same text')
            else:
                row.append('text differs')
        table.append(row)
    # the 1.44.0 catalogue must agree with the curated general-request rows
    curated = [r.split('\t') for r in open(os.path.join(st.REPO, 'docs', 'l1', 'request-codes.tsv')).read().splitlines()[1:]]
    checked = mismatched = 0
    for r in curated:
        if r[1] != '6':
            continue
        checked += 1
        if cats[ref][1].get(int(r[2], 16)) != int(r[3], 16):
            mismatched += 1
    summary['curated_task6_rows'] = {'checked': checked, 'mismatched': mismatched}
    return table, summary


# ---- L2 -------------------------------------------------------------------------------

def l2_report():
    tsv = [['version', 'release', 'bytes', 'kernel_bytes', 'kernel_sha256', 'cramfs_offset', 'cramfs_size']]
    kern = {}
    for ver, rel in L2_SETS:
        d = open(os.path.join(st.ROOT, rel, st.FW, 'l2.bin'), 'rb').read()
        gz = d.find(b'\x1f\x8b\x08')
        z = zlib.decompressobj(31)
        k = z.decompress(d[gz:])
        c = d.find(bytes.fromhex('28cd3d45'))
        size = struct.unpack('>I', d[c + 4:c + 8])[0]
        kern[ver] = k
        tsv.append([ver, rel, len(d), len(k), sha(k), '%x' % c, size])
    cmp_rows = [['from', 'to', 'kernel_same_length', 'kernel_differing_bytes', 'kernel_4k_blocks_equal', 'kernel_4k_blocks']]
    for (a, _), (b, _) in zip(L2_SETS, L2_SETS[1:]):
        ka, kb = kern[a], kern[b]
        if len(ka) == len(kb):
            diff = sum(x != y for x, y in zip(ka, kb))
        else:
            diff = ''
        ba = [ka[i:i + 4096] for i in range(0, len(ka), 4096)]
        bb = [kb[i:i + 4096] for i in range(0, len(kb), 4096)]
        sm = difflib.SequenceMatcher(None, ba, bb, autojunk=False)
        eq = sum(i2 - i1 for t, i1, i2, _, _ in sm.get_opcodes() if t == 'equal')
        cmp_rows.append([a, b, len(ka) == len(kb), diff, eq, len(ba)])
    return tsv, cmp_rows


def write_tsv(name, rows):
    with open(os.path.join(OUT, name), 'w') as f:
        for r in rows:
            f.write('\t'.join('' if c is None else str(c) for c in r) + '\n')


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = l1_routines()
    rtsv, rsum = routine_report(rows)
    write_tsv('l1-routines.tsv', rtsv)
    ctab, csum = request_report(rows)
    write_tsv('l1-request-codes.tsv', ctab)
    ltsv, lcmp = l2_report()
    write_tsv('l2-bytes.tsv', ltsv + [[]] + lcmp)
    print(json.dumps({'routines': rsum, 'requests': csum}, indent=1))
    print('routine rows', len(rtsv) - 1, 'request codes', len(ctab) - 1)


if __name__ == '__main__':
    main()
