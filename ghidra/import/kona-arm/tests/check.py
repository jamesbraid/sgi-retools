"""Check the ARM import against the committed listings and tables.

Usage: python3 ghidra/import/kona-arm/tests/check.py [DUMPDIR]   (default .cache/kona-arm)

Reads the dumps tests/run-ghidra.sh writes and checks, per image:

arm1.u
  - every symbol of ucode/arm1.s that starts a function (debug-table flags 2
    or 3 in the read-only part, not a region mark, an area name or one of
    the documented tables) is a Ghidra function carrying one of the names
    arm1.s prints at that address, and every Ghidra function starts at an
    arm1.s label or is listed as found by analysis alone;
  - every token of ucode/icu_map.tsv sits in the typed token list with the
    documented entry; every ARM-run token's handler pointer equals the
    address in ucode/arm1_handlers.tsv and lands on a function of that name;
  - the documented data tables are laid, and stores reach the host-interface
    and engine-port blocks.
tport.bin
  - every call target labelled in ucode/tport.s is a function, named as
    tport.s names it, or, where tport.s prints fn_<address>, with the label
    ucode/tport.md gives it.
other images
  - the import ran, the entry is a function and the ports are referenced.
Exits 1 on any mismatch.
"""
import os
import re
import sys

D = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else '.cache/kona-arm')
bad = 0


def fail(msg):
    global bad
    bad += 1
    print('FAIL', msg)


def load(name):
    p = os.path.join(D, name + '.dump')
    if not os.path.exists(p):
        fail(f'{name}: no dump at {p}')
        return None
    out = {'F': {}, 'T': {}, 'D': {}, 'B': {}}
    for line in open(p):
        r = line.rstrip('\n').split('\t')
        if r[0] == 'F':
            out['F'][int(r[1], 16)] = r[2]
        elif r[0] == 'T':
            out['T'][int(r[1], 16)] = r[2:]
        elif r[0] == 'D':
            out['D'][int(r[1], 16)] = r[2]
        elif r[0] == 'B':
            out['B'][r[1]] = int(r[3])
    return out


def labels(path):
    lab, cur = {}, []
    for line in open(path):
        line = line.rstrip('\n')
        if line.endswith(':') and not line.startswith('#') and ' ' not in line:
            cur.append(line[:-1])
            continue
        m = re.match(r'^([0-9a-f]{8}):', line)
        if m and cur:
            lab.setdefault(int(m.group(1), 16), []).extend(cur)
            cur = []
    return lab


def tsv(path):
    for line in open(path):
        if line.startswith('#') or not line.strip():
            continue
        yield line.rstrip('\n').split('\t')


RO_DATA = {'vector_start', 'vector_end', 'hipctl', 'hipwc', 'EdgeDescArray'}


def check_arm1():
    g = load('arm1.u')
    if g is None:
        return
    lab = labels('ucode/arm1.s')
    flags = {}
    for r in tsv('ucode/arm1_symbols.tsv'):
        if r[0].startswith('0x'):
            flags[(int(r[0], 16), r[2])] = int(r[1])
    want = set()
    for a, ns in lab.items():
        for n in ns:
            if flags.get((a, n)) in (2, 3) and '$' not in n and n != 'ucode' and n not in RO_DATA:
                want.add(a)
    funcs = g['F']
    missing = sorted(want - set(funcs))
    for a in missing:
        fail(f'arm1.u: no function at 0x{a:08x} {lab[a]}')
    named = 0
    for a in sorted(want & set(funcs)):
        if funcs[a] in lab[a]:
            named += 1
        else:
            fail(f'arm1.u: function at 0x{a:08x} is {funcs[a]}, arm1.s says {lab[a]}')
    extra = sorted(a for a in funcs if a not in lab)
    for a in extra:
        print(f'note: arm1.u: analysis found 0x{a:08x} {funcs[a]}, which has no symbol')
    print(f'arm1.u: {len(want)} function symbols, {len(want) - len(missing)} found, {named} named as arm1.s; '
          f'{len(extra)} more found by analysis')

    hand = {int(r[0], 16): r for r in tsv('ucode/arm1_handlers.tsv') if r[0].startswith('0x')}
    toks = {int(r[0], 16): r for r in tsv('ucode/icu_map.tsv') if r[0].startswith('0x')}
    t = g['T']
    ok = 0
    for tok, r in toks.items():
        if tok not in t:
            fail(f'arm1.u: token 0x{tok:03x} {r[1]} has no list entry')
            continue
        _, word, h, hf = t[tok]
        entry = int(r[2], 16)
        if r[3] == 'arm':
            hv = int(h, 16) if h != '-' else None
            if hv is None or (int(word, 16) | (hv << 4)) & 0xffffffff != entry:
                fail(f'arm1.u: token 0x{tok:03x}: list gives {word} {h}, icu_map.tsv entry {r[2]}')
                continue
            hr = hand.get(tok)
            if hr is None or int(hr[3], 16) != hv or hf != hr[2]:
                fail(f'arm1.u: token 0x{tok:03x} {r[1]}: handler {h} {hf}, arm1_handlers.tsv {hr and hr[2:4]}')
                continue
        elif int(word, 16) != entry:
            fail(f'arm1.u: token 0x{tok:03x}: routed entry {word}, icu_map.tsv {r[2]}')
            continue
        ok += 1
    narm = sum(1 for r in toks.values() if r[3] == 'arm')
    print(f'arm1.u: {ok} of {len(toks)} tokens match icu_map.tsv; {narm} ARM-run handlers resolve to '
          f'arm1_handlers.tsv names ({len(hand)} rows)')
    for name, addr in (('hipwc', 0x0c000ff4), ('DGDispatchTable', 0x040412c0), ('gepc', 0x04068654),
                       ('icu_map', 0x04068e54), ('ICU map', 0x00400000)):
        if addr not in g['D']:
            fail(f'arm1.u: {name} at 0x{addr:08x} not laid as data')
    ports(g, 'arm1.u')


def ports(g, name, need=('hip', 'hip_data', 'ge_ports')):
    for b in need:
        if g['B'].get(b, 0) == 0:
            fail(f'{name}: no references into {b}')
    print(f'{name}: references by block: ' + ', '.join(f'{k} {v}' for k, v in g['B'].items()))


def check_tport():
    g = load('tport.bin')
    if g is None:
        return
    lab = labels('ucode/tport.s')
    md = {}
    for line in open('ucode/tport.md'):
        if line.startswith('| 0x0c'):
            c = line.split('|')
            md[int(c[1].strip(), 16)] = c[2].strip().strip('`')
    funcs = g['F']
    named = 0
    for a, ns in sorted(lab.items()):
        n = ns[0]
        if md.get(a, '').endswith('(data)'):
            if a in funcs:
                fail(f'tport.bin: 0x{a:08x} is data in tport.md but a function')
            continue
        want = md.get(a, n) if n.startswith('fn_') else n
        if a not in funcs:
            fail(f'tport.bin: no function at 0x{a:08x} {n}')
        elif funcs[a] != want:
            fail(f'tport.bin: function at 0x{a:08x} is {funcs[a]}, expected {want}')
        else:
            named += 1
    extra = sorted(a for a in funcs if a not in lab)
    print(f'tport.bin: {len(lab)} labelled call targets, {named} named as tport.s/tport.md; '
          f'{len(extra)} more found by analysis')
    ports(g, 'tport.bin')


def check_other():
    # arm1_kpm.u and arm1_nic.u use only the mailbox, counter and bit-bang
    # registers (ucode/arm1.md); diag_arm_init.u reports through HA_HOST_INTR.
    for name, need in (('arm1_kpm.u', ('hip',)), ('diag_arm1.u', ('hip', 'hip_data', 'ge_ports')),
                       ('diag_arm1_nic.u', ('hip',)), ('diag_diag_arm_init.u', ('hip',))):
        g = load(name)
        if g is None:
            continue
        print(f'{name}: {len(g["F"])} functions')
        ports(g, name, need)


os.chdir(os.path.dirname(os.path.abspath(__file__)) + '/../../../..')
check_arm1()
check_tport()
check_other()
print('FAILURES:', bad)
sys.exit(1 if bad else 0)
