#!/usr/bin/env python3
"""Run a list of BUZZ microcode routines record by record and print the dataflow.

Usage: scripts/buzz_ucode_dataflow.py [--numeric SCENARIO.json] [--code C=FN ...]
                                      [--round MODE] IMAGE ENTRY [ENTRY ...]
       scripts/buzz_ucode_dataflow.py --unresolved IMAGE

IMAGE is ucode/ODSY/buzz_xform.bin or ucode/buzz_ucode_ip30.bin. Each ENTRY
runs from its record to the next end mark (bits 1:0 equal to 1 or 2) plus the
four records after it, then the next ENTRY starts, which is how the sequencer
walks a program list. ENTRY:LAST runs ENTRY to LAST inclusive instead, which
replays part of a routine. ENTRY.. runs to the next mark of any value,
including a value-3 mark, plus the four records after it: one part of a table
program, so the list 1520.. 1541.. 1541.. 1561 runs table record 9's first
part, its loop twice and its closing part (ucode/buzz_isa.md, "Pass 17"). The
rules are those of ucode/buzz_isa.md, "Pass 13" to "Pass 17"; every one of
them is inferred, so the output is a reading, not a trace of a board.

Without --numeric, values are symbols. Slots are named after BUZZ.h section 1
(P position, N normal, T texture coordinate, C colour, Mamb/Mdif/Mspe/Memi the
front material, Bamb/Bdif/Bspe/Bemi the back material, opK operand K of the
dispatching word). Parameter words are named after their host writers: the
constants at 0x1e0 to 0x1ef, and the light record at 0x200 + k (relative to
sequencer 0x31). A fired dot product is dNNN, a scalar result sNNN and an
output-stage result oNNN, where NNN is the record that produced it; the
definitions follow the listing. A register lane no record of the run wrote is
named in:RNNl, the value a routine outside the run left there. A record whose
unit has nothing to take under the rules prints '-' for that operand; the
README of this script's output is ucode/buzz_isa.md, "Pass 15", which lists
every such record and why.

With --numeric, SCENARIO is a JSON file of input numbers: "slots" (slot number
to four floats), "operands" (entry record to a list of operands), "pm" (word
address such as "0x080" to a float; the constants at 0x1e0 to 0x1ef are built
in), "regs" (register number to four floats), "B" (the operand latch at
the start of the run, for a replay that starts after the record loading it)
and "passes" (a list of slot maps, the k-th applying while the k-th ENTRY
runs, so that a program's loop sees a new vertex each pass; slots a pass
leaves out come from "slots"). Every output word is also logged with the
ENTRY that sent it (scripts/odydiags_frame_check.py reads that log).
Every other value starts as NaN, so a NaN in the output marks an input the
scenario did not give.
--code C=FN picks a function for a scalar code the ISA leaves open, from
SCALAR_CHOICES; codes 8, 1, 0xc, 0xd and 0xe follow buzz_isa.md. Parameter
stores update the scenario's words, so a later entry reads them back.
--round MODE rounds every dot product and scalar result as a unit of that
width would: f32 (IEEE single, to nearest even) or tN (N fraction bits below
the leading one, toward minus infinity). The default keeps Python doubles,
which hides every rounding trick the program plays.

--unresolved runs every routine alone (from record 0 and from each record
five after an end mark), skips each run's first twelve records, lists the
records whose port write, scalar operand, factor load, store or output-stage
read has no source, drops those a second pass of the same routine resolves,
and, for buzz_xform.bin, those the loop run of their table program resolves
(first part, the loop twice, the closing part; only the second loop pass and
the closing part are counted), and groups the rest by cause
(ucode/buzz_isa.md, "Pass 16" and "Pass 17").
"""
import json
import math
import re
import struct
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buzz_ucode_disasm import field, records  # noqa: E402

LANES = 'xyzw'
FIELDS = dict(a=(93, 92), r1=(91, 87), r2=(86, 82), r3=(81, 77), b=(76, 75),
              ln=(74, 72), rb=(71, 67), bx=(66, 64), vd=(63, 59), st=(58, 58),
              ma=(57, 48), d0=(47, 44), d1=(43, 40), d2=(39, 32), cu=(31, 16),
              s0=(15, 12), s1=(11, 2), sq=(1, 0))
# The constants at 0x1e0 to 0x1ef (ody_context.s, __glOdysseyInitDefaultValues).
CONSTV = [1.0, 0.5, -1.0, 0.0, 2.828427, 3.0, 1.414214, 0.353553, -2.0,
          -1.414214, -0.707107, -0.5, 131072.0, -32.0, 0.03125, 0.0]
CONST = {0x1e0 + k: n for k, n in enumerate(
    ['1.0', '0.5', '-1.0', '0.0', '2.828', '3.0', '1.414', '0.354', '-2.0',
     '-1.414', '-0.707', '-0.5', '131072', '-32', '0.03125', '0.0'])}
# Light record words written by ValidateLight (ody_lighting.s).
LIGHT = ['Lpos.x', 'Lpos.y', 'Lpos.z', '-H.x', '-H.y', '-H.z', 'L6',
         'katt0', 'katt1', 'katt2', '-Sdir.x', '-Sdir.y', '-Sdir.z',
         'Scut', 'Sexp', '2^22']
SLOT = {0: 'P', 1: 'N', 3: 'T', 5: 'C', 6: 'Mamb', 7: 'Mdif', 8: 'Mspe',
        9: 'Memi', 10: 'Bamb', 11: 'Bdif', 12: 'Bspe', 13: 'Bemi',
        14: 'load', 15: 'grp15'}
# Candidate functions for the scalar codes the ISA leaves open; x is the
# operand, k the factor K and f the factor code 0xe would use.
SCALAR_CHOICES = {
    'pass': lambda x, k, f: x,
    'square': lambda x, k, f: x * x,
    'mulK': lambda x, k, f: k * x,
    'neg': lambda x, k, f: -x,
    'recip': lambda x, k, f: 1.0 / x if x else math.inf,
    'rsqrt': lambda x, k, f: 1.0 / math.sqrt(x) if x > 0 else math.nan,
    'log2': lambda x, k, f: math.log2(x) if x > 0 else math.nan,
    'exp2': lambda x, k, f: 2.0 ** x,
    'pow8': lambda x, k, f: (8.0 / x) ** 8 if x else math.nan,
    # pow8 read from a table whose entries sit 1/32 apart, at the entry at
    # or below x: a lookup with no interpolation of its own.
    'pow8t32': lambda x, k, f: (8.0 / (math.floor(x * 32) / 32)) ** 8 if x >= 1 / 32 else math.nan,
    'mulF': lambda x, k, f: f * x,
}


# Table programs of the 6.5.30m libGLcore (ucode/buzz_routines.md, "Table
# records"): sequencer 0x29 (first part), 0x2a (loop) and 0x2c (closing part)
# as buzz_xform.bin record numbers. Records 14 and 15 point all three at the
# null routine and are left out.
PROGRAMS = [(214, 224, 234), (243, 256, 268), (1313, 1325, 1337),
            (1483, 1496, 1509), (1348, 1364, 1379), (1390, 1406, 1422),
            (1580, 1597, 1613), (1752, 1771, 1789), (1433, 1453, 1472),
            (1520, 1541, 1561), (1623, 1646, 1668), (1689, 1716, 1742),
            (2300, 2328, 2355), (1798, 1824, 1851), (1862, 1896, 1929),
            (1955, 1990, 2024), (2050, 2085, 2119), (2145, 2180, 2214),
            (2590, 2626, 2661), (2691, 2728, 2764)]
XFORM_RECORDS = 2794


def rounder(mode):
    """Return a function that rounds a double as the unit width MODE would."""
    if mode is None:
        return lambda v: v
    if mode == 'f32':
        return lambda v: v if math.isnan(v) or math.isinf(v) else struct.unpack('>f', struct.pack('>f', v))[0]
    if mode.startswith('t'):
        bits = int(mode[1:])

        def trunc(v):
            if not v or math.isnan(v) or math.isinf(v):
                return v
            e = math.floor(math.log2(abs(v)))
            q = 2.0 ** (e - bits)
            return math.floor(v / q) * q
        return trunc
    sys.exit(f'unknown rounding {mode}; use f32 or tN')


def decode(w):
    return {k: field(w, hi, lo) for k, (hi, lo) in FIELDS.items()}


def pm_name(a):
    if a in CONST:
        return CONST[a]
    if a & 0x200 and (a & 0x1ff) < 16:
        return LIGHT[a & 0x1ff]
    return f'pm{a:03x}'


def slot_name(v):
    return f'op{v - 16}' if v >= 16 else SLOT.get(v, f'slot{v}')


class Symbols:
    """Values as names; the default listing."""
    numeric = False

    def __init__(self):
        self.defs = []

    def reg(self, r, l):
        return f'in:R{r}{LANES[l]}'

    def slot(self, v, l, entry, k=0):
        return f'{slot_name(v)}.{LANES[l]}'

    def pm(self, a):
        return pm_name(a)

    def none(self):
        return '-'

    def dot(self, name, aname, a, b):
        self.defs.append(f"{name} = {aname}({', '.join(a)}) . ({', '.join(b)})")
        return name

    def scalar(self, name, code, x, k, f):
        self.defs.append(f'{name} = S{code:x}({x})')
        return name

    def stage(self, name, code, srcs):
        self.defs.append(f"{name} = D{code:02x}({' | '.join(srcs) or '-'})")
        return name

    def show(self, v):
        return v


class Numbers:
    """Values as floats, NaN where the scenario gave no input."""
    numeric = True

    def __init__(self, scen, codes, rnd=None):
        self.scen = scen
        self.codes = codes
        self.rnd = rounder(rnd)
        self.invw = math.nan
        self.defs = []
        self.words = {}
        self.emits = []

    def reg(self, r, l):
        v = self.scen.get('regs', {}).get(str(r))
        return float(v[l]) if v else math.nan

    def slot(self, v, l, entry, k=0):
        # A "passes" list gives the slots of each ENTRY of the run in turn,
        # one vertex per sequencer pass; a slot it leaves out comes from
        # "slots".
        passes = self.scen.get('passes', [])
        if v < 16 and k < len(passes) and str(v) in passes[k]:
            return float(passes[k][str(v)][l])
        if v >= 16:
            ops = self.scen.get('operands', {}).get(str(entry), [])
            return float(ops[v - 16]) if v - 16 < len(ops) else math.nan
        s = self.scen.get('slots', {}).get(str(v))
        return float(s[l]) if s else math.nan

    def pm(self, a):
        if a in CONST:
            return CONSTV[a - 0x1e0]
        v = self.scen.get('pm', {}).get(f'0x{a:03x}')
        return float(v) if v is not None else math.nan

    def none(self):
        return math.nan

    def dot(self, name, aname, a, b):
        v = self.rnd(sum(x * y for x, y in zip(a, b)))
        self.defs.append(f'{name} = {aname} . B = {v:.6g}')
        return v

    def scalar(self, name, code, x, k, f):
        if code == 8:
            v = x
        elif code == 1:
            v = 1.0 / math.sqrt(x) if x > 0 else math.nan
        elif code == 0xc:
            v = -x
        elif code == 0xd:
            v = k * x
        elif code == 0xe:
            v = f * x
        elif code in self.codes:
            v = SCALAR_CHOICES[self.codes[code]](x, k, f)
        else:
            v = math.nan
        v = self.rnd(v)
        self.defs.append(f'{name} = S{code:x}({x:.6g}) = {v:.6g}')
        return v

    def stage(self, name, code, srcs):
        x = srcs[0] if srcs else math.nan
        if code in (0x2b, 0x33):
            v = self.invw = 1.0 / x if x else math.inf
        elif code in (0x26, 0x46, 0x24, 0x44, 0x27):
            v = x * self.invw
        else:
            v = x
        self.defs.append(f'{name} = D{code:02x}({x:.6g}) = {v:.6g}')
        return v

    def show(self, v):
        return f'{v:.6g}' if isinstance(v, float) else str(v)


def routine(recs, entry):
    i = entry
    while recs[i]['sq'] not in (1, 2):
        i += 1
    return range(entry, i + 5)


def part(recs, entry):
    """From ENTRY to the next mark of any value, plus its four delay slots."""
    i = entry
    while not recs[i]['sq']:
        i += 1
    return range(entry, i + 5)


def parse_entry(recs, e):
    if e.endswith('..'):
        return part(recs, int(e[:-2], 0))
    if ':' in e:
        a, b = (int(x, 0) for x in e.split(':'))
        return range(a, b + 1)
    return routine(recs, int(e, 0))


def run(recs, entries, dom):
    seq = []
    for k, e in enumerate(entries):
        rng = parse_entry(recs, e)
        seq += [(i, rng[0], k) for i in rng]
    reg = {(r, l): dom.reg(r, l) for r in range(32) for l in range(4)}
    B = [dom.none()] * 4
    if dom.numeric and 'B' in dom.scen:
        B = [float(v) for v in dom.scen['B']]
    nextB = None
    A = Aname = None
    auto_fire = last_issue = -9
    vready, dready, loads, sres, pmv, lane, d2res = {}, {}, {}, {}, {}, {}, {}
    K = nextK = dom.none()
    fhist = []
    out = []
    sh = dom.show
    for c, (i, entry, k) in enumerate(seq):
        r = recs[i]
        d0 = r['d0']
        ev = []
        if nextB is not None:
            B, nextB = nextB, None
        # A factor loaded in one record multiplies from the next (pass 15).
        K = nextK
        snap = dict(reg)
        # A fire takes the latched A and B as it stands at the start of the record.
        if c == auto_fire or (d0 & 1 and last_issue != c - 1):
            if A:
                v = dom.dot(f'd{i}', Aname, A, B)
            else:
                v = dom.none()
            vready[c + 6] = dready[c + 10] = v
            ev.append('fire' if A else 'fire (nothing latched in this run)')
        if d0 & 4:
            if d0 & 2:
                # Without an issue and with field a bit 0 clear the load
                # names its register in r1; otherwise in r2 (pass 15).
                # Field a bit 0 clear: lanes x to z come from R[r1] and lane w
                # from R[r2] (pass 17); set: the whole of R[r2].
                lr = r['r1'] if not r['a'] & 1 else r['r2']
                src = [snap[(lr, l)] for l in range(3)] + [snap[(r['r2'], 3)]]
                if not r['a'] & 1 and r['r2'] != r['r1']:
                    lr = f"{r['r1']}/{r['r2']}"
                if r['a'] & 1 and r['r1'] & 16:
                    nextB = [src[l] if r['r1'] >> l & 1 else B[l] for l in range(4)]
                    ev.append(f"B[mask {r['r1'] & 15:x}] <- R{lr}")
                else:
                    nextB = src
                    ev.append(f"B <- R{lr}")
            else:
                nextB = [dom.slot(r['r3'], l, entry, k) for l in range(4)]
                ev.append(f"B <- {slot_name(r['r3'])}")
            # A load with no issue reaches port V and the scalar unit seven
            # records on as its w lane (pass 15).
            loads[c + 7] = nextB[3]
        if r['a'] & 1 and not r['r1'] & 16:
            lane[c] = snap[(r['r2'], r['r1'] & 3)]
            ev.append(f"read R{r['r2']}.{LANES[r['r1'] & 3]}")
        if d0 & 8:
            # The same read: x to z from R[r1], w from R[r2] (pass 17).
            ar = r['r2'] if r['a'] & 1 else r['r1']
            A = [snap[(ar, l)] for l in range(3)] + [snap[(r['r2'], 3)]]
            Aname = f'R{ar}' if ar == r['r2'] else f"R{ar}/{r['r2']}"
            auto_fire, last_issue = c + 1, c
            ev.append(f'latch A = {Aname}')
        # What reaches port V in this record: a fire's product six records
        # on, else a load seven records on.
        arriving = vready.get(c, loads.get(c))
        if r['d2'] & 0x80:
            # Factor K (pass 13, source order refined in pass 15).
            if r['a'] & 2:
                nextK = pmv.get(c - 2, dom.pm(0))
            elif arriving is not None:
                nextK = arriving
            elif c - 4 in sres:
                nextK = sres[c - 4]
            elif c in dready:
                nextK = dready[c]
            else:
                nextK = dom.none()
            ev.append(f'K = {sh(nextK)}')
        if r['d1']:
            # Bit 3 of the code picks the operand (pass 16): set, the lane
            # read of one record before; clear, what arrives in this record.
            # A record that stores takes what arrives whatever the code,
            # because its store consumes the read (pass 15).
            if r['d1'] & 8 and not r['st']:
                opnd = lane.get(c - 1, dom.none())
            elif arriving is not None:
                opnd = arriving
            else:
                opnd = dom.none()
            # Code 0xe multiplies by the last code 1 or 0xc result that is at
            # least four records old.
            fs = [v for (cc, v) in fhist if cc <= c - 4]
            F = fs[-1] if fs else dom.none()
            v = dom.scalar(f's{i}', r['d1'], opnd, K, F)
            sres[c] = v
            if r['d1'] in (1, 0xc):
                fhist.append((c, v))
            ev.append(f"s{i} = S{r['d1']:x}({sh(opnd)})" +
                      (f' = {sh(v)}' if dom.numeric else ''))
        if r['ma'] and not r['st']:
            pmv[c] = dom.pm(r['ma'])
        if r['st']:
            v = lane.get(c - 1, dom.none())
            ev.append(f"store pm[{pm_name(r['ma'])}] <- {sh(v)}")
            if dom.numeric:
                dom.scen.setdefault('pm', {})[f"0x{r['ma']:03x}"] = v
        if r['bx'] & 4:
            if c in vready:
                val = vready[c]
            elif c in loads:
                val = loads[c]
            elif c - 7 in d2res:
                val = d2res[c - 7]
            else:
                val = dom.none()
            reg[(r['vd'], r['bx'] & 3)] = val
            ev.append(f"R{r['vd']}.{LANES[r['bx'] & 3]} = {sh(val)}")
        if r['ln'] & 4:
            if r['b'] == 0:
                val = pmv.get(c - 2, dom.pm(0))
            elif r['b'] == 2:
                val = sres.get(c - 4, dom.none())
            else:
                val = dom.none()
            reg[(r['rb'], r['ln'] & 3)] = val
            ev.append(f"R{r['rb']}.{LANES[r['ln'] & 3]} = {sh(val)}")
        if r['d2'] and r['d2'] != 0x80:
            if r['d2'] & 0x80 and r['a'] & 2:
                srcs = [pmv.get(c - 2, dom.pm(0))]
            else:
                srcs = [x for x in (dready.get(c), sres.get(c - 4)) if x is not None]
            v = dom.stage(f'o{i}', r['d2'], srcs)
            d2res[c] = v
            t = f"o{i} = D{r['d2']:02x}({' | '.join(sh(x) for x in srcs) or '-'})"
            if dom.numeric:
                t += f' = {sh(v)}'
            if r['s1'] & 0x80 and not r['s1'] & 1:
                t += f" -> word {r['s0']}"
                if dom.numeric:
                    dom.words[r['s0']] = v
                    dom.emits.append((k, i, r['s0'], v))
            ev.append(t)
        elif r['s1'] & 0x80 and not r['s1'] & 1:
            ev.append(f"word {r['s0']}")
        if r['s1'] & 0x300:
            ev.append(f"header {r['s0']}")
        if r['cu'] != 8:
            t = f"colour {r['cu']:04x}"
            if not d0 & 4 and r['r3']:
                t += f"[{slot_name(r['r3'])}]"
            if r['s1'] & 1:
                t += f" -> word {r['s0']}"
            ev.append(t)
        if r['sq']:
            ev.append(('', 'end', 'end2', 'mark3')[r['sq']])
        out.append(f'{c:4d} {i:4d}  ' + '; '.join(ev))
    return out, dom.defs


# Events that name an operand with no source under the rules.
UNRESOLVED = [(re.compile(r'R\d+\.[xyzw] = -$'), 'port'),
              (re.compile(r's\d+ = S[0-9a-f]\(-\)'), 'scalar'),
              (re.compile(r'o\d+ = D[0-9a-f]+\(-\)'), 'stage'),
              (re.compile(r'K = -$'), 'factor'),
              (re.compile(r'store .*<- -$'), 'store')]


def unresolved_records(recs, entries, skip):
    """Return the (record, kind) pairs a symbolic run leaves without a source."""
    out, _ = run(recs, entries, Symbols())
    found = set()
    for line in out[skip:]:
        rec = int(line.split()[1])
        for ev in line.split('  ', 1)[1].split('; '):
            for pat, kind in UNRESOLVED:
                if pat.match(ev):
                    found.add((rec, kind))
    return found


def census(recs):
    """Run every routine alone, then twice in a row, and list what stays open."""
    ends = [i for i, r in enumerate(recs) if r['sq'] in (1, 2)]
    entries = [0] + [i + 5 for i in ends if i + 5 < len(recs)]
    alone, twice = set(), set()
    for e in entries:
        first = unresolved_records(recs, [str(e)], 12)
        n = len(run(recs, [str(e)], Symbols())[0])
        again = unresolved_records(recs, [str(e), str(e)], n)
        alone |= first
        twice |= first & again
    print(f'{len(alone)} records alone; {len(alone - twice)} resolve when the routine follows itself:',
          ' '.join(f'{r}:{k}' for r, k in sorted(alone - twice)))
    if len(recs) == XFORM_RECORDS:
        looped = set()
        for p29, p2a, p2c in PROGRAMS:
            lst = [f'{p29}..', f'{p2a}..', f'{p2a}..', str(p2c)]
            skip = len(part(recs, p29)) + len(part(recs, p2a))
            seen = {i for i in list(part(recs, p2a)) + list(routine(recs, p2c))}
            still = unresolved_records(recs, lst, skip)
            looped |= {(r, k) for r, k in twice if r in seen and (r, k) not in still}
        twice -= looped
        print(f'{len(looped)} resolve in the loop run of their table program:',
              ' '.join(f'{r}:{k}' for r, k in sorted(looped)))
    groups = {}
    for rec, kind in sorted(twice):
        r = recs[rec]
        if kind == 'port' and r['ln'] & 4 and r['b'] in (1, 3):
            why = f"port P source b = {r['b']}"
        elif kind == 'port' and r['ln'] & 4 and r['b'] == 2:
            why = 'port P scalar source, no scalar result four records before'
        elif kind == 'port':
            why = 'port V, no fire six or load seven records before'
        elif kind == 'scalar' and r['d1'] & 8:
            why = 'scalar read code, no lane read one record before'
        elif kind == 'scalar':
            why = 'scalar arrival code, nothing arrives'
        else:
            why = kind
        groups.setdefault(why, []).append(rec)
    for why, recs_ in groups.items():
        print(f'{len(recs_):3d} {why}:', ' '.join(map(str, recs_)))


def main():
    args = sys.argv[1:]
    if args[:1] == ['--unresolved'] and len(args) == 2:
        census([decode(w) for w in records(args[1])[0]])
        return
    scen, codes, rnd = None, {}, None
    while args and args[0].startswith('--'):
        opt = args.pop(0)
        if opt == '--numeric':
            scen = json.load(open(args.pop(0)))
        elif opt == '--code':
            c, fn = args.pop(0).split('=')
            if fn not in SCALAR_CHOICES:
                sys.exit(f'unknown function {fn}; choose from {sorted(SCALAR_CHOICES)}')
            codes[int(c, 16)] = fn
        elif opt == '--round':
            rnd = args.pop(0)
        else:
            sys.exit(__doc__)
    if len(args) < 2:
        sys.exit(__doc__)
    recs = [decode(w) for w in records(args[0])[0]]
    dom = Numbers(scen, codes, rnd) if scen is not None else Symbols()
    out, defs = run(recs, args[1:], dom)
    print('\n'.join(out))
    print('; definitions')
    print('\n'.join(defs))
    if dom.numeric:
        print('; parameter words')
        for k, v in sorted(dom.scen.get('pm', {}).items()):
            print(f'{k} = {dom.show(float(v))}')
        print('; output words')
        for k in sorted(dom.words):
            print(f'word {k} = {dom.show(dom.words[k])}')


if __name__ == '__main__':
    main()
