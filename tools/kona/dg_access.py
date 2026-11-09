#!/usr/bin/env python3
"""List every access an ARM image makes to the display-generator window.

Reads a listing written by arm1_disasm.py (ucode/arm1.s or ucode/tport.s),
follows constant values through mov, mvn, add, sub, orr, bic and pc-relative
literal loads inside each function (forgetting r0-r3, r12 and lr after a
call, and everything at a label), and prints each load or store whose base
register holds an address in 0x00600000-0x006fffff.

The window is word addressed: ARM address 0x00600000 + 4 * A is
display-bus address A (DoDGRqstVCWrite, 0x0c012200).  Columns: function,
instruction address, access, ARM address, bus address, the shift of an
index register added to it (blank for a constant address), and the value
stored when it is a known constant.

    scripts/dg_access.py ucode/arm1.s > ucode/dg_access.tsv

With --functions LISTING ACCESS_TSV it prints instead one markdown table
row per display-side function of the listing (dg*, i2c_*, eeprom_*, the
PAB loader and the display-command entry): its address, the bus addresses
it reads (r) and writes (w) from the access table (+0x100*n for a
per-channel block, +i for an index register), the functions it calls and
its first message string. docs/dg.md carries that table.
"""
import re
import sys

LO, HI = 0x00600000, 0x00700000
INSN = re.compile(r'^([0-9a-f]{8}): ([0-9a-f]{8})  (\S+)\s*(.*)$')
LABEL = re.compile(r'^([A-Za-z_$][\w$.]*):$')
IMM = r'#(-?0x[0-9a-f]+|-?\d+)'


def num(s):
    return int(s, 0) & 0xffffffff


def main(path):
    func = '?'
    known = {}
    print('function\tpc\taccess\tarm_address\tbus_address\tindex_shift\tvalue')
    for line in open(path):
        line = line.rstrip('\n')
        m = LABEL.match(line)
        if m:
            func = m.group(1)
            known = {}
            continue
        m = INSN.match(line)
        if not m:
            continue
        pc, op, args = m.group(1), m.group(3), m.group(4)
        conds = ('eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
                 'hi', 'ls', 'ge', 'lt', 'gt', 'le')
        if op == 'bl' or (op[:2] == 'bl' and op[2:] in conds):
            base_op = 'bl'          # blt, ble and bls are b with a condition
        elif op[:1] == 'b' and op[:3] != 'bic' and (op == 'b' or op[1:] in conds):
            base_op = 'b'
        else:
            base_op = re.match(r'(ldr|str|mov|mvn|add|sub|orr|bic|ldm|stm|cmp|teq|tst|cmn|and|eor|rsb|mul|mla)', op)
            base_op = base_op.group(1) if base_op else op
        cond = op[len(base_op):len(base_op) + 2] if base_op not in ('ldm', 'stm') else ''
        conditional = cond in conds
        if base_op in ('ldr', 'str'):
            mm = re.match(r'(\w+), \[(\w+)(?:, (.*?))?\](!?)(?:, (.*))?', args)
            if not mm:
                continue
            rt, rn, off, wb, post = mm.groups()
            lit = re.search(r'=0x([0-9a-f]+)', args)
            if base_op == 'ldr' and rn == 'pc' and lit:
                if conditional:
                    known.pop(rt, None)
                else:
                    known[rt] = int(lit.group(1), 16)
                continue
            addr, shift = None, ''
            if rn in known:
                b = known[rn]
                if off is None or post:
                    addr = b
                else:
                    mi = re.fullmatch(IMM, off)
                    if mi:
                        addr = (b + num(mi.group(1))) & 0xffffffff
                    else:
                        mr = re.fullmatch(r'(-?)(\w+)(?:, lsl #(\w+))?', off)
                        if mr:
                            k = int(mr.group(3), 0) if mr.group(3) else 0
                            if mr.group(2) in known:
                                addr = (b + (known[mr.group(2)] << k)) & 0xffffffff
                            else:
                                addr, shift = b, str(k)
            if addr is not None and LO <= addr < HI:
                val = ''
                if base_op == 'str' and rt in known:
                    val = hex(known[rt])
                print(f'{func}\t0x{pc}\t{op}\t{addr:#010x}\t{(addr - LO) >> 2:#x}\t{shift}\t{val}')
            if base_op == 'ldr':
                known.pop(rt, None)
            if wb or post:
                known.pop(rn, None)
            continue
        if base_op == 'bl':
            for r in ('r0', 'r1', 'r2', 'r3', 'r12', 'lr'):
                known.pop(r, None)
            continue
        if base_op in ('b', 'cmp', 'teq', 'tst', 'cmn', 'stm'):
            continue
        if base_op == 'ldm':
            regs = re.search(r'\{(.*)\}', args)
            if regs:
                for r in regs.group(1).split(','):
                    known.pop(r.strip(), None)
            continue
        parts = [p.strip() for p in args.split(',')]
        if not parts or not parts[0]:
            continue
        rd = parts[0]
        val = None
        try:
            if base_op in ('mov', 'mvn') and len(parts) == 2:
                mi = re.fullmatch(IMM, parts[1])
                if mi:
                    val = num(mi.group(1))
                elif parts[1] in known:
                    val = known[parts[1]]
                if val is not None and base_op == 'mvn':
                    val = ~val & 0xffffffff
            elif base_op in ('add', 'sub', 'orr', 'bic') and len(parts) == 3:
                a = known.get(parts[1])
                mi = re.fullmatch(IMM, parts[2])
                bv = num(mi.group(1)) if mi else known.get(parts[2])
                if a is not None and bv is not None:
                    val = {'add': a + bv, 'sub': a - bv, 'orr': a | bv,
                           'bic': a & ~bv}[base_op] & 0xffffffff
        except ValueError:
            val = None
        if val is not None and not conditional:
            known[rd] = val
        else:
            known.pop(rd, None)


def functions(listing, table):
    import collections
    acc = collections.defaultdict(lambda: collections.defaultdict(set))
    for line in open(table).read().splitlines()[1:]:
        f = line.split('\t')
        k = f[4] + ('+0x100*n' if f[5] == '10' else ('+i' if f[5] else ''))
        acc[f[0]][k].add('r' if f[2].startswith('ldr') else 'w')
    calls = collections.defaultdict(list)
    strs = collections.defaultdict(list)
    addr = {}
    cur = None
    for line in open(listing):
        m = LABEL.match(line.rstrip('\n'))
        if m:
            cur = m.group(1)
            continue
        if cur and cur not in addr:
            m = re.match(r'^([0-9a-f]{8}):', line)
            if m:
                addr[cur] = m.group(1)
        m = re.search(r'\bbl\w* 0x\w+ <(\w+)>', line)
        if m and cur:
            calls[cur].append(m.group(1))
        m = re.search(r'\.asciz "(.*)"', line)
        if m and cur:
            strs[cur].append(m.group(1))
    pat = re.compile(r'(dg[A-Z]|i2c_|read_edid|eeprom_|init_voc|init_dac|init_dg|pab[A-Z]|pgmclr|'
                     r'waitclr|databit|chkframe|chkdone|isvoc1b|arm_video_cmd|SendDGRply)')
    for n in sorted((n for n in addr if pat.match(n)), key=lambda x: addr[x]):
        bus = ', '.join('%s %s' % (k, '/'.join(sorted(v))) for k, v in sorted(acc[n].items()))
        cs = [c for c in dict.fromkeys(calls[n])
              if c not in ('_printf', '__rt_sdiv', '__rt_udiv', 'sleep')]
        msg = [x for x in strs[n] if len(x) > 8][:1]
        text = ('"%s"' % msg[0][:60].replace('|', '/')) if msg else ''
        print('| `%s` | 0x%s | %s | %s | %s |' % (
            n, addr[n], bus or '-', ', '.join('`%s`' % c for c in cs[:6]) or '-', text))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--functions':
        functions(sys.argv[2], sys.argv[3])
    else:
        main(sys.argv[1] if len(sys.argv) > 1 else 'ucode/arm1.s')
