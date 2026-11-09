"""Addressed disassembly of crm.so routines, callees named by target address.
  tools/re-run python3 tools/crime/crm_exec/crmdis.py cfbFillPoly1RectCopy
The symbol table comes from docs/inventory/functions.tsv (address, size, name); a jal or a
PIC call through t9 is resolved from the address, so a wrong label in the generated listings shows.
"""
import sys, os, csv
from elftools.elf.elffile import ELFFile
import capstone as cs
here = os.path.dirname(os.path.abspath(__file__)); root = os.path.join(here, '..', '..')
so = os.environ.get('CRM_SO', os.path.join(root, 'ddx', 'crm.so'))
syms = {}
for row in csv.reader(open(os.path.join(root, 'docs/inventory/functions.tsv')), delimiter='\t'):
    if row and row[0].endswith('crm.so') and row[4].startswith('0x'):
        syms[int(row[4], 16)] = (row[6], int(row[5]))
byname = {v[0]: (k, v[1]) for k, v in syms.items()}
e = ELFFile(open(so, 'rb'))
seg = [s for s in e.iter_segments() if s['p_type'] == 'PT_LOAD'][0]
base = seg['p_vaddr']; data = seg.data()
def name_at(a):
    if a in syms: return syms[a][0]
    best = max((k for k in syms if k <= a), default=None)
    return '%s+0x%x' % (syms[best][0], a - best) if best is not None and a - best < syms[best][1] else None
md = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64 | cs.CS_MODE_BIG_ENDIAN)
def dis(a, n):
    for i in md.disasm(data[a - base:a - base + n], a):
        t = ''
        if i.mnemonic in ('jal', 'j', 'b', 'beq', 'bne', 'beqz', 'bnez', 'bltz', 'bgez', 'blez', 'bgtz', 'bal', 'beql', 'bnel'):
            try:
                tg = int(i.op_str.split(',')[-1].strip(), 0); t = '  ; ' + (name_at(tg) or hex(tg))
            except ValueError: pass
        print('%x:\t%s\t%s%s' % (i.address, i.mnemonic, i.op_str, t))
if __name__ == '__main__':
    arg = sys.argv[1]
    if arg in byname: a, n = byname[arg]
    else: a = int(arg, 0); n = int(sys.argv[2], 0) if len(sys.argv) > 2 else syms[a][1]
    dis(a, n)
