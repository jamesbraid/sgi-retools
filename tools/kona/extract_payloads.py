"""List the fixed payload of every straight-line libGLcore command emitter.

Usage: extract_payloads.py [HP_TSV] [ASM_DIR] > libglcore/payloads.tsv
       defaults: diags/kpm/hp_commands.tsv libglcore/asm

A function qualifies when it has no branches or calls and its first store
to the FIFO address 0x4000 is a constant token loaded with li. Each later
store is one payload item: i = sw (one integer word), f = swc1 (one float
word), ii = sd (two words, high word first), d = sdc1 (one double, two
words). The token name comes from kpm's command table.
"""
import re,sys,glob,collections
hp={}
for l in open((sys.argv[1] if len(sys.argv) > 1 else 'diags/kpm/hp_commands.tsv')):
    if l.startswith('0x'):
        va,t,n=l.rstrip('\n').split('\t'); hp[int(t,16)]=n
rows=[]
for f in sorted(glob.glob((sys.argv[2] if len(sys.argv) > 2 else 'libglcore/asm')+'/*/*.s')):
    fn=None; body=[]
    for l in open(f):
        m=re.match(r'# Function: (\S+)',l)
        if m:
            if fn: rows.append((fn,f,body))
            fn=m.group(1); body=[]; continue
        if fn: body.append(l)
    if fn: rows.append((fn,f,body))
out=[]
for fn,f,body in rows:
    code=[l for l in body if not l.strip().startswith('#') and l.strip() and not l.startswith('.')]
    # straight-line only: no branches other than jr ra
    if any(re.match(r'\s+(b|beq|bne|bnez|beqz|bgez|bltz|blez|bgtz|bc1t|bc1f|jal|bal|jalr)\b',l) for l in code): continue
    regs={}; seq=[]
    for l in code:
        m=re.match(r'\s+li\s+\$(\w+),(-?(?:0x)?[0-9a-f]+)$',l)
        if m: regs[m.group(1)]=int(m.group(2),0)
        m=re.match(r'\s+(sw|sd|swc1|sdc1)\s+\$(\w+),16384\(\$zero\)',l)
        if m: seq.append((m.group(1),m.group(2)))
    if len(seq)<1 or seq[0][0]!='sw' or seq[0][1] not in regs: continue
    tok=regs[seq[0][1]]
    words=sum(2 if s[0] in('sd','sdc1') else 1 for s in seq[1:])
    kinds=' '.join({'sw':'i','swc1':'f','sd':'ii','sdc1':'d'}[s[0]] for s in seq[1:])
    out.append((tok,hp.get(tok,'?'),fn,words,kinds,f.split('/')[-1]))
print("token\tname\tfunction\twords\titems\tunit")
for r in sorted(out): print('0x%03x\t%s\t%s\t%d\t%s\t%s'%r)
