"""Map each hardware-routed host token to its entry in the distributor program.

Usage: ged_route.py [GED1B_U] [HW_ROUTE] [RELOCS] [OUT_ROUTE] [OUT_BANKS]
       defaults: ucode/KONA/ged1b.u ucode/hw_route.tsv ucode/ged_relocs.tsv
                 ucode/ged_route.tsv ucode/ged_banks.tsv

ucode/arm1.md shows that a hardware-routed token's 9-bit command number n
indexes the distributor's 512-word table (the second segment of ged1b.u,
after a 16-word table) to get a program address. ged1b.u also carries a line
table that gives, for every program word, the source file and line it was
assembled from (dist.s, flush.s, material.s, trigger.s, tstrip.s, points.s,
lineloop.s, linestrip.s, quad.s, qstrip.s, tfanpoly.s, tri.s, lines.s).
This script joins the two:

  ged_banks.tsv   all 512 table entries, split into the eight banks of 64
                  that bits 6-8 of n select: bank, k = n & 63, entry word,
                  source file, source line.
  ged_route.tsv   every routed token: command number, bank, k, the table
                  word at index n with its source file and line, the words
                  from there to the next entry point of any token, and the
                  geometry-engine handler words (ged_relocs.tsv) inside that
                  span; then the token's form, and the idle-class entry
                  B[k] with its source. The "bound" column is yes for the 54
                  pass and register tokens whose handler is already fixed by
                  the handler table (ucode/arm1.md: the handler at index
                  n & 63 has the token's own name, or the same role for six
                  more); never for the geometry form.

ucode/ged.md supersedes the reading of the table as indexed by command
number: the 512 words are laid out per primitive class and vertex state
(B[8 x A[r48] + 4 x state + j]), so the word at index n is where n falls in
that layout, not the program the token runs. For a token whose entry number
k (n & 63) is used, the idle class gives B[k]; which index the hardware uses
for a given token inside a primitive, and for the pass and register forms,
is the open question in ucode/ged.md.
"""
import csv
import re
import struct
import sys

ged = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/ged1b.u'
hw = sys.argv[2] if len(sys.argv) > 2 else 'ucode/hw_route.tsv'
rel = sys.argv[3] if len(sys.argv) > 3 else 'ucode/ged_relocs.tsv'
out_route = sys.argv[4] if len(sys.argv) > 4 else 'ucode/ged_route.tsv'
out_banks = sys.argv[5] if len(sys.argv) > 5 else 'ucode/ged_banks.tsv'

b = open(ged, 'rb').read()
hdr = struct.unpack('>11I', b[:44])
code = b[hdr[3]:hdr[3] + hdr[4]]
ba, bl = struct.unpack('>II', code[:8])
nwords = bl // 4
tab_off = 16 + bl
table = [struct.unpack('>I', code[tab_off + 4 * i:tab_off + 4 * i + 4])[0] for i in range(0x840 // 4)]
tab = table[16:]          # the 512-entry table indexed by command number
files = [x.decode().split('/')[-1] for x in b[hdr[9]:hdr[9] + hdr[10]].split(b'\0')][:18]
lt = b[hdr[5]:hdr[5] + hdr[6]]
line = {}
for i in range(0, len(lt), 8):
    a, ln, f = struct.unpack('>IHH', lt[i:i + 8])
    line[a] = (ln, files[f])

handler = {}
for r in csv.reader((x for x in open(rel) if not x.startswith('#')), delimiter='\t'):
    if r[0] != 'ged_word':
        handler[int(r[0], 16)] = r[5]

starts = sorted(set(tab) | {0})
ROLE = {'HP_MAPGRID1D', 'HP_MAPGRID2D', 'HP_X_POINT6_R', 'HP_X_POINT24_R',
        'HP_X_LINE6_R', 'HP_LOAD_POST_TEX_SCALE_BIAS'}


def norm(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())


def bound(name, handler_name):
    if name in ROLE:
        return True
    if not handler_name:
        return False
    h = norm(re.sub(r'^mge\w*?_', '', handler_name))
    n = norm(name[3:])
    return h == n or h in n or n in h or h.replace('modelview', '') in n


with open(out_banks, 'w') as f:
    f.write('# The distributor 512-entry table (ged1b.u second segment) as eight banks of 64.\n')
    f.write('# bank = bits 6-8 of the command number n, k = n & 63; source = file and line of the\n')
    f.write('# entry word from the assembler line table. Produced by scripts/ged_route.py.\n')
    f.write('n\tbank\tk\tentry\tsource\tline\n')
    for n in range(512):
        e = tab[n]
        ln, src = line.get(e, ('', '?'))
        f.write('%d\t%d\t%d\t0x%03x\t%s\t%s\n' % (n, n >> 6 & 7, n & 63, e, src, ln))

with open(out_route, 'w') as f:
    f.write('# Hardware-routed host tokens and the distributor table words their numbers reach.\n')
    f.write('# entry = table B word at index n. ucode/ged.md lays table B out by primitive class and\n')
    f.write('# vertex state, so this is where n falls in that layout, not the program the token runs.\n')
    f.write('# idle_entry = B[k], the entry for entry number k = n & 63 in the idle class (ged.md);\n')
    f.write('# which index the hardware uses inside a primitive, and for the pass and register forms,\n')
    f.write('# is open in ged.md. bound = yes when the handler table fixes the handler (ucode/arm1.md),\n')
    f.write('# never for the geometry form. span = words from the entry to the next entry point of any\n')
    f.write('# command number; handlers = relocated slot words inside the span. Produced by\n')
    f.write('# scripts/ged_route.py.\n')
    f.write('token\tname\tn\tbank\tk\tentry\tsource\tline\tspan\tbound\thandlers\tform\tidle_entry\tidle_source\n')
    for ln_ in open(hw):
        if ln_.startswith('#') or ln_.startswith('token'):
            continue
        p = ln_.rstrip('\n').split('\t')
        tok, name, n = p[0], p[1], int(p[2])
        bnd = p[5] if len(p) > 5 else ''
        form = p[6] if len(p) > 6 else ''
        e = tab[n]
        ln, src = line.get(e, ('', '?'))
        nxt = [s for s in starts if s > e]
        end = nxt[0] if nxt else nwords
        hs = [handler[a] for a in range(e, end) if a in handler]
        ie = tab[n & 63]
        iln, isrc = line.get(ie, ('', '?'))
        f.write('\t'.join([tok, name, str(n), str(n >> 6 & 7), str(n & 63), '0x%03x' % e, src,
                           str(ln), str(end - e), 'yes' if form != 'geometry' and bound(name, bnd) else 'no',
                           ','.join(hs), form, '0x%03x' % ie, '%s:%s' % (isrc, iln)]) + '\n')
