"""Summarise the diagnostic board netlists: chips, instances and pin widths.

Usage: netmap_summary.py [DATA_DIR] [OUT]
       defaults: diags/IR/data diags/netmap_chips.tsv

The IR diagnostics (IRIX 6.5.30m, /usr/diags/IR/data/*.netmap.Z) ship one
compressed netlist per board or board combination. Each line is a net
number, the net's names, a tab, and the pins on it written as
instance.path:pin or instance.path:pin[bit]. The chip type is the last
component of the instance path (rm0.tmm0.tm -> tm). This writes, per
netlist and chip type, how many instances appear and every pin group with
its width (highest bit index + 1), so bus widths can be cited without
reading the netlists. .Z files are LZW; gzip -dc reads them.
"""
import collections
import glob
import os
import re
import subprocess
import sys

data = sys.argv[1] if len(sys.argv) > 1 else 'diags/IR/data'
out = sys.argv[2] if len(sys.argv) > 2 else 'diags/netmap_chips.tsv'

with open(out, 'w') as fh:
    fh.write('# Chips and pin widths in the IR diagnostic netlists (IRIX 6.5.30m /usr/diags/IR/data).\n')
    fh.write('# width = highest bit index seen + 1; EXTRA_CRC_* scan pins are left out.\n')
    fh.write('netlist\tchip\tinstances\tpins\n')
    for path in sorted(glob.glob(os.path.join(data, '*.netmap.Z'))):
        text = subprocess.run(['gzip', '-dc', path], capture_output=True, check=True).stdout.decode('latin1')
        pins = collections.defaultdict(dict)
        inst = collections.defaultdict(set)
        for line in text.splitlines():
            for col in line.split('\t')[1:]:
                for t in col.split(','):
                    t = t.strip()
                    if ':' not in t:
                        continue
                    ipath, pin = t.rsplit(':', 1)
                    if pin.startswith('EXTRA_CRC'):
                        continue
                    chip = ipath.split('.')[-1]
                    inst[chip].add(ipath)
                    m = re.match(r'(.*)\[(\d+)\]$', pin)
                    name, width = (m.group(1), int(m.group(2)) + 1) if m else (pin, 1)
                    pins[chip][name] = max(pins[chip].get(name, 0), width)
        for chip in sorted(pins):
            fh.write('%s\t%s\t%d\t%s\n' % (os.path.basename(path)[:-len('.netmap.Z')], chip, len(inst[chip]),
                                           ' '.join('%s[%d]' % (k, v) if v > 1 else k
                                                    for k, v in sorted(pins[chip].items()))))
