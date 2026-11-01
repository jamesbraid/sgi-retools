# Copyright (c) 2026, Dominik Behr. BSD 3-Clause; see scripts/LICENSE-gr4.
# Adapted from scripts/clean_asm.py in https://github.com/techomancer/gr4 for the KONA
# workspace; board-specific tables were removed.
import os
import sys
import re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.resolve_got import build_got_map

def clean_file(in_path, out_path, got_map):
    with open(in_path) as f:
        lines = f.readlines()

    new_lines = []
    t9_sym = None
    for line in lines:
        m_load = re.search(r'lw\s+\$t9,\s*(-?\d+)\(\$gp\)', line)
        if m_load:
            off = int(m_load.group(1))
            if off in got_map:
                t9_sym = got_map[off]
                new_lines.append(f'    # lw $t9, {off}($gp) # &{t9_sym}\n')
                continue
        if 'jalr' in line and '$t9' in line and t9_sym:
            # preserve indentation
            indent = line[:len(line) - len(line.lstrip())]
            new_lines.append(f'{indent}jal\t{t9_sym}\n')
            t9_sym = None
            continue
        new_lines.append(line)

    with open(out_path, 'w') as f:
        f.writelines(new_lines)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit("usage: clean_asm.py ELF IN.s OUT.s  (replace $gp-relative GOT calls with symbol names)")
    got_map = build_got_map(sys.argv[1])
    clean_file(sys.argv[2], sys.argv[3], got_map)
    print(f"Done generating {sys.argv[3]}")
