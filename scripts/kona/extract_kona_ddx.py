#!/usr/bin/env python3
# Copyright (c) 2026, Dominik Behr. BSD 3-Clause; see scripts/LICENSE-gr4.
# Adapted from scripts/extract_impact_ddx.py in https://github.com/techomancer/gr4 for the KONA
# workspace; board-specific tables were removed.
"""
scripts/extract_kona_ddx.py

Extracts functions, symbols and disassembly from an X server DDX module
(ddx/kona.so and its siblings) into per-group assembly for m2c.
Usage: extract_kona_ddx.py [SO [OUT_DIR]]   (default ddx/kona.so, ddx)

Functions are grouped by the lowercase prefix of their name (e.g. a name
starting `abcDraw...` goes to group `abc`). To group them your own way, put
a JSON object {"group": ["func", ...]} at OUT_DIR/groups.json.

Generates:
  1. OUT_DIR/<module>/manifest.json
  2. OUT_DIR/asm/<module>/<group>/<group>.s
  3. OUT_DIR/decompile_ddx.sh (m2c runner script)
"""

import os
import sys
import re
import json
import struct
import subprocess
from collections import defaultdict
from elftools.elf.elffile import ELFFile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.resolve_got import build_got_map
from scripts.toolchain import objdump

TARGET_SO = sys.argv[1] if len(sys.argv) > 1 else 'ddx/kona.so'
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else 'ddx'
MODULE = os.path.splitext(os.path.basename(TARGET_SO))[0]

def sanitize_ident(name):
    s = name.replace('*', '_').replace('..', '__').replace('.', '_').replace('$', '_')
    if s and s[0].isdigit():
        s = '_' + s
    return s

def load_groups():
    p = f'{OUT_DIR}/groups.json'
    return json.load(open(p)) if os.path.exists(p) else {}

MODULE_GROUPS = load_groups()

def classify_function(name):
    g = _classify(name)
    return g if g in MODULE_GROUPS or PREFIX_COUNTS.get(g, 0) >= MIN_GROUP else 'misc'

MIN_GROUP = 5   # prefixes with fewer functions than this merge into 'misc'
PREFIX_COUNTS = {}

def _classify(name):
    clean = sanitize_ident(name)
    for group, fnames in MODULE_GROUPS.items():
        if clean in fnames or name in fnames:
            return group
    m = re.match(r'_*([a-z]+)', clean)
    return m.group(1) if m else 'other'

def parse_dynsyms(so_path):
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        funcs = []
        objects = []
        for s in dynsym.iter_symbols():
            if s.name and s['st_value'] and s['st_shndx'] != 'SHN_UNDEF':
                stype = s['st_info']['type']
                item = {
                    'name': s.name,
                    'clean_name': sanitize_ident(s.name),
                    'addr': s['st_value'],
                    'size': s['st_size'],
                    'type': stype
                }
                if stype == 'STT_FUNC':
                    funcs.append(item)
                elif stype == 'STT_OBJECT':
                    objects.append(item)

        funcs.sort(key=lambda x: x['addr'])
        objects.sort(key=lambda x: x['addr'])

        # Infer function sizes if size is 0
        for i in range(len(funcs) - 1):
            if funcs[i]['size'] == 0:
                funcs[i]['size'] = funcs[i+1]['addr'] - funcs[i]['addr']

        return funcs, objects

def get_disassembly(so_path):
    print(f"[*] Disassembling {so_path} ...")
    cmd = [objdump(), '-d', '-z', '--no-show-raw-insn', so_path]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)

    disasm = {}
    pattern = re.compile(r'^\s*([0-9a-fA-F]+):\s*(.*)')
    for line in res.stdout.splitlines():
        m = pattern.match(line)
        if m:
            addr = int(m.group(1), 16)
            instr = m.group(2).strip()
            disasm[addr] = instr
    print(f"[+] Loaded {len(disasm)} disassembled instructions from DDX.")
    return disasm

def format_instruction(instr):
    regs = [
        'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
        'a4', 'a5', 'a6', 'a7', 't0', 't1', 't2', 't3',
        's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
        't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra',
        'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',
        'f8', 'f9', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15',
        'f16', 'f17', 'f18', 'f19', 'f20', 'f21', 'f22', 'f23',
        'f24', 'f25', 'f26', 'f27', 'f28', 'f29', 'f30', 'f31'
    ]
    reg_pattern = r'(?<!\$)\b(' + '|'.join(regs) + r')\b'
    instr = re.sub(reg_pattern, r'$\1', instr)

    # Normalize MIPS IV condition codes $fcc0-$fcc7
    instr = re.sub(r'\b(c\.[a-z]+\.[sd])\s+\$fcc\d+\s*,\s*', r'\1 ', instr)
    instr = re.sub(r'\b(bc1[tf]l?)\s+\$fcc\d+\s*,\s*', r'\1 ', instr)

    return instr

def write_ddx_asm(funcs, disasm, got_map):
    print("[*] Generating DDX assembly files organized by module...")
    by_group = defaultdict(list)
    for f in funcs:
        group = classify_function(f['name'])
        by_group[group].append(f)

    for group, gfuncs in by_group.items():
        out_s = f"{OUT_DIR}/asm/{MODULE}/{group}/{group}.s"
        os.makedirs(os.path.dirname(out_s), exist_ok=True)
        with open(out_s, 'w') as out:
            out.write(f"# DDX module {MODULE}: group {group}\n")
            out.write(f"# Functions: {len(gfuncs)}\n\n")
            out.write(".text\n.set noat\n.set noreorder\n\n")

            for func in gfuncs:
                fname = func['name']
                cname = func['clean_name']
                low = func['addr']
                size = func['size']
                high = low + size if size > 0 else low + 64

                out.write(f"glabel {cname}\n")

                # Collect instructions and branch targets
                f_insns = []
                branch_targets = set()
                for addr in range(low, high, 4):
                    raw = disasm.get(addr, 'nop')
                    f_insns.append((addr, raw))
                    m = re.search(r'\b([0-9a-fA-F]{7,8})\b', raw)
                    if m:
                        t = int(m.group(1), 16)
                        if low <= t < high:
                            branch_targets.add(t)

                t9_sym = None
                for addr, raw in f_insns:
                    if addr in branch_targets:
                        out.write(f".L{addr:08x}:\n")

                    # Check for GOT loads
                    m_lw = re.search(r'lw\s+([$]?\w+),\s*(-?\d+)\([$]?(?:at|gp)\)', raw)
                    if m_lw:
                        dreg = m_lw.group(1)
                        off = int(m_lw.group(2))
                        if off in got_map:
                            sym = got_map[off]
                            if dreg in ('$t9', 't9'):
                                t9_sym = sym
                            else:
                                raw = f"la\t{dreg},{sanitize_ident(sym)}"

                    if 'jalr' in raw and '$t9' in raw and t9_sym:
                        raw = f"jal\t{sanitize_ident(t9_sym)}"
                        t9_sym = None

                    # Replace objdump targets with labels or symbols
                    m_tgt = re.search(r'\b([0-9a-fA-F]{7,8})\s*<([^>]+)>', raw)
                    if m_tgt:
                        target_addr = int(m_tgt.group(1), 16)
                        target_sym = m_tgt.group(2).split('+')[0]
                        if low <= target_addr < high:
                            raw = raw[:m_tgt.start()] + f".L{target_addr:08x}"
                        else:
                            raw = raw[:m_tgt.start()] + sanitize_ident(target_sym)
                    elif '<' in raw and '>' in raw:
                        raw = re.sub(r'<[^>]+>', '', raw).strip()

                    # Convert bgezall / bgezal with zero to bal
                    raw = re.sub(r'\bbgezall?\s+[$]?zero\s*,\s*', 'bal ', raw)

                    # Format registers
                    formatted = format_instruction(raw)
                    out.write(f"    {formatted}\n")

                out.write("\n")
        print(f"[+] [{group}] Emitted {len(gfuncs)} functions -> {out_s}")

def generate_runner_script():
    script_path = f"{OUT_DIR}/decompile_ddx.sh"
    with open(script_path, 'w') as f:
        f.write(r"""#!/usr/bin/env bash
# decompile_ddx.sh - run m2c over the extracted DDX assembly.
# Usage: decompile_ddx.sh all | MODULE/GROUP     (e.g. kona/abc)
# A reader-written ctx.c beside this script (struct and prototype
# definitions) is passed to m2c when present.
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

M2C="python3 ${ROOT_DIR}/m2c/m2c.py -t mipsn32"
[ -f "${SCRIPT_DIR}/ctx.c" ] && M2C="$M2C --context ${SCRIPT_DIR}/ctx.c"

decompile() {
    local f="$1" rel
    rel="${f#${SCRIPT_DIR}/asm/}"
    local out="${SCRIPT_DIR}/decomp/${rel%.s}.c"
    mkdir -p "$(dirname "$out")"
    echo "[*] Decompiling $f -> $out ..."
    $M2C "$f" > "$out" 2>&1 || true
    echo "[+] Done: $out ($(wc -l < "$out") lines)"
}

if [ $# -eq 0 ] || [ "$1" == "all" ]; then
    for f in "${SCRIPT_DIR}"/asm/*/*/*.s; do decompile "$f"; done
    exit 0
fi

f="${SCRIPT_DIR}/asm/$1/$(basename "$1").s"
[ -f "$f" ] || { echo "[-] File not found: $f"; exit 1; }
decompile "$f"
""")
    os.chmod(script_path, 0o755)
    print(f"[+] Created {script_path}")

def main():
    os.makedirs(f'{OUT_DIR}/{MODULE}', exist_ok=True)
    got_map = build_got_map(TARGET_SO)
    print(f"[*] Loaded {len(got_map)} GOT entries.")
    funcs, objects = parse_dynsyms(TARGET_SO)
    for f in funcs:
        g = _classify(f['name'])
        PREFIX_COUNTS[g] = PREFIX_COUNTS.get(g, 0) + 1
    print(f"[*] Parsed {len(funcs)} functions and {len(objects)} objects.")
    disasm = get_disassembly(TARGET_SO)
    write_ddx_asm(funcs, disasm, got_map)
    groups = sorted({classify_function(f['name']) for f in funcs})
    manifest = {
        'target': TARGET_SO,
        'total_funcs': len(funcs),
        'total_objects': len(objects),
        'modules': {g: len([f for f in funcs if classify_function(f['name']) == g]) for g in groups},
    }
    with open(f'{OUT_DIR}/{MODULE}/manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)
    generate_runner_script()
    print("[SUCCESS] DDX extraction complete")

if __name__ == '__main__':
    main()
