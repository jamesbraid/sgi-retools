#!/usr/bin/env python3
# Copyright (c) 2026, Dominik Behr. BSD 3-Clause; see scripts/LICENSE-gr4.
# Adapted from scripts/map_binaries.py in https://github.com/techomancer/gr4 for the KONA
# workspace; board-specific tables were removed.
"""
scripts/map_binaries.py - Map and inspect all binaries in this workspace.

Walks the symlink directories (following links into root/) and reports, for
every ELF file, its sections, function symbols and DWARF compilation units.
Non-ELF files (microcode, tables) are listed by size.

Outputs:
  - binaries_manifest.json
  - Detailed terminal report
"""

import os
import sys
import glob
import json
import subprocess
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.dwarf.abbrevtable import AbbrevTable
import io

def get_dwarf_cus(elf):
    if not elf.has_dwarf_info():
        return []
    try:
        dwarf = elf.get_dwarf_info()
        data_abbrev = dwarf.debug_abbrev_sec.stream.getvalue()
        cu_abbrev_offsets = sorted(set(cu.header['debug_abbrev_offset'] for cu in dwarf.iter_CUs()))
        cu_abbrev_offsets.append(len(data_abbrev))
        abbrev_slices = {
            cu_abbrev_offsets[i]: data_abbrev[cu_abbrev_offsets[i]:cu_abbrev_offsets[i+1]] + b'\x00'
            for i in range(len(cu_abbrev_offsets) - 1)
        }
        orig_get = dwarf.get_abbrev_table
        dwarf.get_abbrev_table = lambda off: AbbrevTable(dwarf.structs, io.BytesIO(abbrev_slices[off]), 0) if off in abbrev_slices else orig_get(off)

        cus = []
        for cu in dwarf.iter_CUs():
            top = cu.get_top_DIE()
            name_attr = top.attributes.get('DW_AT_name')
            producer_attr = top.attributes.get('DW_AT_producer')
            cus.append({
                'name': name_attr.value.decode('utf-8', errors='ignore') if name_attr else 'unknown',
                'producer': producer_attr.value.decode('utf-8', errors='ignore') if producer_attr else ''
            })
        return cus
    except Exception as e:
        return [{'error': str(e)}]

def analyze_elf(path):
    info = {
        'path': path,
        'filename': os.path.basename(path),
        'size': os.path.getsize(path),
        'sections': {},
        'symbols_count': 0,
        'dynsyms_count': 0,
        'funcs': [],
        'has_dwarf': False,
        'cus': []
    }
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        info['class'] = elf.elfclass
        info['arch'] = elf.get_machine_arch()
        info['type'] = elf.header['e_type']
        
        for s in elf.iter_sections():
            if s['sh_size'] > 0:
                info['sections'][s.name] = s['sh_size']
        
        symtab = elf.get_section_by_name('.symtab')
        if symtab:
            info['symbols_count'] = symtab.num_symbols()
            for s in symtab.iter_symbols():
                if s['st_info']['type'] == 'STT_FUNC' and s['st_size'] > 0:
                    info['funcs'].append({
                        'name': s.name,
                        'value': hex(s['st_value']),
                        'size': s['st_size'],
                        'bind': s['st_info']['bind']
                    })
        
        dynsym = elf.get_section_by_name('.dynsym')
        if dynsym:
            info['dynsyms_count'] = dynsym.num_symbols()
            if not info['funcs']:
                for s in dynsym.iter_symbols():
                    if s['st_info']['type'] == 'STT_FUNC' and s['st_size'] > 0:
                        info['funcs'].append({
                            'name': s.name,
                            'value': hex(s['st_value']),
                            'size': s['st_size'],
                            'bind': s['st_info']['bind']
                        })
        
        info['has_dwarf'] = elf.has_dwarf_info()
        if info['has_dwarf']:
            info['cus'] = get_dwarf_cus(elf)
            
    return info

BOARD_NAME = 'KONA'
# Directories of symlinks into root/ (see IRIX_FILES.md). Edit for new binaries.
CATEGORIES = ['kona_kernel', 'libglcore', 'irisgl', 'ddx', 'ucode', 'diags']


def is_elf(path):
    with open(path, 'rb') as f:
        return f.read(4) == b'\x7fELF'


def walk(top):
    """All regular files below top, following symlinks."""
    for dirpath, _, names in os.walk(top, followlinks=True):
        for n in names:
            p = os.path.join(dirpath, n)
            if os.path.isfile(p) and not n.startswith('.') and '/asm' not in p \
                    and '/disasm' not in p and '/decomp' not in p and '/include' not in p \
                    and not p.endswith(('.md', '.txt', '.json', '.h', '.c', '.s')):
                yield p


def main():
    print("======================================================================")
    print(f"{BOARD_NAME} Binary Cataloging & Analysis")
    print("======================================================================")
    
    categories = {cat: sorted(walk(cat)) for cat in CATEGORIES}

    full_manifest = {}

    for cat, files in categories.items():
        print(f"\n--- {cat.upper()} ({len(files)} files) ---")
        cat_data = []
        for fpath in files:
            if not is_elf(fpath):
                sz = os.path.getsize(fpath)
                print(f"  {os.path.basename(fpath):25s} Size: {sz:8d} bytes (Data/Microcode)")
                cat_data.append({'filename': fpath, 'size': sz, 'type': 'data'})
                continue

            elf_info = analyze_elf(fpath)
            cat_data.append(elf_info)
            t_sz = elf_info['sections'].get('.text', 0)
            n_fn = len(elf_info['funcs'])
            n_cu = len(elf_info['cus'])
            print(f"  {elf_info['filename']:25s} ELF{elf_info['class']} | text: {t_sz:7d} B | funcs: {n_fn:4d} | CUs: {n_cu:3d} | DWARF: {elf_info['has_dwarf']}")

        full_manifest[cat] = cat_data

    manifest_file = 'binaries_manifest.json'
    with open(manifest_file, 'w') as f:
        json.dump(full_manifest, f, indent=2)
    print(f"\n[+] Saved detailed manifest to {manifest_file}")
    print("======================================================================")

if __name__ == '__main__':
    main()
