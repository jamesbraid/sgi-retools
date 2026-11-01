# Copyright (c) 2026, Dominik Behr. BSD 3-Clause; see scripts/LICENSE-gr4.
# Adapted from scripts/resolve_got.py in https://github.com/techomancer/gr4 for the KONA
# workspace; board-specific tables were removed.
"""
scripts/resolve_got.py - Dynamic GOT and symbol resolver for IRIX MIPS ELF binaries.
"""

import sys
import struct
from elftools.elf.elffile import ELFFile

def build_got_map(elf_path):
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        got = elf.get_section_by_name('.got')
        if not got:
            return {}
        got_addr = got['sh_addr']
        got_data = got.data()
        gp = got_addr + 0x7ff0

        dynsec = elf.get_section_by_name('.dynamic')
        local_gotno = 0
        gotsym = 0
        if dynsec:
            for tag in dynsec.iter_tags():
                if tag.entry.d_tag == 'DT_MIPS_LOCAL_GOTNO':
                    local_gotno = tag.entry.d_val
                elif tag.entry.d_tag == 'DT_MIPS_GOTSYM':
                    gotsym = tag.entry.d_val

        dynsym = elf.get_section_by_name('.dynsym')
        symtab = elf.get_section_by_name('.symtab')
        addr2sym = {}
        if symtab:
            for s in symtab.iter_symbols():
                if s['st_value']:
                    addr2sym[s['st_value']] = s.name
        if dynsym:
            for s in dynsym.iter_symbols():
                if s['st_value']:
                    addr2sym[s['st_value']] = s.name

        got_map = {}
        esz = 8 if elf.elfclass == 64 else 4
        fmt = '>Q' if esz == 8 else '>I'
        num_entries = len(got_data) // esz
        for i in range(num_entries):
            entry_addr = got_addr + i * esz
            gp_offset = entry_addr - gp
            val = struct.unpack(fmt, got_data[i*esz:(i+1)*esz])[0]
            if local_gotno and i >= local_gotno and dynsym:
                sym_idx = gotsym + (i - local_gotno)
                if sym_idx < dynsym.num_symbols():
                    name = dynsym.get_symbol(sym_idx).name
                else:
                    name = addr2sym.get(val, f'sub_{val:08x}')
            else:
                name = addr2sym.get(val, f'sub_{val:08x}')
            got_map[gp_offset] = name
        return got_map

if __name__ == '__main__':
    elf = sys.argv[1] if len(sys.argv) > 1 else 'libglcore/libGLcore.so'
    got_map = build_got_map(elf)
    print(f"Loaded {len(got_map)} GOT entries for {elf}.")
