#!/usr/bin/env python3
# Copyright (c) 2026, Dominik Behr. BSD 3-Clause; see scripts/LICENSE-gr4.
# Adapted from scripts/extract_libglcore_mgras.py in https://github.com/techomancer/gr4 for the KONA
# workspace; board-specific tables were removed.
"""
scripts/extract_libglcore_kona.py

Extracts DWARF metadata, functions, line tables and disassembly from a
libGLcore.so (MIPS N32 / 64 OpenGL driver) into per-compilation-unit assembly.
Usage: extract_libglcore_kona.py [ELF [OUT_DIR]]   (default libglcore/libGLcore.so)

Generates:
  1. OUT_DIR/manifest.json (machine-readable database of CUs, functions, variables)
  2. OUT_DIR/asm/<category>/<cu>.s (per-CU assembly with labels and line numbers)
  3. OUT_DIR/decompile_libglcore.sh (m2c runner script)

CUs are grouped by the leading directory or filename prefix of their source
name. A stripped binary (no DWARF, as IRIX 6.5.30 ships) falls back to one
pseudo-unit built from .symtab / .dynsym function symbols.
"""
import os
import sys
import io
import re
import json
import struct
import subprocess
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.dwarf.abbrevtable import AbbrevTable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.resolve_got import build_got_map
from scripts.toolchain import objdump

JTBL_BASE = int(os.environ['JTBL_BASE'], 0) if os.environ.get('JTBL_BASE') else None
TARGET_ELF = sys.argv[1] if len(sys.argv) > 1 else 'libglcore/libGLcore.so'
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else 'libglcore'

def category_for(name):
    """Group by the source's leading directory, else its filename prefix."""
    parts = [p for p in name.split('/') if p and p != '.']
    if len(parts) > 1:
        return re.sub(r'[^A-Za-z0-9_.-]', '_', parts[-2])
    m = re.match(r'([A-Za-z0-9]+)_', parts[-1] if parts else '')
    return m.group(1) if m else 'misc'

def clean_cu_name(name):
    return os.path.basename(name)

def setup_dirs(cats):
    os.makedirs(f'{OUT_DIR}/asm', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/decomp', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/include', exist_ok=True)
    for cat in cats:
        os.makedirs(f'{OUT_DIR}/asm/{cat}', exist_ok=True)
        os.makedirs(f'{OUT_DIR}/decomp/{cat}', exist_ok=True)

def symbol_unit(elf_path):
    """Pseudo compilation unit for a binary with no DWARF."""
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        funcs, seen = [], set()
        for secname in ('.symtab', '.dynsym'):
            sec = elf.get_section_by_name(secname)
            if not sec:
                continue
            for s in sec.iter_symbols():
                if s['st_info']['type'] == 'STT_FUNC' and s['st_value'] and s.name \
                        and s['st_value'] not in seen:
                    seen.add(s['st_value'])
                    funcs.append((s.name, s['st_value'], s['st_size']))
        funcs.sort(key=lambda x: x[1])
        end = text['sh_addr'] + text['sh_size']
        out = []
        for i, (n, a, sz) in enumerate(funcs):
            if sz == 0:
                sz = (funcs[i + 1][1] if i + 1 < len(funcs) else end) - a
            out.append({'name': n, 'low_pc': a, 'high_pc': a + sz, 'size': sz,
                        'decl_line': 0, 'min_line': 0, 'max_line': 0, 'frame_size': 0,
                        'is_external': True, 'cu_index': 0, 'cu_name': 'nodwarf',
                        'cu_base': 'nodwarf', 'category': 'nodwarf'})
        cu = {'index': 0, 'name': 'nodwarf', 'basename': 'nodwarf', 'category': 'nodwarf',
              'comp_dir': '', 'producer': '(no DWARF: symbol table only)', 'funcs': out,
              'variables': [], 'line_map': {}}
        return text['sh_addr'], text['sh_size'], [cu], out

def parse_dwarf(elf_path):
    print(f"[*] Parsing DWARF from {elf_path}...")
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print('[!] no DWARF; using symbol table')
            return symbol_unit(elf_path)
        try:
            return _parse_dwarf(elf, elf_path)
        except Exception as e:  # pyelftools rejects some 64-bit SGI DWARF headers
            print(f'[!] DWARF unreadable ({e}); using symbol table')
            return symbol_unit(elf_path)

def _parse_dwarf(elf, elf_path):
    text_sec = elf.get_section_by_name('.text')
    text_addr = text_sec['sh_addr']
    text_size = text_sec['sh_size']

    dwarf = elf.get_dwarf_info()
    data_abbrev = dwarf.debug_abbrev_sec.stream.getvalue()
    cu_abbrev_offsets = sorted(set(cu.header['debug_abbrev_offset'] for cu in dwarf.iter_CUs()))
    cu_abbrev_offsets.append(len(data_abbrev))
    abbrev_slices = {}
    for i in range(len(cu_abbrev_offsets) - 1):
        start = cu_abbrev_offsets[i]
        end = cu_abbrev_offsets[i+1]
        abbrev_slices[start] = data_abbrev[start:end] + b'\x00'

    orig_get_abbrev = dwarf.get_abbrev_table
    def patched_get_abbrev(offset):
        if offset in abbrev_slices:
            return AbbrevTable(dwarf.structs, io.BytesIO(abbrev_slices[offset]), 0)
        return orig_get_abbrev(offset)
    dwarf.get_abbrev_table = patched_get_abbrev

    cus = []
    all_funcs = []
    for i, cu in enumerate(dwarf.iter_CUs()):
        top = cu.get_top_DIE()
        name_attr = top.attributes.get('DW_AT_name')
        name_str = name_attr.value.decode('utf-8', errors='ignore') if name_attr else f'cu_{i}'
        comp_dir_attr = top.attributes.get('DW_AT_comp_dir')
        comp_dir_str = comp_dir_attr.value.decode('utf-8', errors='ignore') if comp_dir_attr else ''
        producer_attr = top.attributes.get('DW_AT_producer')
        producer_str = producer_attr.value.decode('utf-8', errors='ignore') if producer_attr else ''

        # Line table
        line_map = {}
        try:
            lp = dwarf.line_program_for_CU(cu)
            if lp:
                for entry in lp.get_entries():
                    if entry.state:
                        line_map[entry.state.address] = entry.state.line
        except Exception:
            pass

        category = category_for(name_str)
        cu_base = clean_cu_name(name_str)

        funcs = []
        variables = []
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_subprogram':
                sub_name = die.attributes.get('DW_AT_name')
                low_pc = die.attributes.get('DW_AT_low_pc')
                high_pc = die.attributes.get('DW_AT_high_pc')
                decl_line = die.attributes.get('DW_AT_decl_line')
                frame_base = die.attributes.get('DW_AT_frame_base')
                ext = die.attributes.get('DW_AT_external')

                if sub_name and low_pc and high_pc:
                    sname = sub_name.value.decode('utf-8', errors='ignore')
                    low = low_pc.value
                    high = high_pc.value
                    dline = decl_line.value if decl_line else 0
                    frame_size = 0
                    if frame_base:
                        val = frame_base.value
                        if isinstance(val, list) and len(val) >= 2 and val[0] == 141:  # DW_OP_breg29
                            frame_size = val[1]

                    func_lines = [l for addr, l in line_map.items() if low <= addr < high]
                    min_l = min(func_lines) if func_lines else dline
                    max_l = max(func_lines) if func_lines else dline

                    func_obj = {
                        'name': sname,
                        'low_pc': low,
                        'high_pc': high,
                        'size': high - low,
                        'decl_line': dline,
                        'min_line': min_l,
                        'max_line': max_l,
                        'frame_size': frame_size,
                        'is_external': bool(ext and ext.value),
                        'cu_index': i,
                        'cu_name': name_str,
                        'cu_base': cu_base,
                        'category': category
                    }
                    funcs.append(func_obj)
                    all_funcs.append(func_obj)

            elif die.tag == 'DW_TAG_variable':
                vname = die.attributes.get('DW_AT_name')
                loc = die.attributes.get('DW_AT_location')
                dline = die.attributes.get('DW_AT_decl_line')
                if vname:
                    var_name = vname.value.decode('utf-8', errors='ignore')
                    addr = 0
                    if loc and isinstance(loc.value, list) and len(loc.value) >= 5 and loc.value[0] == 3:
                        addr = int.from_bytes(bytes(loc.value[1:5]), 'big')
                    variables.append({
                        'name': var_name,
                        'addr': addr,
                        'decl_line': dline.value if dline else 0
                    })

        funcs.sort(key=lambda x: x['low_pc'])
        cus.append({
            'index': i,
            'name': name_str,
            'basename': cu_base,
            'category': category,
            'comp_dir': comp_dir_str,
            'producer': producer_str,
            'funcs': funcs,
            'variables': variables,
            'line_map': line_map
        })

    print(f"[+] Found {len(cus)} CUs and {len(all_funcs)} functions.")
    return text_addr, text_size, cus, all_funcs

def get_disassembly():
    print("[*] Disassembling .text...")
    cmd = [objdump(), '-d', '--no-show-raw-insn', TARGET_ELF]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)

    disasm = {}
    pattern = re.compile(r'^\s*([0-9a-fA-F]+):\s*(.*)')
    for line in res.stdout.splitlines():
        m = pattern.match(line)
        if m:
            addr = int(m.group(1), 16)
            instr = m.group(2).strip()
            disasm[addr] = instr
    print(f"[+] Loaded {len(disasm)} disassembled instructions.")
    return disasm

def format_instruction(addr, instr):
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
    # Normalize MIPS IV condition codes $fcc0-$fcc7 for m2c
    instr = re.sub(r'\b(c\.[a-z]+\.[sd])\s+\$fcc\d+\s*,\s*', r'\1 ', instr)
    instr = re.sub(r'\b(bc1[tf]l?)\s+\$fcc\d+\s*,\s*', r'\1 ', instr)
    return instr

def got_gp(elf_path):
    with open(elf_path, 'rb') as f:
        got = ELFFile(f).get_section_by_name('.got')
        return got['sh_addr'] + 0x7ff0 if got else 0

def build_lit_maps(elf_path, gp_val=None):
    if gp_val is None:
        gp_val = got_gp(elf_path)
    lit4, lit8 = {}, {}
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for s in elf.iter_sections():
            if s.name == ".lit4":
                data = s.data()
                base = s["sh_addr"]
                for i in range(0, len(data), 4):
                    addr = base + i
                    off = addr - gp_val
                    uval = struct.unpack(">I", data[i:i+4])[0]
                    fval = struct.unpack(">f", data[i:i+4])[0]
                    lit4[off] = (fval, uval)
            elif s.name == ".lit8":
                data = s.data()
                base = s["sh_addr"]
                for i in range(0, len(data), 8):
                    addr = base + i
                    off = addr - gp_val
                    uval = struct.unpack(">Q", data[i:i+8])[0]
                    fval = struct.unpack(">d", data[i:i+8])[0]
                    lit8[off] = (fval, uval)
    return lit4, lit8

def build_jtbl_map(elf_path, all_funcs):
    funcs_by_range = [(f["low_pc"], f["high_pc"], f["name"]) for f in all_funcs]
    def get_func_for_pc(pc):
        for low, high, name in funcs_by_range:
            if low <= pc < high:
                return name
        return None

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        rodata = elf.get_section_by_name(".rodata")
        rdata = rodata.data()
        rbase = rodata["sh_addr"]
        rsize = rodata["sh_size"]
        text = elf.get_section_by_name(".text")
        tbase = text["sh_addr"]
        tsize = text["sh_size"]

    tables = {}
    i = 0
    while i < rsize:
        val = struct.unpack(">I", rdata[i:i+4])[0]
        if tbase <= val < tbase + tsize:
            start_addr = rbase + i
            fn_name = get_func_for_pc(val)
            entries = []
            while i < rsize:
                v = struct.unpack(">I", rdata[i:i+4])[0]
                if tbase <= v < tbase + tsize:
                    v_fn = get_func_for_pc(v)
                    if v_fn == fn_name:
                        entries.append(v)
                        i += 4
                    else:
                        break
                else:
                    break
            if entries and fn_name:
                tables[start_addr] = {
                    "fn_name": fn_name,
                    "entries": entries
                }
        else:
            i += 4
    return tables

def write_cu_assembly(cu, disasm_map, got_map, lit4_map, lit8_map, jtbl_map):
    cat = cu['category']
    cu_base = cu['basename']
    base_no_ext = os.path.splitext(cu_base)[0]
    out_asm_path = f"{OUT_DIR}/asm/{cat}/{base_no_ext}.s"
    cu['asm_file'] = out_asm_path
    cu['decomp_file'] = f"{OUT_DIR}/decomp/{cat}/{base_no_ext}.c"

    cu_funcs = {f['name'] for f in cu['funcs']}
    cu_jtbls = {addr: info for addr, info in jtbl_map.items() if info['fn_name'] in cu_funcs}
    cu_lits = {}

    with open(out_asm_path, 'w') as f:
        f.write(f"# Source: {cu['name']}\n")
        f.write(f"# Category: {cat}\n")
        f.write(f"# Compiler Options: {cu['producer']}\n")
        f.write(f"# Total Functions: {len(cu['funcs'])}\n\n")
        f.write(f".text\n\n")

        line_map = cu['line_map']

        for func in cu['funcs']:
            fname = func['name']
            low = func['low_pc']
            high = func['high_pc']
            size = func['size']
            dline = func['decl_line']
            min_l = func['min_line']
            max_l = func['max_line']
            fsize = func['frame_size']

            f.write(f"# Function: {fname}\n")
            f.write(f"# Declared: Line {dline} (Source lines: {min_l}-{max_l})\n")
            f.write(f"# Address: 0x{low:08x} - 0x{high:08x} (Size: {size} bytes, Frame: {fsize})\n")
            if func['is_external']:
                f.write(f".globl {fname}\n")
            f.write(f".ent {fname}\n")
            f.write(f"{fname}:\n")

            func_items = []
            for addr in range(low, high, 4):
                raw = disasm_map.get(addr, 'nop')
                func_items.append({'addr': addr, 'raw': raw, 'line': line_map.get(addr)})

            branch_targets = set()
            for item in func_items:
                m = re.search(r'\b([0-9a-fA-F]{7,8})\b', item['raw'])
                if m:
                    target = int(m.group(1), 16)
                    if low <= target < high:
                        branch_targets.add(target)

            fn_jtbls = {t_addr: t_info for t_addr, t_info in cu_jtbls.items() if t_info['fn_name'] == fname}
            for t_info in fn_jtbls.values():
                for target in t_info['entries']:
                    if low <= target < high:
                        branch_targets.add(target)

            gp_regs = {'gp'}
            for item in func_items:
                m_addu = re.search(r'addu\s+[$]?([a-zA-Z0-9]+),\s*[$]?t9,\s*[$]?([a-zA-Z0-9]+)', item['raw'])
                if m_addu:
                    gp_regs.add(m_addu.group(1).lstrip('$'))

            gp_reg_pattern = '|'.join(re.escape(r) for r in gp_regs)

            # Resolve GOT calls and float/double loads
            t9_target = None
            for idx, item in enumerate(func_items):
                raw_instr = item['raw']

                m_lw = re.search(r'lw\s+([$]?\w+),\s*(-?\d+)\([$]?(' + gp_reg_pattern + r')\)', raw_instr)
                if m_lw:
                    dest_reg = m_lw.group(1)
                    off = int(m_lw.group(2))
                    if off in got_map:
                        sym = got_map[off]
                        if dest_reg in ('$t9', 't9'):
                            t9_target = sym
                            in_delay = False
                            if idx > 0:
                                prev_raw = func_items[idx-1]['raw'].strip()
                                if prev_raw.startswith(('b', 'j', 'jal', 'jr')):
                                    in_delay = True
                            if in_delay:
                                item['raw'] = f"nop\t# was lw $t9, {off}($gp) # &{sym}"
                            else:
                                item['raw'] = f"# lw $t9, {off}($gp) # &{sym}"
                                item['is_comment'] = True
                        else:
                            item['raw'] = f"la\t{dest_reg},{sym}"
                        continue

                if ('jalr' in raw_instr and 't9' in raw_instr) and t9_target:
                    item['raw'] = f"jal\t{t9_target}"
                    t9_target = None
                    continue

                m_lwc1 = re.search(r'lwc1\s+([$]?f\d+),\s*(-?\d+)\([$]?(' + gp_reg_pattern + r')\)', raw_instr)
                if m_lwc1:
                    freg = m_lwc1.group(1)
                    off = int(m_lwc1.group(2))
                    if off in lit4_map:
                        fval, uval = lit4_map[off]
                        if uval == 0:
                            item['raw'] = f"mtc1\t$zero,{freg}"
                        else:
                            lit_sym = f"_lit_{uval:08x}"
                            cu_lits[lit_sym] = (4, uval)
                            item['raw'] = f"lwc1\t{freg},{lit_sym}"
                        continue

                m_ldc1 = re.search(r'ldc1\s+([$]?f\d+),\s*(-?\d+)\([$]?(' + gp_reg_pattern + r')\)', raw_instr)
                if m_ldc1:
                    freg = m_ldc1.group(1)
                    off = int(m_ldc1.group(2))
                    if off in lit8_map:
                        fval, uval = lit8_map[off]
                        if uval == 0:
                            item['raw'] = f"dmtc1\t$zero,{freg}"
                        else:
                            lit_sym = f"_lit8_{uval:016x}"
                            cu_lits[lit_sym] = (8, uval)
                            item['raw'] = f"ldc1\t{freg},{lit_sym}"
                        continue

                if re.search(r'\bjr\s+[$]?t9\b', raw_instr):
                    if idx + 1 < len(func_items):
                        delay_item = func_items[idx + 1]
                        m_delay_lw = re.search(r'lw\s+[$]?t9,\s*(-?\d+)\([$]?(' + gp_reg_pattern + r')\)', delay_item['raw'])
                        if m_delay_lw:
                            off = int(m_delay_lw.group(1))
                            if off in got_map:
                                sym = got_map[off]
                                item['raw'] = f"j\t{sym}"
                                delay_item['raw'] = f"nop\t# was lw $t9, {off}($gp)"

            # Jump tables: rewrite 'addiu rX,rY,OFF' when OFF is the table's offset
            # from JTBL_BASE (an address you identified in the binary; see --jtbl-base
            # in AGENTS.md). Without a base the tables are still emitted, unreferenced.
            for t_addr, t_info in fn_jtbls.items():
                jtbl_sym = f"jtbl_{t_addr:08x}"
                if JTBL_BASE is None:
                    continue
                off = t_addr - JTBL_BASE
                for idx, item in enumerate(func_items):
                    m_addiu = re.search(rf'addiu\s+([$]?\w+),\s*[$]?\w+,\s*{off}\b', item['raw'])
                    if m_addiu:
                        base_reg = m_addiu.group(1)
                        if not base_reg.startswith('$'):
                            base_reg = '$' + base_reg
                        item['raw'] = f"lui\t{base_reg},%hi({jtbl_sym})"
                        break

                for idx in range(len(func_items)):
                    m_jr = re.search(r'\bjr\s+([$]?\w+)', func_items[idx]['raw'])
                    if m_jr:
                        jr_reg = m_jr.group(1).lstrip('$')
                        if jr_reg != 'ra':
                            for k in range(idx - 1, max(-1, idx - 6), -1):
                                m_lw = re.search(r'\blw\s+[$]?' + jr_reg + r',\s*0\(([$]?\w+)\)', func_items[k]['raw'])
                                if m_lw:
                                    func_items[k]['raw'] = f"lw\t${jr_reg},%lo({jtbl_sym})({m_lw.group(1)})"
                                    break

            last_line = -1
            for item in func_items:
                addr = item['addr']
                raw_instr = item['raw']
                l = item['line']

                if addr in branch_targets:
                    f.write(f".L{addr:08x}:\n")

                if l is not None and l != last_line:
                    f.write(f"    # Line {l}\n")
                    last_line = l

                if not item.get('is_comment'):
                    m = re.search(r'\b([0-9a-fA-F]{7,8})\s*<([^>]+)>', raw_instr)
                    if m:
                        target_addr = int(m.group(1), 16)
                        target_sym = m.group(2).split('+')[0]
                        if low <= target_addr < high:
                            raw_instr = raw_instr[:m.start()] + f".L{target_addr:08x}"
                        else:
                            raw_instr = raw_instr[:m.start()] + target_sym

                    raw_instr = re.sub(r'\bbgezall?\s+[$]?zero\s*,\s*', 'bal ', raw_instr)
                    formatted = format_instruction(addr, raw_instr)
                    f.write(f"    {formatted}\n")
                else:
                    f.write(f"    {raw_instr}\n")

            f.write(f".end {fname}\n\n")

        if cu_jtbls:
            f.write(".late_rodata\n")
            for t_addr, t_info in sorted(cu_jtbls.items()):
                f.write(f"{f'jtbl_{t_addr:08x}'}:\n")
                for target in t_info['entries']:
                    f.write(f"    .word .L{target:08x}\n")
            f.write("\n")

        if cu_lits:
            f.write(".rdata\n")
            for lit_sym, (lit_size, lit_val) in sorted(cu_lits.items()):
                f.write(f"{lit_sym}:\n")
                if lit_size == 4:
                    f.write(f"    .word 0x{lit_val:08x}\n")
                else:
                    f.write(f"    .word 0x{lit_val >> 32:08x}, 0x{lit_val & 0xffffffff:08x}\n")
            f.write("\n")

def generate_runner_script():
    script_path = f"{OUT_DIR}/decompile_libglcore.sh"
    with open(script_path, "w") as f:
        f.write(r"""#!/usr/bin/env bash
# decompile_libglcore.sh
# Runs m2c decompiler on libGLcore.so functions and modules using ctx_libglcore.c in N32 mode.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# A reader-written context file (struct definitions, prototypes) improves output.
CTX="${SCRIPT_DIR}/ctx_libglcore.c"
M2C="python3 ${ROOT_DIR}/m2c/m2c.py -t mipsn32"
[ -f "$CTX" ] && M2C="$M2C --context $CTX"

if [ $# -eq 0 ]; then
    echo "Usage:"
    echo "  $0 <module_name>       (e.g., $0 some_cu)"
    echo "  $0 <category>          (e.g., $0 <category dir under asm/>)"
    echo "  $0 --func <func_name>  (e.g., $0 --func some_function)"
    echo "  $0 all                 (decompile every module)"
    exit 1
fi

decompile_file() {
    local asm_file="$1"
    local rel_path="${asm_file#${SCRIPT_DIR}/asm/}"
    local out_c="${SCRIPT_DIR}/decomp/${rel_path%.s}.c"
    mkdir -p "$(dirname "$out_c")"
    echo "[*] Decompiling $asm_file -> $out_c ..."
    if $M2C "$asm_file" > "$out_c" 2>&1; then
        echo "[+] Done: $out_c ($(wc -l < "$out_c") lines)"
    else
        echo "[-] Failed: $asm_file"
    fi
}

if [ "$1" == "--func" ]; then
    func_name="$2"
    echo "[*] Searching for function $func_name across assembly files..."
    asm_file=$(grep -l "\.ent $func_name" "${SCRIPT_DIR}/asm"/*/*.s | head -n 1)
    if [ -z "$asm_file" ]; then
        echo "[-] Function $func_name not found in ${SCRIPT_DIR}/asm/*/*.s"
        exit 1
    fi
    echo "[*] Found in $asm_file. Decompiling..."
    $M2C -f "$func_name" "$asm_file"
    exit 0
fi

if [ "$1" == "all" ]; then
    echo "[*] Decompiling every module..."
    for f in "${SCRIPT_DIR}"/asm/*/*.s; do
        decompile_file "$f"
    done
    exit 0
fi

if [ -d "${SCRIPT_DIR}/asm/$1" ]; then
    for f in "${SCRIPT_DIR}/asm/$1"/*.s; do
        decompile_file "$f"
    done
    exit 0
fi

# Search by module basename
target="$1"
target="${target%.c}"
target="${target%.s}"
matches=$(find "${SCRIPT_DIR}/asm" -name "${target}.s")
if [ -z "$matches" ]; then
    echo "[-] Module ${target}.s not found under ${SCRIPT_DIR}/asm/"
    exit 1
fi

for f in $matches; do
    decompile_file "$f"
done
""")
    os.chmod(script_path, 0o755)
    print(f"[+] Created {script_path}")

def main():
    got_map = build_got_map(TARGET_ELF)
    print(f"[*] Loaded {len(got_map)} entries from GOT.")
    lit4_map, lit8_map = build_lit_maps(TARGET_ELF)
    print(f"[*] Loaded {len(lit4_map)} .lit4 and {len(lit8_map)} .lit8 constants.")
    text_addr, text_size, cus, all_funcs = parse_dwarf(TARGET_ELF)
    cats = sorted({c['category'] for c in cus})
    setup_dirs(cats)
    jtbl_map = build_jtbl_map(TARGET_ELF, all_funcs)
    print(f"[*] Loaded {len(jtbl_map)} jump tables.")
    disasm_map = get_disassembly()

    print("[*] Writing per-CU assembly files...")
    for cu in cus:
        if cu['funcs']:
            write_cu_assembly(cu, disasm_map, got_map, lit4_map, lit8_map, jtbl_map)

    manifest = {
        'target_elf': TARGET_ELF,
        'text_addr': hex(text_addr),
        'text_size': text_size,
        'total_cus': len(cus),
        'total_funcs': len(all_funcs),
        'categories': {cat: sum(1 for c in cus if c['category'] == cat) for cat in cats},
        'cus': [
            {
                'index': c['index'], 'name': c['name'], 'basename': c['basename'],
                'category': c['category'], 'num_funcs': len(c['funcs']),
                'asm_file': c.get('asm_file', ''), 'decomp_file': c.get('decomp_file', ''),
                'producer': c['producer'], 'funcs': c['funcs'], 'variables': c['variables']
            }
            for c in cus
        ]
    }
    with open(f'{OUT_DIR}/manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Wrote manifest with {len(cus)} CUs and {len(all_funcs)} functions.")
    generate_runner_script()
    print("[SUCCESS] extraction complete")

if __name__ == '__main__':
    main()
