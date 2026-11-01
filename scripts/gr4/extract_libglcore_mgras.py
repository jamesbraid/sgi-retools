#!/usr/bin/env python3
"""
scripts/extract_libglcore_mgras.py

Extracts all DWARF metadata, functions, line tables, and disassembly from
libglcore/libGLcore.so (MIPS-III N32 OpenGL driver for SGI Impact / MGRAS / GR4).

Organizes code into original .c compilation units across 7 categories:
  - MGRAS   (MGRAS hardware drivers: mgras_*.c, mgras_*.s, mips_*.s)
  - soft    (software rasterizer fallback: so_*.c)
  - pixel   (pixel pipeline: px_*.c)
  - dlist   (display list engine: dl_*.c)
  - gl      (core GL routines: g_lcomp.c, g_lexec.c, etc.)
  - mips    (optimized assembly routines: mips_*.s)
  - PIXMAP  (pixmap rendering: pm_*.c)

Generates:
  1. libglcore/manifest.json (complete machine-readable database)
  2. libglcore/asm/<category>/<cu>.s (per-CU assembly with labels & line numbers)
  3. libglcore/include/glcore_types.h & glcore_mgras.h (data structures & hardware context)
  4. libglcore/include/glcore_prots.h (prototypes for all functions)
  5. ctx_libglcore_source.h & ctx_libglcore.c (preprocessed context for m2c)
  6. decompile_libglcore.sh (decompilation runner script)
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

TARGET_ELF = 'libglcore/libGLcore.so'
OUT_DIR = 'libglcore'

CATEGORIES = ['MGRAS', 'soft', 'pixel', 'dlist', 'gl', 'mips', 'PIXMAP']

def setup_dirs():
    os.makedirs(f'{OUT_DIR}/asm', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/decomp', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/include', exist_ok=True)
    for cat in CATEGORIES:
        os.makedirs(f'{OUT_DIR}/asm/{cat}', exist_ok=True)
        os.makedirs(f'{OUT_DIR}/decomp/{cat}', exist_ok=True)

def categorize_cu(name):
    if 'MGRAS' in name or 'mgras' in name:
        return 'MGRAS'
    elif 'soft/' in name or name.startswith('so_'):
        return 'soft'
    elif 'pixel/' in name or name.startswith('px_'):
        return 'pixel'
    elif 'dlist/' in name or name.startswith('dl_'):
        return 'dlist'
    elif 'PIXMAP/' in name or name.startswith('pm_'):
        return 'PIXMAP'
    elif name.startswith('g_'):
        return 'gl'
    elif 'mips/' in name or name.startswith('mips_'):
        return 'mips'
    return 'MGRAS'

def clean_cu_name(name):
    base = os.path.basename(name)
    return base

def parse_dwarf(elf_path):
    print(f"[*] Parsing DWARF from {elf_path}...")
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
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

            category = categorize_cu(name_str)
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
    print("[*] Disassembling .text using mips-unknown-linux-gnu-objdump...")
    cmd = ['mips-unknown-linux-gnu-objdump', '-d', '--no-show-raw-insn', TARGET_ELF]
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
    # Replace thread-local loads 4112(zero) -> __glCurrentContext, 4120(zero) -> __glBeginMode
    instr = re.sub(r'4112\((?:\$?zero|\$0)\)', '__glCurrentContext', instr)
    instr = re.sub(r'4120\((?:\$?zero|\$0)\)', '__glBeginMode', instr)

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
    return instr

def build_lit_maps(elf_path, gp_val=0xdbfe698):
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

            # Jump tables
            for t_addr, t_info in fn_jtbls.items():
                off = t_addr - 0x0dbed000
                jtbl_sym = f"jtbl_{t_addr:08x}"
                for idx, item in enumerate(func_items):
                    raw = item['raw']
                    m_addiu = re.search(rf'addiu\s+([$]?\w+),\s*[$]?\w+,\s*{off}\b', raw)
                    if m_addiu:
                        base_reg = m_addiu.group(1)
                        if not base_reg.startswith('$'):
                            base_reg = '$' + base_reg
                        item['raw'] = f"lui\t{base_reg},%hi({jtbl_sym})"
                        break

                for idx in range(len(func_items)):
                    raw_jr = func_items[idx]['raw']
                    m_jr = re.search(r'\bjr\s+([$]?\w+)', raw_jr)
                    if m_jr:
                        jr_reg = m_jr.group(1).lstrip('$')
                        if jr_reg != 'ra':
                            for k in range(idx - 1, max(-1, idx - 6), -1):
                                raw_lw = func_items[k]['raw']
                                m_lw = re.search(r'\blw\s+[$]?' + jr_reg + r',\s*0\(([$]?\w+)\)', raw_lw)
                                if m_lw:
                                    comb_reg = m_lw.group(1)
                                    func_items[k]['raw'] = f"lw\t${jr_reg},%lo({jtbl_sym})({comb_reg})"
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

def parse_gl_api_prototypes():
    protos = {}
    gl_h = f"{OUT_DIR}/include/gl_1_1.h"
    if os.path.exists(gl_h):
        with open(gl_h) as f:
            for line in f:
                m = re.match(r'^(.*?)\s+gl(\w+)\s*\((.*?)\);', line.strip())
                if m:
                    ret, name, params = m.groups()
                    protos[name] = (ret.strip(), params.strip())
    print(f"[*] Loaded {len(protos)} API prototypes from gl_1_1.h.")
    return protos

def generate_context_headers(all_funcs):
    print("[*] Generating context headers for m2c...")
    gl_api = parse_gl_api_prototypes()

    # 1. libglcore/include/glcore_mgras.h
    mgras_h_path = f"{OUT_DIR}/include/glcore_mgras.h"
    with open(mgras_h_path, 'w') as f:
        f.write("""#ifndef __GLCORE_MGRAS_H__
#define __GLCORE_MGRAS_H__

/*
 * glcore_mgras.h - SGI Impact / Mardi Gras (MGRAS) OpenGL Driver Context & Structures
 * Authoritative header for Silicon Graphics Impact Graphics subsystem.
 */

#include "glcore_types.h"
#include "../../MGRAS.h"
#include "../../HQ3.h"
#include "../../GE11.h"
#include "../../RE4.h"
#include "../../PP1.h"
#include "../../TE1.h"
#include "../../VC3.h"
#include "../../CMAP.h"

/* MGRAS Board Capabilities */
typedef struct __glMgrasCapsRec {
    u32 num_re;             /* Number of RE4 chips: 1 (Solid Impact) or 2 (High/Max) */
    u32 num_te;             /* Number of TE1 chips: 0 (Solid), 1 (High), 2 (Max) */
    u32 num_pp;             /* Number of PP1 chips: 1 or 2 */
    u32 tram_size;          /* TETRAM size in bytes: 1MB or 4MB */
    u32 has_tbuf;           /* Texture buffer installed (TRAM option) */
    u32 dram_type;          /* Framebuffer RDRAM type and channel count */
    u32 board_rev;          /* Board revision from HQ3 config */
    u32 dcb_mode;           /* DCB bus mode */
} __glMgrasCaps;

/* MGRAS Driver Private Context (__glMgrasContext: 47688 bytes = 0xBA48) */
typedef struct __glMgrasContextRec {
    __GLcontext         gc;                 /* 0x0000 - 0x7B77 (Base OpenGL Context) */
    char                pad_base[0x1B18];   /* 0x7B78 - 0x968F (Driver Private State) */

    /* 0x9690: MGRAS Hardware Register Aperture */
    mgras_hw            *hw;                /* 0x9690: Pointer to memory-mapped ASIC apertures */
    __glMgrasCaps       caps;               /* 0x9694: Board capability flags */

    /* 0x96B4: FIFO & Command Queue State */
    u32                 cfifo_hw_free;      /* Current free words in HQ3 CFIFO */
    u32                 dfifo_hw_free;      /* Current free words in HQ3 DFIFO */
    u32                 dcb_ctrl;           /* DCB bus control shadow */

    /* 0x96C0: RE4 Rasterizer Mode Registers */
    u32                 re_mode1;           /* 0x96C0: RE4 MODE1 shadow */
    u32                 re_mode2;           /* 0x96C4: RE4 MODE2 shadow */
    u32                 re_fillmode;        /* 0x96C8: RE4 FILLMODE shadow */
    u32                 re_viewport;        /* 0x96CC: RE4 packed viewport (X << 16 | (X + W - 1)) */
    u32                 re_viewport_y;      /* 0x96D0: RE4 packed viewport Y */
    u32                 re_ir_opcode;       /* 0x96D4: Iteration request opcode */
    char                pad_re[0xC4];       /* 0x96D8 - 0x979B */

    /* 0x979C: Scissor / Screen Window Limits */
    u32                 scissor_xmax;       /* 0x979C: Default 1279 */
    u32                 scissor_ymax;       /* 0x97A0: Default 1023 */
    u32                 scissor_boxes[8];   /* 0x97A4 - 0x97C3: 4 hardware scissor boxes */

    /* 0x97C4 - 0xBA47: Remaining Context Tail */
    char                pad_tail[0x2284];   /* 0x97C4 - 0xBA47 */
} __glMgrasContext;

#endif /* __GLCORE_MGRAS_H__ */
""")

    # 2. libglcore/include/glcore_types.h
    types_path = f"{OUT_DIR}/include/glcore_types.h"
    with open(types_path, 'w') as f:
        f.write("""#ifndef __GLCORE_TYPES_H__
#define __GLCORE_TYPES_H__

/* Primitive integer and floating point types */
typedef signed char         s8;
typedef unsigned char       u8;
typedef signed short        s16;
typedef unsigned short      u16;
typedef signed int          s32;
typedef unsigned int        u32;
typedef signed long long    s64;
typedef unsigned long long  u64;
typedef float               f32;
typedef double              f64;
typedef unsigned int        size_t;

/* Standard OpenGL 1.1 types and enums */
#include "gl_enums.h"
typedef unsigned char       GLboolean;
typedef unsigned int        GLbitfield;
typedef signed char         GLbyte;
typedef short               GLshort;
typedef int                 GLint;
typedef int                 GLsizei;
typedef unsigned char       GLubyte;
typedef unsigned short      GLushort;
typedef unsigned int        GLuint;
typedef float               GLfloat;
typedef float               GLclampf;
typedef double              GLdouble;
typedef double              GLclampd;
typedef void                GLvoid;

/* Forward declarations */
struct __GLcontextRec;
typedef struct __GLcontextRec __GLcontext;
struct __GLattributeRec;
typedef struct __GLattributeRec __GLattribute;

/* Basic geometric structures */
typedef struct __GLcoordRec {
    GLfloat x, y, z, w;
} __GLcoord;

typedef struct __GLcolorRec {
    GLfloat r, g, b, a;
} __GLcolor;

struct __GLmatrixRec;
typedef struct __GLmatrixRec __GLmatrix;

struct __GLmatrixRec {
    GLfloat matrix[4][4];
    GLenum  matrixType;
    GLshort width, height;
    void (*xf2)(__GLcoord *res, const GLfloat *v, const __GLmatrix *m);
    void (*xf3)(__GLcoord *res, const GLfloat *v, const __GLmatrix *m);
    void (*xf4)(__GLcoord *res, const GLfloat *v, const __GLmatrix *m);
    char pad[4];
};

typedef struct __GLtransformRec {
    __GLmatrix matrix;
    __GLmatrix inverseTranspose;
    __GLmatrix mvp;
    GLuint sequence;
    GLboolean updateInverse;
    char pad[3];
    GLfloat rescaleFactor;
} __GLtransform;

typedef struct __GLvertexRec {
    GLuint                   flagBits;
    GLuint                   pad4;
    void                     (*validate)(struct __GLcontextRec *gc, struct __GLvertexRec *v);
    GLuint                   pad0C;
    __GLcoord                obj;
    __GLcoord                normal;
    __GLcoord                texture[1];
    char                     pad40[0x20];
    __GLcoord                eye;
    __GLcoord                clip;
    __GLcoord                window;
    __GLcolor                colors[2];
    char                     padB0[0x10];
} __GLvertex;

typedef struct __GLimportsRec {
    void *(*malloc)(__GLcontext *gc, size_t size);
    void *(*calloc)(__GLcontext *gc, size_t numElem, size_t elemSize);
    void *(*realloc)(__GLcontext *gc, void *oldAddr, size_t newSize);
    void (*free)(__GLcontext *gc, void *addr);
    void (*warning)(__GLcontext *gc, char *fmt);
    void (*fatal)(__GLcontext *gc, char *fmt);
    char *(*getenv)(__GLcontext *gc, const char *var);
    int (*atoi)(__GLcontext *gc, const char *str);
    int (*sprintf)(__GLcontext *gc, char *str, const char *fmt, ...);
    void *(*fopen)(__GLcontext *gc, const char *path, const char *mode);
    int (*fclose)(__GLcontext *gc, void *stream);
    int (*fprintf)(__GLcontext *gc, void *stream, const char *fmt, ...);
    void *(*getDrawablePrivate)(__GLcontext *gc);
    void *wscx;
    void *other;
    char pad[16];
} __GLimports;

typedef struct __GLexportsRec {
    GLboolean (*destroyContext)(__GLcontext *gc);
    GLboolean (*loseCurrent)(__GLcontext *gc);
    GLboolean (*makeCurrent)(__GLcontext *gc);
    GLboolean (*shareContext)(__GLcontext *gc, __GLcontext *gcShare);
    GLboolean (*copyContext)(__GLcontext *dst, const __GLcontext *src, GLuint mask);
    GLboolean (*forceCurrent)(__GLcontext *gc);
    GLboolean (*notifyResize)(__GLcontext *gc);
    void (*notifyDestroy)(__GLcontext *gc);
    void (*notifySwapBuffers)(__GLcontext *gc);
    void *(*dispatchExec)(__GLcontext *gc);
    void (*beginDispatchOverride)(__GLcontext *gc);
    void (*endDispatchOverride)(__GLcontext *gc);
    char pad[24];
} __GLexports;

typedef struct __GLcontextModesRec {
    GLint       visualID;
    GLboolean   rgbMode;
    GLboolean   colorIndexMode;
    GLboolean   doubleBufferMode;
    GLboolean   stereoMode;
    GLboolean   haveAccumBuffer;
    GLboolean   haveDepthBuffer;
    GLboolean   haveStencilBuffer;
    GLboolean   pad0;
    GLint       accumRedBits;
    GLint       accumGreenBits;
    GLint       accumBlueBits;
    GLint       accumAlphaBits;
    GLint       depthBits;
    GLint       stencilBits;
    GLint       indexBits;
    GLint       redBits;
    GLint       greenBits;
    GLint       blueBits;
    GLint       alphaBits;
    GLuint      redMask;
    GLuint      greenMask;
    GLuint      blueMask;
    GLuint      alphaMask;
    GLint       rgbBits;
    GLint       level;
    GLint       numAuxBuffers;
    GLint       maxAuxBuffers;
} __GLcontextModes;

typedef struct __GLbufferRec {
    __GLcontext         *gc;
    void                *drawableBuf;
    void                *other;
    void                (*resize)();
    void                (*makeCurrent)();
    void                (*loseCurrent)();
    void                (*free)();
} __GLbuffer;

typedef struct __GLcolorBufferRec __GLcolorBuffer;
struct __GLcolorBufferRec {
    __GLbuffer          buf;
    GLint               redMax, greenMax, blueMax;
    GLboolean           needColorFragmentOps;
    char                pad29[3];
    GLubyte             *alphaTestFuncTable;
    GLfloat             redScale, greenScale, blueScale;
    GLint               iRedScale, iGreenScale, iBlueScale;
    GLint               redShift, greenShift, blueShift, alphaShift;
    GLfloat             alphaScale;
    GLint               iAlphaScale;
    GLfloat             oneOverRedScale, oneOverGreenScale, oneOverBlueScale, oneOverAlphaScale;
    GLuint              sourceMask, destMask;
    void                (*pick)();
    GLint               (*getDisplayMasks)();
    void                (*store)();
    void                (*fetch)();
    void                (*readColor)();
    GLboolean           (*readSpan)();
    void                (*returnSpan)();
    void                *storeSpan;
    void                *storeStippledSpan;
    void                *storeLine;
    void                *storeStippledLine;
    void                *fetchSpan;
    void                *fetchStippledSpan;
    void                *fetchLine;
    void                *fetchStippledLine;
    char                padB4[36];
    void                (*clear)(__GLcolorBuffer *cfb);
};

typedef struct __GLstencilBufferRec {
    __GLbuffer          buf;
    char                pad1C[88];
    void                (*clear)(struct __GLstencilBufferRec *sfb, s64 mask, __GLcontext *gc);
} __GLstencilBuffer;

typedef struct __GLdepthBufferRec {
    __GLbuffer          buf;
    char                pad1C[48];
    GLuint              scale;
    char                pad50[40];
    void                (*clear)(struct __GLdepthBufferRec *dfb, s64 mask, __GLcontext *gc);
    char                pad7C[8];
} __GLdepthBuffer;

typedef struct __GLaccumBufferRec {
    __GLbuffer          buf;
    char                pad1C[80];
    void                (*clear)(struct __GLaccumBufferRec *afb);
} __GLaccumBuffer;

typedef struct __GLprocsRec {
    void (*validate)(__GLcontext *gc);
    void (*finish)(__GLcontext *gc);
    void (*flush)(__GLcontext *gc);
    void (*applyColor)(__GLcontext *gc);
    void *table[128];
    char pad[324];
} __GLprocs;

/* Base OpenGL Context structure (__GLcontextRec) */
struct __GLcontextRec {
    __GLimports             imports;            /* 0x0000 - 0x004B (76 bytes) */
    __GLexports             exports;            /* 0x004C - 0x0093 (72 bytes) */
    GLint                   gcState;            /* 0x0094 - 0x0097 (4 bytes) */
    char                    pad_state[2936];    /* 0x0098 - 0x0C0F (Attributes) */
    u32                     beginMode;          /* 0x0C10 - 0x0C13 (4 bytes) */
    GLenum                  renderMode;         /* 0x0C14 - 0x0C17 (4 bytes) */
    GLint                   error;              /* 0x0C18 - 0x0C1B (4 bytes) */
    __GLcontextModes        modes;              /* 0x0C1C - 0x0C73 (88 bytes) */
    __GLcontextModes        readModes;          /* 0x0C74 - 0x0CCB (88 bytes) */
    GLboolean               yInverted;          /* 0x0CCC (1 byte) */
    char                    pad_yinv[3];        /* 0x0CCD - 0x0CCF (3 bytes) */
    char                    pad_const[8380];    /* 0x0CD0 - 0x2DEF */
    GLuint                  validateMask;       /* 0x2DF0 (11760) */
    GLuint                  dirtyMask;          /* 0x2DF4 (11764) */
    __GLcolorBuffer         *drawBuffer;        /* 0x2DF8 (11768) */
    __GLcolorBuffer         *readBuffer;        /* 0x2DFC (11772) */
    char                    pad_proc[16];       /* 0x2E00 - 0x2E0F */
    void                    (*validate)(__GLcontext *gc); /* 0x2E10 (11792) */
    char                    pad_proc2[28];      /* 0x2E14 - 0x2E2F */
    __GLprocs               procs;              /* 0x2E30 (11824) */
    char                    pad_mid[19060];     /* 0x3184 - 0x77C3 */
    __GLcolorBuffer         *front;             /* 0x77C4 (30660) */
    __GLcolorBuffer         *back;              /* 0x77C8 (30664) */
    __GLcolorBuffer         frontBuffer;        /* 0x77CC (30668, 220 bytes) */
    __GLcolorBuffer         backBuffer;         /* 0x78A8 (30888, 220 bytes) */
    __GLcolorBuffer         *auxBuffer;         /* 0x7984 (31108) */
    __GLstencilBuffer       stencilBuffer;      /* 0x7988 (31112, 120 bytes) */
    __GLdepthBuffer         depthBuffer;        /* 0x7A00 (31232, 132 bytes) */
    __GLaccumBuffer         accumBuffer;        /* 0x7A84 (31364, 112 bytes) */
    char                    pad_bufend[28];     /* 0x7AF4 - 0x7B0F (28 bytes) */
    GLint                   fd;                 /* 0x7B10 (graphics device fd) */
    GLint                   boardIndex;         /* 0x7B14 (board index) */
    GLint                   zDepth;             /* 0x7B18 (bits of Z: 24) */
    GLint                   stencilDepth;       /* 0x7B1C (bits of stencil: 4) */
    char                    rendererString[40]; /* 0x7B20 - 0x7B47 (40 bytes) */
    GLuint                  swapInterval;       /* 0x7B48 (buffer swap interval) */
    u8                      hwFlags;            /* 0x7B4C */
    u8                      haveZ;              /* 0x7B4D */
    u8                      haveStencil;        /* 0x7B4E */
    u8                      fastMode;           /* 0x7B4F */
    void                    (*primitiveProcs[10])(__GLcontext *gc); /* 0x7B50 - 0x7B77 */
};

extern __GLcontext *__glCurrentContext;
extern u32 __glBeginMode;
void __glSetError(GLenum code);

#endif /* __GLCORE_TYPES_H__ */
""")

    # 3. libglcore/include/glcore_prots.h
    prots_path = f"{OUT_DIR}/include/glcore_prots.h"
    with open(prots_path, 'w') as f:
        f.write("#ifndef __GLCORE_PROTS_H__\n#define __GLCORE_PROTS_H__\n\n")
        f.write("/* Standard libc & system functions */\n")
        f.write("int ioctl(int fd, unsigned long request, ...);\n")
        f.write("int printf(const char *format, ...);\n")
        f.write("void *malloc(u32 size);\n")
        f.write("void free(void *ptr);\n")
        f.write("void *memcpy(void *dest, const void *src, u32 n);\n")
        f.write("void *memset(void *s, int c, u32 n);\n")
        f.write("void bzero(void *s, u32 n);\n")
        f.write("f32 sqrtf(f32 x);\n")
        f.write("f32 fabsf(f32 x);\n")
        f.write("f32 floorf(f32 x);\n")
        f.write("f32 ceilf(f32 x);\n")
        f.write("f32 cosf(f32 x);\n")
        f.write("f32 sinf(f32 x);\n\n")

        f.write("/* DWARF-extracted function prototypes */\n")
        seen = set()
        for func in all_funcs:
            fname = func['name']
            if fname in seen:
                continue
            seen.add(fname)

            mapped = False
            for prefix in ['__glMgrim_', '__glMgrlc_', '__glim_', '__glce_', '__glMgras', 'gl', 'mgras_']:
                if fname.startswith(prefix):
                    base_api = fname[len(prefix):]
                    if base_api in gl_api:
                        ret, params = gl_api[base_api]
                        f.write(f"{ret} {fname}({params});\n")
                        mapped = True
                        break

            if not mapped:
                if fname.startswith('__glMgr') or fname.startswith('so_') or fname.startswith('mgras_'):
                    f.write(f"void {fname}(__GLcontext *gc, ...);\n")
                else:
                    f.write(f"void {fname}();\n")

        f.write("\n#endif /* __GLCORE_PROTS_H__ */\n")

    # 4. ctx_libglcore_source.h
    ctx_src_path = f"{OUT_DIR}/ctx_libglcore_source.h"
    with open(ctx_src_path, "w") as f:
        f.write("""/*
 * ctx_libglcore_source.h
 * Master context source for m2c decompiler on libGLcore.so.
 */
#define _LANGUAGE_C
#include "include/glcore_types.h"
#include "include/glcore_mgras.h"
#include "include/glcore_prots.h"
""")

    # 5. Compile ctx_libglcore.c
    ctx_c_path = f"{OUT_DIR}/ctx_libglcore.c"
    print(f"[*] Preprocessing {ctx_src_path} -> {ctx_c_path}...")
    cmd = ['gcc', '-std=c99', '-E', '-P', '-D_LANGUAGE_C', '-I.', f'-I{OUT_DIR}', ctx_src_path, '-o', ctx_c_path]
    subprocess.run(cmd, check=True)
    print(f"[+] Successfully generated {ctx_c_path} for m2c.")

def generate_runner_script():
    script_path = f"{OUT_DIR}/decompile_libglcore.sh"
    with open(script_path, "w") as f:
        f.write(r"""#!/usr/bin/env bash
# decompile_libglcore.sh
# Runs m2c decompiler on libGLcore.so functions and modules using ctx_libglcore.c in N32 mode.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

M2C="python3 ${ROOT_DIR}/m2c/m2c.py -t mipsn32 --context ${SCRIPT_DIR}/ctx_libglcore.c"

if [ $# -eq 0 ]; then
    echo "Usage:"
    echo "  $0 <module_name>       (e.g., $0 mgras_context or $0 mgras_modes)"
    echo "  $0 <category>          (e.g., $0 MGRAS)"
    echo "  $0 --func <func_name>  (e.g., $0 --func __glMgrCreateContext)"
    echo "  $0 all                 (decompile all MGRAS hardware modules)"
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

if [ "$1" == "all" ] || [ "$1" == "MGRAS" ]; then
    echo "[*] Decompiling MGRAS hardware modules..."
    for f in "${SCRIPT_DIR}"/asm/MGRAS/*.s; do
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
    setup_dirs()
    got_map = build_got_map(TARGET_ELF)
    print(f"[*] Loaded {len(got_map)} entries from GOT.")
    lit4_map, lit8_map = build_lit_maps(TARGET_ELF)
    print(f"[*] Loaded {len(lit4_map)} .lit4 and {len(lit8_map)} .lit8 constants.")
    text_addr, text_size, cus, all_funcs = parse_dwarf(TARGET_ELF)
    jtbl_map = build_jtbl_map(TARGET_ELF, all_funcs)
    print(f"[*] Loaded {len(jtbl_map)} jump tables.")
    disasm_map = get_disassembly()

    print("[*] Writing per-CU assembly files...")
    for cu in cus:
        if cu['funcs']:
            write_cu_assembly(cu, disasm_map, got_map, lit4_map, lit8_map, jtbl_map)

    print("[*] Writing libglcore/manifest.json...")
    manifest = {
        'target_elf': TARGET_ELF,
        'text_addr': hex(text_addr),
        'text_size': text_size,
        'total_cus': len(cus),
        'total_funcs': len(all_funcs),
        'categories': {
            cat: sum(1 for c in cus if c['category'] == cat)
            for cat in CATEGORIES
        },
        'cus': [
            {
                'index': c['index'],
                'name': c['name'],
                'basename': c['basename'],
                'category': c['category'],
                'num_funcs': len(c['funcs']),
                'asm_file': c.get('asm_file', ''),
                'decomp_file': c.get('decomp_file', ''),
                'producer': c['producer'],
                'funcs': c['funcs'],
                'variables': c['variables']
            }
            for c in cus
        ]
    }

    with open(f'{OUT_DIR}/manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Wrote manifest with {len(cus)} CUs and {len(all_funcs)} functions.")

    generate_context_headers(all_funcs)
    generate_runner_script()
    print("\n[SUCCESS] Extraction, context generation, and runner setup complete!")

if __name__ == '__main__':
    main()
