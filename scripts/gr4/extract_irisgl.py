#!/usr/bin/env python3
"""
scripts/extract_irisgl.py

Extracts all DWARF metadata, functions, line tables, and disassembly from
irisgl/libgl.so (MIPS-III N32 IrisGL / Igloo translation layer for SGI Impact / GR4).

Organizes code into original .c compilation units across 10 categories:
  - igloo     (core translation engine: ../igloo/*.c, ext/*.c, undef/*.c, etc.)
  - graphics  (core drawing: ../igloo/graphics/*.c - clear, polygon, movedraw, etc.)
  - glws      (window system / GLX: ../igloo/glws/*.c - window, context, modes, etc.)
  - texture   (texture mapping: ../igloo/texture/*.c - texdef, texbind, etc.)
  - light     (lighting & materials: ../igloo/light/*.c - lmdef, lmbind, etc.)
  - curve     (curves & NURBS: ../igloo/curve/*.c - curve, patch, etc.)
  - xform     (matrix math & transforms: ../igloo/xform/*.c - viewport, rotate, etc.)
  - object    (display lists: ../object/*.c - object, makeroom, interp, etc.)
  - dgl       (distributed GL / network: ../dgl/*.c, dglcmds.c)
  - stubs     (API stubs: gl_if.s - 547 entry points)

Generates:
  1. irisgl/manifest.json (complete machine-readable database)
  2. irisgl/asm/<category>/<cu>.s (per-CU assembly with labels & line numbers)
  3. irisgl/include/igloo_types.h & igloo.h (IrisGL types, constants, state structures)
  4. irisgl/include/igloo_prots.h (prototypes for all functions)
  5. irisgl/ctx_source.h & irisgl/ctx.c (preprocessed context for m2c)
  6. irisgl/decompile_irisgl.sh (decompilation runner script)
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

TARGET_ELF = 'irisgl/libgl.so'
OUT_DIR = 'irisgl'

CATEGORIES = [
    'igloo',
    'graphics',
    'glws',
    'texture',
    'light',
    'curve',
    'xform',
    'object',
    'dgl',
    'stubs'
]

def setup_dirs():
    os.makedirs(f'{OUT_DIR}/asm', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/decomp', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/include', exist_ok=True)
    for cat in CATEGORIES:
        os.makedirs(f'{OUT_DIR}/asm/{cat}', exist_ok=True)
        os.makedirs(f'{OUT_DIR}/decomp/{cat}', exist_ok=True)

def categorize_cu(name):
    if 'gl_if.s' in name:
        return 'stubs'
    elif '/graphics/' in name:
        return 'graphics'
    elif '/glws/' in name:
        return 'glws'
    elif '/texture/' in name:
        return 'texture'
    elif '/light/' in name:
        return 'light'
    elif '/curve/' in name:
        return 'curve'
    elif '/xform/' in name:
        return 'xform'
    elif '/object/' in name:
        return 'object'
    elif '/dgl/' in name or 'dglcmds' in name:
        return 'dgl'
    else:
        return 'igloo'

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
    print("[*] Disassembling .text using mips-unknown-linux-gnu-objdump -d -z...")
    cmd = ['mips-unknown-linux-gnu-objdump', '-d', '-z', '--no-show-raw-insn', TARGET_ELF]
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
    # Normalize bgezall zero, <target> -> bal <target>
    instr = re.sub(r'\bbgezall\s+(?:\$?zero|\$0),\s*', 'bal\t', instr)

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

def build_lit_maps(elf_path, gp_val=0x0f033248):
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

def build_jtbl_map(elf_path, all_funcs, disasm_map):
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

    sorted_addrs = sorted(disasm_map.keys())
    lines = [disasm_map[a] for a in sorted_addrs]

    jtbl_addrs = {}
    for i, line in enumerate(lines):
        m_lw = re.search(r'lw\s+(\w+),\s*-32680\(gp\)', line)
        if m_lw:
            reg = m_lw.group(1)
            for j in range(i + 1, min(len(lines), i + 6)):
                m_add = re.search(rf'addiu\s+{reg},\s*{reg},\s*(-?\d+)', lines[j])
                if m_add:
                    off = int(m_add.group(1))
                    addr = 0x0f020000 + off
                    if rbase <= addr <= rbase + rsize - 4:
                        val = struct.unpack('>I', rdata[addr - rbase:addr - rbase + 4])[0]
                        if tbase <= val < tbase + tsize:
                            fn = get_func_for_pc(val)
                            if fn:
                                jtbl_addrs[addr] = fn
                    break

    sorted_tbl_addrs = sorted(jtbl_addrs.keys())
    tables = {}
    for idx, s_addr in enumerate(sorted_tbl_addrs):
        fn_name = jtbl_addrs[s_addr]
        next_s = sorted_tbl_addrs[idx + 1] if idx + 1 < len(sorted_tbl_addrs) else rbase + rsize
        entries = []
        curr = s_addr
        while curr < next_s and curr <= rbase + rsize - 4:
            val = struct.unpack('>I', rdata[curr - rbase:curr - rbase + 4])[0]
            if tbase <= val < tbase + tsize and get_func_for_pc(val) == fn_name:
                entries.append(val)
                curr += 4
            else:
                break
        tables[s_addr] = {'fn_name': fn_name, 'entries': entries}

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

            # GOT and register cleanup
            def is_branch(raw_str):
                s = raw_str.strip()
                if not s or s.startswith('#'):
                    return False
                op = s.split()[0]
                return op.startswith(('b', 'j'))

            t9_target = None
            gp_reg_pattern = r'gp|\$gp|\$28'
            for idx, item in enumerate(func_items):
                raw_instr = item['raw']

                m_gp_setup = re.search(rf'addu\s+[$]?gp,\s*[$]?(?:t9|ra),\s*[$]?(?:at|v0|v1)', raw_instr)
                if m_gp_setup:
                    in_delay = (idx > 0 and is_branch(func_items[idx-1]['raw']))
                    if in_delay:
                        item['raw'] = f"nop\t# was {raw_instr} (gp setup in delay)"
                    else:
                        item['is_comment'] = True
                        item['raw'] = f"# {raw_instr} (gp setup)"
                    if idx > 0 and 'lui' in func_items[idx-1]['raw'] and not in_delay:
                        func_items[idx-1]['is_comment'] = True
                        func_items[idx-1]['raw'] = f"# {func_items[idx-1]['raw']} (gp disp hi)"
                    if idx > 1 and 'addiu' in func_items[idx-1]['raw'] and 'lui' in func_items[idx-2]['raw'] and not in_delay:
                        func_items[idx-1]['is_comment'] = True
                        func_items[idx-1]['raw'] = f"# {func_items[idx-1]['raw']} (gp disp lo)"
                        func_items[idx-2]['is_comment'] = True
                        func_items[idx-2]['raw'] = f"# {func_items[idx-2]['raw']} (gp disp hi)"
                    continue

                m_lw = re.search(r'lw\s+([$]?\w+),\s*(-?\d+)\([$]?(' + gp_reg_pattern + r')\)', raw_instr)
                if m_lw:
                    dest_reg = m_lw.group(1)
                    off = int(m_lw.group(2))
                    if off in got_map:
                        sym = got_map[off]
                        item['raw'] = f"la\t{dest_reg},{sym}"
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
                                continue
                    item['raw'] = "jalr\t$t9\n    nop\n    jr\t$ra"
                    continue

            # Jump tables
            for t_addr, t_info in fn_jtbls.items():
                off = t_addr - 0x0f020000
                jtbl_sym = f"jtbl_{t_addr:08x}"
                for idx, item in enumerate(func_items):
                    raw = item['raw']
                    m_addiu = re.search(rf'addiu\s+([$]?\w+),\s*[$]?\w+,\s*{off}\b', raw)
                    if m_addiu:
                        reg = m_addiu.group(1)
                        item['raw'] = f"la\t{reg},{jtbl_sym}"
                        for b_idx in range(idx - 1, max(-1, idx - 4), -1):
                            b_raw = func_items[b_idx]['raw']
                            if 'sub_0f020000' in b_raw and reg in b_raw:
                                in_delay = (b_idx > 0 and is_branch(func_items[b_idx-1]['raw']))
                                if in_delay:
                                    func_items[b_idx]['raw'] = f"nop\t# was {b_raw}"
                                else:
                                    func_items[b_idx]['raw'] = f"# {b_raw}"
                                    func_items[b_idx]['is_comment'] = True
                                break

            # Emit instructions with labels and line comments
            current_line = None
            for item in func_items:
                addr = item['addr']
                line = item['line']
                raw = item['raw']

                if addr in branch_targets:
                    f.write(f".L{addr:08x}:\n")

                if line and line != current_line:
                    f.write(f"    # Line {line}\n")
                    current_line = line

                if not item.get('is_comment'):
                    m = re.search(r'\b([0-9a-fA-F]{7,8})\s*<([^>]+)>', raw)
                    if m:
                        target_addr = int(m.group(1), 16)
                        target_sym = m.group(2).split('+')[0]
                        if low <= target_addr < high:
                            raw = raw[:m.start()] + f".L{target_addr:08x}"
                        else:
                            raw = raw[:m.start()] + target_sym

                    raw = re.sub(r'\bbgezall?\s+(?:\$?zero|\$0)\s*,\s*', 'bal ', raw)
                    formatted = format_instruction(addr, raw)
                    f.write(f"    {formatted}\n")
                else:
                    f.write(f"    {raw}\n")

            f.write(f".end {fname}\n\n")

        # Emit jump tables
        if cu_jtbls:
            f.write(".late_rodata\n")
            for t_addr, t_info in sorted(cu_jtbls.items()):
                f.write(f"jtbl_{t_addr:08x}:\n")
                for target in t_info['entries']:
                    f.write(f"    .word .L{target:08x}\n")
            f.write("\n")

        # Emit float literals
        if cu_lits:
            f.write(".rdata\n")
            for lit_sym, (size, uval) in sorted(cu_lits.items()):
                f.write(f"{lit_sym}:\n")
                if size == 4:
                    f.write(f"    .word 0x{uval:08x}\n")
                else:
                    f.write(f"    .word 0x{uval >> 32:08x}, 0x{uval & 0xffffffff:08x}\n")
            f.write("\n")

def generate_context_headers(all_funcs):
    print("[*] Generating IrisGL context headers...")

    # 1. irisgl/include/igloo_types.h
    types_path = f"{OUT_DIR}/include/igloo_types.h"
    with open(types_path, 'w') as f:
        f.write("""#ifndef __IGLOO_TYPES_H__
#define __IGLOO_TYPES_H__

/* Standard integer types */
typedef signed char         s8;
typedef unsigned char       u8;
typedef short               s16;
typedef unsigned short      u16;
typedef int                 s32;
typedef unsigned int        u32;
typedef long long           s64;
typedef unsigned long long  u64;
typedef float               f32;
typedef double              f64;

/* Authentic IrisGL Primitive Types */
typedef char                Boolean;
typedef short               Colorindex;
typedef unsigned long       RGBvalue;
typedef float               Coord;
typedef long                Icoord;
typedef short               Scoord;
typedef short               Screencoord;
typedef float               Matrix[4][4];
typedef unsigned short      Angle;
typedef long                Object;
typedef long                Tag;
typedef unsigned short      Pattern[16];
typedef unsigned short      Linestyle;
typedef unsigned long       Device;

/* X11 & GLX Stub Types */
typedef void *              Display;
typedef unsigned long       Window;
typedef unsigned long       Colormap;
typedef unsigned long       VisualID;
typedef unsigned long       Pixmap;
typedef void *              Visual;
typedef void *              GLXContext;
typedef unsigned long       GLXDrawable;

typedef struct {
    Visual *visual;
    VisualID visualid;
    int screen;
    int depth;
    int class;
    unsigned long red_mask;
    unsigned long green_mask;
    unsigned long blue_mask;
    int colormap_size;
    int bits_per_rgb;
} XVisualInfo;

/* OpenGL Standard Types */
typedef unsigned int        GLenum;
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

#endif /* __IGLOO_TYPES_H__ */
""")

    # 2. irisgl/include/igloo.h
    igloo_path = f"{OUT_DIR}/include/igloo.h"
    with open(igloo_path, 'w') as f:
        f.write("""#ifndef __IGLOO_H__
#define __IGLOO_H__

#include "igloo_types.h"

/*
 * ============================================================================
 * IRISGL / IGLOO CONSTANTS & TOKENS
 * ============================================================================
 */

/* Standard Colors */
#define BLACK               0
#define RED                 1
#define GREEN               2
#define YELLOW              3
#define BLUE                4
#define MAGENTA             5
#define CYAN                6
#define WHITE               7

/* Display Modes */
#define NORMALDRAW          0
#define PUPDRAW             1
#define OVERDRAW            2
#define UNDERDRAW           3
#define CURSORDRAW          4

/* Buffering Modes */
#define SINGLEBUFFER        0
#define DOUBLEBUFFER        1

/* Color Modes */
#define CMAPMODE            0
#define RGBMODE             1

/* Matrix Modes */
#define MSINGLE             0
#define MPROJECTION         1
#define MVIEWING            2
#define MTEXTURE            3

/* Shading Modes */
#define FLAT                0
#define GOURAUD             1

/* Z-Buffer Comparison Functions */
#define ZF_NEVER            0
#define ZF_LESS             1
#define ZF_EQUAL            2
#define ZF_LEQUAL           3
#define ZF_GREATER          4
#define ZF_NOTEQUAL         5
#define ZF_GEQUAL           6
#define ZF_ALWAYS           7

/* Blend Functions */
#define BF_ZERO             0
#define BF_ONE              1
#define BF_DC               2
#define BF_MDC              3
#define BF_SA               4
#define BF_MSA              5
#define BF_DA               6
#define BF_MDA              7
#define BF_MIN_CA           8
#define BF_MIN_SA_MDA       9
#define BF_SC               10
#define BF_MSC              11

/* Logic Ops */
#define LO_ZERO             0
#define LO_AND              1
#define LO_ANDR             2
#define LO_SRC              3
#define LO_ANDI             4
#define LO_NOP              5
#define LO_XOR              6
#define LO_OR               7
#define LO_NOR              8
#define LO_XNOR             9
#define LO_INVERT           10
#define LO_ORR              11
#define LO_NSRC             12
#define LO_ORI              13
#define LO_NAND             14
#define LO_ONE              15

/* Lighting & Material */
#define LMNULL              0.0f
#define DEFMATERIAL         0
#define DEFLIGHT            1
#define DEFLMODEL           2
#define LCOLOR              0x1001
#define MATERIAL            0x1002
#define BACKMATERIAL        0x1003

/* Device Query Tokens (getgdesc) */
#define GD_XPMAX            0
#define GD_YPMAX            1
#define GD_XMMAX            2
#define GD_YMMAX            3
#define GD_ZMIN             4
#define GD_ZMAX             5
#define GD_BITS_NORM_SNG_RGB 6
#define GD_BITS_NORM_DBL_RGB 7
#define GD_BITS_NORM_SNG_CMODE 8
#define GD_BITS_NORM_DBL_CMODE 9
#define GD_BITS_OVERLAY     10
#define GD_BITS_UNDERLAY    11
#define GD_BITS_PUP         12
#define GD_BITS_ZBUFFER     13
#define GD_BITS_STENCIL     14

/* SGI Internal Igloo SGIX Tokens (passed to libGL / MGRAS) */
#define IGLOO_FULLSCREEN_SGIX       0x819E
#define IGLOO_VIEWPORT_OFFSET_SGIX  0x819F
#define IGLOO_SWAPTMESH_SGIX        0x81A0
#define IGLOO_COLORNORMAL_SGIX      0x81A1
#define IGLOO_IRISGL_MODE_SGIX      0x81A2
#define IGLOO_LMC_COLOR_SGIX        0x81A3
#define IGLOO_TMESHMODE_SGIX        0x81A4

/*
 * ============================================================================
 * IGLOO INTERNAL STATE STRUCTURES
 * ============================================================================
 */

/* Matrix Stack */
typedef struct {
    int         depth;
    int         max_depth;
    Matrix      stack[32];
} IglooMatrixStack;

/* Window State (gl_wstate) - Total size 12,160 bytes (0x2F80) */
typedef struct __gl_wstateRec {
    struct __gl_wstateRec *next;        /* 0x0000: Next context */
    u32                 flags;          /* 0x0004: State flags */
    GLint               drawMode;       /* 0x0008: NORMALDRAW, PUPDRAW, etc. */
    GLint               colorMode;      /* 0x000C: CMAPMODE or RGBMODE */
    GLint               bufferMode;     /* 0x0010: SINGLEBUFFER or DOUBLEBUFFER */
    GLint               shadingModel;   /* 0x0014: FLAT or GOURAUD */
    GLint               zbuffer;        /* 0x0018: Z-buffer enabled flag */
    GLint               zfunction;      /* 0x001C: ZF_LEQUAL, etc. */
    GLint               blendSrc;       /* 0x0020: Blend source */
    GLint               blendDst;       /* 0x0024: Blend destination */
    Colorindex          currentColor;   /* 0x0028: Current CI */
    RGBvalue            currentRGB;     /* 0x002C: Current RGB */
    f32                 currentNormal[3];/* 0x0030: Normal x, y, z */
    char                pad_header[164];/* 0x003C - 0x00DF */
    u32                 active;         /* 0x00E0: Context active / bound */
    u32                 valid;          /* 0x00E4: Context valid flag (1) */
    char                pad_win[4];     /* 0x00E8 */
    Window              xwindow;        /* 0x00EC: X11 Window ID */
    GLXContext          glxcx;          /* 0x00F0: GLX Context */
    Display             *display;       /* 0x00F4: X11 Display */
    u32                 screen;         /* 0x00F8: Screen number */
    void                *screenState;   /* 0x00FC: Pointer to gl_sstate */
    char                pad_mid[2624];  /* 0x0100 - 0x0B3F */
    IglooMatrixStack    modelviewStack; /* Modelview matrix stack */
    IglooMatrixStack    projStack;      /* Projection matrix stack */
    char                pad_matrices[4000];
    Coord               currentVertex[4];/* 0x2CD4 - 0x2CE4: Current vertex */
    char                pad_tail[1000];
} gl_wstate;

/* Shared / Screen State (gl_sstate) */
typedef struct __gl_sstateRec {
    Display             *display;       /* 0x0000: X Display */
    int                 screen;         /* 0x0004: Screen index */
    Window              root;           /* 0x0008: Root window */
    Colormap            colormap;       /* 0x000C: Colormap */
    Visual              *visual;        /* 0x0010: Visual */
    char                pad[252];       /* 0x0014 - 0x010F */
    s32                 graphicsType;   /* 0x0110: Hardware type (2=GR2, 4=MGRAS, etc.) */
} gl_sstate;

/* Global state pointers defined in libgl.so */
extern gl_wstate *gl_wstatep;
extern gl_sstate *gl_sstatep;
extern s32 gl_inMoveDraw;
extern s32 gl_iglooGouraudCIDepthCue;
extern s32 gl_iglooUseTexObj;

#endif /* __IGLOO_H__ */
""")

    # 3. irisgl/include/igloo_prots.h
    prots_path = f"{OUT_DIR}/include/igloo_prots.h"
    with open(prots_path, 'w') as f:
        f.write("#ifndef __IGLOO_PROTS_H__\n#define __IGLOO_PROTS_H__\n\n")
        f.write("/* Standard libc & system functions */\n")
        f.write("int ioctl(int fd, unsigned long request, ...);\n")
        f.write("int printf(const char *format, ...);\n")
        f.write("char *getenv(const char *name);\n")
        f.write("void *malloc(u32 size);\n")
        f.write("void *calloc(u32 n, u32 size);\n")
        f.write("void free(void *ptr);\n")
        f.write("void *memcpy(void *dest, const void *src, u32 n);\n")
        f.write("void *memset(void *s, int c, u32 n);\n")
        f.write("void bzero(void *s, u32 n);\n")
        f.write("int uname(void *buf);\n")
        f.write("f32 sqrtf(f32 x);\n")
        f.write("f32 fabsf(f32 x);\n")
        f.write("f32 sinf(f32 x);\n")
        f.write("f32 cosf(f32 x);\n")
        f.write("f32 floorf(f32 x);\n")
        f.write("f32 ceilf(f32 x);\n\n")

        f.write("/* OpenGL functions called by Igloo */\n")
        f.write("void glBegin(GLenum mode);\n")
        f.write("void glEnd(void);\n")
        f.write("void glVertex2f(GLfloat x, GLfloat y);\n")
        f.write("void glVertex3f(GLfloat x, GLfloat y, GLfloat z);\n")
        f.write("void glVertex4f(GLfloat x, GLfloat y, GLfloat z, GLfloat w);\n")
        f.write("void glNormal3f(GLfloat nx, GLfloat ny, GLfloat nz);\n")
        f.write("void glColor3f(GLfloat r, GLfloat g, GLfloat b);\n")
        f.write("void glColor4f(GLfloat r, GLfloat g, GLfloat b, GLfloat a);\n")
        f.write("void glIndexi(GLint c);\n")
        f.write("void glTexCoord2f(GLfloat s, GLfloat t);\n")
        f.write("void glClear(GLbitfield mask);\n")
        f.write("void glClearColor(GLclampf red, GLclampf green, GLclampf blue, GLclampf alpha);\n")
        f.write("void glClearIndex(GLfloat c);\n")
        f.write("void glClearDepth(GLclampd depth);\n")
        f.write("void glEnable(GLenum cap);\n")
        f.write("void glDisable(GLenum cap);\n")
        f.write("void glFlush(void);\n")
        f.write("void glFinish(void);\n")
        f.write("void glPushMatrix(void);\n")
        f.write("void glPopMatrix(void);\n")
        f.write("void glLoadIdentity(void);\n")
        f.write("void glLoadMatrixf(const GLfloat *m);\n")
        f.write("void glMultMatrixf(const GLfloat *m);\n")
        f.write("void glMatrixMode(GLenum mode);\n")
        f.write("void glViewport(GLint x, GLint y, GLsizei width, GLsizei height);\n")
        f.write("void glBlendFunc(GLenum sfactor, GLenum dfactor);\n")
        f.write("void glDepthFunc(GLenum func);\n")
        f.write("void glShadeModel(GLenum mode);\n")
        f.write("void glCallList(GLuint list);\n")
        f.write("void glCallLists(GLsizei n, GLenum type, const GLvoid *lists);\n")
        f.write("void glClearStencil(GLint s);\n")
        f.write("void glRecti(GLint x1, GLint y1, GLint x2, GLint y2);\n")
        f.write("void glRectf(GLfloat x1, GLfloat y1, GLfloat x2, GLfloat y2);\n")
        f.write("void glRects(GLshort x1, GLshort y1, GLshort x2, GLshort y2);\n")
        f.write("void glScissor(GLint x, GLint y, GLsizei width, GLsizei height);\n")
        f.write("void glDrawBuffer(GLenum mode);\n")
        f.write("void glReadBuffer(GLenum mode);\n")
        f.write("void glPixelStorei(GLenum pname, GLint param);\n")
        f.write("void glIglooInterfaceSGIX(GLenum pname, void *param);\n\n")

        f.write("/* DWARF-extracted IrisGL / Igloo function prototypes */\n")
        seen = set()
        for func in all_funcs:
            fname = func['name']
            if fname in seen:
                continue
            seen.add(fname)
            if 'Get' in fname or 'get' in fname or fname.startswith('is') or fname.startswith('has') or 'Is' in fname:
                f.write(f"s32 {fname}();\n")
            elif 'alloc' in fname.lower() or 'malloc' in fname.lower() or 'calloc' in fname.lower() or 'context' in fname.lower():
                f.write(f"void *{fname}();\n")
            else:
                f.write(f"void {fname}();\n")

        f.write("\n#endif /* __IGLOO_PROTS_H__ */\n")

    # 4. irisgl/ctx_source.h
    ctx_src_path = f"{OUT_DIR}/ctx_source.h"
    with open(ctx_src_path, "w") as f:
        f.write("""/*
 * ctx_source.h
 * Master context source for m2c decompiler on irisgl/libgl.so.
 */
#define _LANGUAGE_C
#include "include/igloo_types.h"
#include "include/igloo.h"
#include "include/igloo_prots.h"
""")

    # 5. Compile irisgl/ctx.c
    ctx_c_path = f"{OUT_DIR}/ctx.c"
    print(f"[*] Preprocessing {ctx_src_path} -> {ctx_c_path}...")
    cmd = ['gcc', '-std=c99', '-E', '-P', '-D_LANGUAGE_C', '-I.', f'-I{OUT_DIR}', ctx_src_path, '-o', ctx_c_path]
    subprocess.run(cmd, check=True)
    print(f"[+] Successfully generated {ctx_c_path} for m2c.")

def generate_runner_script():
    script_path = f"{OUT_DIR}/decompile_irisgl.sh"
    with open(script_path, "w") as f:
        f.write("""#!/usr/bin/env bash
# irisgl/decompile_irisgl.sh
# Automated decompilation runner for SGI IrisGL (igloo) using m2c.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
M2C="python3 ${ROOT_DIR}/m2c/m2c.py --target mips-ido-c --context ${SCRIPT_DIR}/ctx.c"

CATEGORIES=(
    "igloo"
    "graphics"
    "glws"
    "texture"
    "light"
    "curve"
    "xform"
    "object"
    "dgl"
    "stubs"
)

if [ -z "$1" ]; then
    echo "Usage: $0 <category | module_name | all | --func <func_name>>"
    echo "Categories: ${CATEGORIES[*]}"
    exit 1
fi

decompile_file() {
    local asm_file="$1"
    local rel_path="${asm_file#$SCRIPT_DIR/asm/}"
    local out_c="$SCRIPT_DIR/decomp/${rel_path%.s}.c"
    local out_dir="$(dirname "$out_c")"
    mkdir -p "$out_dir"

    echo "[*] Decompiling $rel_path -> $out_c..."
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
    echo "[*] Decompiling all IrisGL / Igloo modules..."
    for cat in "${CATEGORIES[@]}"; do
        for f in "${SCRIPT_DIR}"/asm/"$cat"/*.s; do
            [ -f "$f" ] && decompile_file "$f"
        done
    done
    exit 0
fi

# Check if argument is a category
for cat in "${CATEGORIES[@]}"; do
    if [ "$1" == "$cat" ]; then
        echo "[*] Decompiling category $cat..."
        for f in "${SCRIPT_DIR}"/asm/"$cat"/*.s; do
            [ -f "$f" ] && decompile_file "$f"
        done
        exit 0
    fi
done

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
    disasm_map = get_disassembly()
    jtbl_map = build_jtbl_map(TARGET_ELF, all_funcs, disasm_map)
    print(f"[*] Loaded {len(jtbl_map)} jump tables.")

    print("[*] Writing per-CU assembly files...")
    for cu in cus:
        if cu['funcs']:
            write_cu_assembly(cu, disasm_map, got_map, lit4_map, lit8_map, jtbl_map)

    print("[*] Writing irisgl/manifest.json...")
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
