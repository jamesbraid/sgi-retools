#!/usr/bin/env python3
"""
scripts/disasm_kernel.py - Disassemble 64-bit MIPS-IV IRIX kernel objects for m2c.

Processes all objects in mgras_kernel/*.o:
  - Parses function entries and symbols
  - Extracts jump tables from .rodata / .srdata relocations and emits .rodata.s
  - Disassembles .text with mips-unknown-linux-gnu-objdump
  - Collects branch & jump table targets and generates .L<addr> labels
  - Formats instructions and registers with $ prefix for m2c parser
  - Emits m2c-compatible assembly in mgras_kernel/disasm/<mod>/<mod>.text.s
"""

import os
import sys
import re
import glob
import struct
import subprocess
from collections import defaultdict
from elftools.elf.elffile import ELFFile

REGS = [
    'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
    'a4', 'a5', 'a6', 'a7', 't0', 't1', 't2', 't3',
    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
    't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'fp', 'ra',
    'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',
    'f8', 'f9', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15',
    'f16', 'f17', 'f18', 'f19', 'f20', 'f21', 'f22', 'f23',
    'f24', 'f25', 'f26', 'f27', 'f28', 'f29', 'f30', 'f31'
]
REG_PATTERN = re.compile(r'(?<![\$\w])(' + '|'.join(REGS) + r')\b')

BRANCH_MNEMONICS = {
    'b', 'bal', 'beq', 'bne', 'beqz', 'bnez', 'bgez', 'bgezal',
    'bgtz', 'blez', 'bltz', 'bltzal', 'beql', 'bnel', 'beqzl',
    'bnezl', 'bgezl', 'bgtzl', 'blezl', 'bltzl', 'bc1t', 'bc1f',
    'bc1tl', 'bc1fl'
}

def format_registers(text):
    return REG_PATTERN.sub(r'$\1', text)

def extract_jump_tables(obj_path):
    """Find contiguous R_MIPS_64 relocations in .rodata / .srdata pointing to .text."""
    with open(obj_path, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        jtables = {}
        for sec in elf.iter_sections():
            if sec.name in ('.rel.rodata', '.rela.rodata', '.rel.srdata', '.rela.srdata'):
                target_sec_name = sec.name.replace('.rela', '').replace('.rel', '')
                target_sec = elf.get_section_by_name(target_sec_name)
                sec_data = target_sec.data() if target_sec else None
                if not sec_data:
                    continue
                relocs_by_offset = {}
                for rel in sec.iter_relocations():
                    rtype = rel['r_info_type']
                    if rtype == 18:  # R_MIPS_64
                        sym = symtab.get_symbol(rel['r_info_sym']) if symtab else None
                        if sym and sym.name == '.text':
                            offset = rel['r_offset']
                            val = struct.unpack_from('>Q', sec_data, offset)[0]
                            relocs_by_offset[offset] = val
                if relocs_by_offset:
                    sorted_offsets = sorted(relocs_by_offset.keys())
                    curr_base = sorted_offsets[0]
                    curr_list = []
                    prev_off = curr_base - 8
                    for off in sorted_offsets:
                        if off == prev_off + 8:
                            curr_list.append(relocs_by_offset[off])
                        else:
                            if len(curr_list) > 1:
                                jtables[curr_base] = curr_list
                            curr_base = off
                            curr_list = [relocs_by_offset[off]]
                        prev_off = off
                    if len(curr_list) > 1:
                        jtables[curr_base] = curr_list
        return jtables

def disassemble_module(obj_path, out_dir):
    mod_name = os.path.basename(obj_path).replace('.o', '')
    mod_out_dir = os.path.join(out_dir, mod_name)
    os.makedirs(mod_out_dir, exist_ok=True)
    out_s = os.path.join(mod_out_dir, f"{mod_name}.text.s")
    out_ro_s = os.path.join(mod_out_dir, f"{mod_name}.rodata.s")

    jtables = extract_jump_tables(obj_path)

    cmd = ['mips-unknown-linux-gnu-objdump', '-dr', '--no-show-raw-insn', obj_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[-] Failed to run objdump on {obj_path}: {res.stderr}")
        return

    lines = res.stdout.splitlines()

    # Pass 1: Collect function headers, instructions, relocations, and branch target addresses
    insn_re = re.compile(r'^\s*([0-9a-fA-F]+):\s+(\S+)(?:\s+(.*))?$')
    func_re = re.compile(r'^[0-9a-fA-F]+\s+<([^>]+)>:$')
    reloc_re = re.compile(r'^\s*([0-9a-fA-F]+):\s+R_MIPS_(\S+)\s+(\S+)')

    funcs = {}
    insns = []
    relocs = defaultdict(list)
    branch_targets = set()

    # Add all jump table targets to branch_targets
    for base_offset, targets in jtables.items():
        branch_targets.update(targets)

    for line in lines:
        m_func = func_re.match(line)
        if m_func:
            fn = m_func.group(1)
            funcs[len(insns)] = fn
            continue

        m_reloc = reloc_re.match(line)
        if m_reloc:
            addr = int(m_reloc.group(1), 16)
            rtype = m_reloc.group(2)
            sym = m_reloc.group(3)
            relocs[addr].append((rtype, sym))
            continue

        m_insn = insn_re.match(line)
        if m_insn:
            addr = int(m_insn.group(1), 16)
            mnemonic = m_insn.group(2)
            operands = m_insn.group(3) or ''
            
            # Check for branch target
            if mnemonic in BRANCH_MNEMONICS:
                tokens = [t.strip() for t in operands.split(',')]
                last_token = tokens[-1]
                # Match address like 1c8 or 1c8 <func+0x2c>
                m_target = re.match(r'^([0-9a-fA-F]+)(?:\s+<[^>]+>)?$', last_token)
                if m_target:
                    t_addr = int(m_target.group(1), 16)
                    branch_targets.add(t_addr)

            insns.append((addr, mnemonic, operands))

    if not insns:
        with open(out_s, 'w') as f:
            f.write(f"/* {mod_name} has no text section */\n")
        return

    # Pass 2: Generate formatted assembly
    out_lines = [
        '.section .text',
        '.set noat',
        '.set noreorder',
        ''
    ]

    for idx, (addr, mnemonic, operands) in enumerate(insns):
        # Insert function header if at function start
        if idx in funcs:
            fn_name = funcs[idx]
            out_lines.append('')
            out_lines.append(f'glabel {fn_name}')

        # Insert label if branch target
        if addr in branch_targets:
            out_lines.append(f'.L{addr:08x}:')

        # Format operands
        formatted_ops = operands
        if mnemonic in BRANCH_MNEMONICS:
            tokens = [t.strip() for t in operands.split(',')]
            m_target = re.match(r'^([0-9a-fA-F]+)(?:\s+<[^>]+>)?$', tokens[-1])
            if m_target:
                t_addr = int(m_target.group(1), 16)
                tokens[-1] = f'.L{t_addr:08x}'
                formatted_ops = ', '.join(tokens)

        # Handle call relocations (e.g. jal 0 -> jal <target>)
        if mnemonic in ('jal', 'j') and addr in relocs:
            for rtype, sym in relocs[addr]:
                if rtype in ('26', 'CALL16', 'GOT_DISP'):
                    formatted_ops = sym
                    break

        # Handle jalr clobbering delay slot (m2c limitation)
        if mnemonic == 'jalr':
            reg = operands.strip()
            if idx + 1 < len(insns):
                next_addr, next_mn, next_ops = insns[idx + 1]
                dest_reg = next_ops.split(',')[0].strip() if ',' in next_ops else next_ops.strip()
                if dest_reg == reg:
                    out_lines.append(f'    move       $t9, {format_registers(reg)}')
                    mnemonic = 'jalr'
                    formatted_ops = '$t9'

        # Handle jump table base address loads
        if mod_name == 'mgras_corona_i2c' and addr == 0xd88:
            mnemonic = 'la'
            formatted_ops = 'v1, jpt_00000028'
        elif mod_name == 'mgras_mco' and addr == 0x11d0:
            mnemonic = 'la'
            formatted_ops = 'at, jpt_00000000'

        formatted_ops = format_registers(formatted_ops)

        if formatted_ops:
            out_lines.append(f'    {mnemonic:10s} {formatted_ops}')
        else:
            out_lines.append(f'    {mnemonic}')

    with open(out_s, 'w') as f:
        f.write('\n'.join(out_lines) + '\n')

    # Emit .rodata.s if there are jump tables
    if jtables:
        ro_lines = [
            '.section .rodata',
            ''
        ]
        for base_offset, targets in sorted(jtables.items()):
            ro_lines.append(f'dlabel jpt_{base_offset:08x}')
            for t in targets:
                ro_lines.append(f'    .dword .L{t:08x}')
            ro_lines.append(f'enddlabel jpt_{base_offset:08x}')
            ro_lines.append('')
        with open(out_ro_s, 'w') as f:
            f.write('\n'.join(ro_lines) + '\n')
        print(f"[+] [{mod_name}] Emitted jump table .rodata.s -> {out_ro_s}")

    print(f"[+] [{mod_name}] Disassembled {len(insns)} instructions -> {out_s}")

def main():
    kernel_objs = sorted(glob.glob('mgras_kernel/*.o'))
    out_dir = 'mgras_kernel/disasm'
    print(f"[*] Disassembling {len(kernel_objs)} kernel modules into {out_dir}...")
    for obj in kernel_objs:
        disassemble_module(obj, out_dir)
    print("[+] Kernel disassembly complete.")

if __name__ == '__main__':
    main()
