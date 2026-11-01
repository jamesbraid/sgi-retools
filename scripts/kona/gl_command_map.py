#!/usr/bin/env python3
"""Map each public GL entry point to the command words its immediate-mode sender stores.

Usage: scripts/gl_command_map.py [--binary FILE] [--out FILE] [--ge-header FILE]

The chain, for each entry stub in the N32 libGLcore:

  entry      `lw $t9,OFF($zero)` then `jr $t9`: the stub jumps through the absolute
             word at OFF in the global dispatch table
  slot       table index (OFF - BASE) / 4, where BASE is the address of the table's
             first slot (see GLOBAL_TABLE_BASE)
  sender     the routine whose address the immediate-mode dispatch state
             (`__glkonim_dispatchState`, copied into each context by MakeCurrentRead)
             holds in that slot
  words      every store to the command port (absolute 0x4000) in the sender, in
             address order, from its fact sheet (scripts/facts.py)

Grades, from the sender's fact sheet:

  established  the entry stub and the sender body were read in full, the sender has no
               conditional branch and no call before its last command-port store, and
               the first command-port store is a constant (or an expression ending in a
               constant byte, which is the token)
  inferred     the same, but a conditional branch or a call comes before a store, so the
               words depend on the path taken
  located      no entry stub, sender or constant could be read, or the sender stores
               no command word (for example, an unimplemented stub that only sets an error)

The script reads the binaries the repository's root/ links to; it writes nothing
else. Run it inside the toolchain environment (scripts/inventory.py has the same needs).
"""
import argparse
import collections
import csv
import io
import os
import re
import sys

os.environ['LC_ALL'] = os.environ['LANG'] = 'C'
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import facts  # noqa: E402  the same file in every workspace

DEFAULT_BINARY = os.path.join(ROOT, 'root/usr/gfx/arch/IP27KONA32/libGLcore.so')
DEFAULT_OUT = os.path.join(ROOT, 'docs/gl-command-map.tsv')
DEFAULT_GE = os.path.join(ROOT, 'GE.h')

TABLE_SYMBOL = '__glkonim_dispatchState'
TABLE_SIZE = 1888          # 472 slots of 4 bytes, the size the symbol table gives
# Address of slot 0 of the global dispatch table. The stubs read it from absolute
# addresses; the first stub in the public table order (glNewList) reads 4176, and the
# name check in the output confirms the rest of the layout.
GLOBAL_TABLE_BASE = 4176
COMMAND_PORT = 0x4000

LW_T9_ZERO = 0x8C190000    # lw $t9,OFF($zero)
JR_T9 = 0x03200008         # jr $t9
UNCONDITIONAL = {'j', 'jr', 'b', 'bal', 'jal', 'jalr'}
# Senders the fact sheet cannot evaluate: each signed-byte word combines an andi-masked
# byte with a shift, and the sheet leaves the stored value unknown. Each body was read
# whole from its disassembly (objdump -d, 0xda65180 to 0xda651a4 and so on). Entries are
# (token or None, grade, note, words as read).
MANUAL = {
    '__glkonim_Color3b': (0x061, 'established',
                          'read whole; the first word is (a0 << 24) | ((a1 & 0xff) << 16) | 0x61 and the second is a2 << 24',
                          '0xda65198:(a0<<24)|((a1&0xff)<<16)|0x61; 0xda651a0:a2<<24'),
    '__glkonim_Color4b': (0x069, 'established',
                          'read whole; the first word is (a0 << 24) | ((a1 & 0xff) << 16) | 0x69 and the second is (a2 << 24) | ((a3 & 0xff) << 16)',
                          '0xda65370:(a0<<24)|((a1&0xff)<<16)|0x69; 0xda6537c:(a2<<24)|((a3&0xff)<<16)'),
    '__glkonim_Normal3b': (0x076, 'established',
                           'read whole; the first word is (a0 << 24) | ((a1 & 0xff) << 16) | 0x76 and the second is a2 << 24',
                           '0xda65628:(a0<<24)|((a1&0xff)<<16)|0x76; 0xda65630:a2<<24'),
    '__glkonim_Begin': (None, 'inferred',
                        'first word is KONA_HP_BEGIN_POINTS (0x057) plus the mode in a0, for modes 0 to 9 (sltiu against 10 at 0xd94dbb0); other modes branch to the error path at 0xd94dbd4, which stores 0xe4 and 0x500',
                        '0xd94dbc4:a0+87 (0x57 plus the mode); 0xd94dbc8:0x0; 0xd94dbd4:0xe4; 0xd94dbe0:0x500'),
}
# Rect senders: BEGIN_RECT, then a vertex-format word, then four vertex calls, then END.
# The format word is 22 for double, 14 for float and int, 10 for short (GE.h, KONA_HP_BEGIN_RECT).
# Its value collides with other token numbers (22 is KONA_HP_TEXBIND, 14 KONA_HP_TEXPARAMETERI,
# 10 KONA_HP_LIGHTMODELI), so the row's words are read by position, not by token name.
RECT_FORMAT = {
    '__glkonim_Rectd': 22, '__glkonim_Rectdv': 22,
    '__glkonim_Rectf': 14, '__glkonim_Rectfv': 14, '__glkonim_Recti': 14, '__glkonim_Rectiv': 14,
    '__glkonim_Rects': 10, '__glkonim_Rectsv': 10,
}


# Paths the word lists above leave out. Begin stores 1 at absolute 4120 on its valid path and
# End stores 0 there; the sender reads that word and branches on it.
SENDER_NOTES = {
    '__glkonim_Finish': 'when the word at absolute 4120 is 1, the sender calls __glSetError with 1282 and '
                        'sends no command word; otherwise it calls __glkona_wait_rdata with a1 = 1 between the two words',
}


def target_name(names, addr):
    return names.get(addr, '')


def word(img, addr):
    w = img.read(addr, 4)
    return int.from_bytes(w, 'big') if w else None


def entry_stubs(img):
    """(name, address, offset) for every public entry stub: a symbol named gl* whose
    first word loads a dispatch slot from absolute memory and whose first jump through
    $t9 follows within five words."""
    found, seen = [], set()
    for (addr, size, name, sec, isfn, src) in img.syms:
        if not name or not name.startswith('gl') or not isfn or name in seen:
            continue
        w0 = word(img, addr)
        if w0 is None or (w0 & 0xFFFF0000) != LW_T9_ZERO:
            continue
        if not any(word(img, addr + 4 * i) == JR_T9 for i in range(1, 6)):
            continue
        seen.add(name)
        found.append((name, addr, w0 & 0xFFFF))
    return found


def ge_tokens(path):
    names = {}
    pat = re.compile(r'^\s+(KONA_HP_\w+)\s*=\s*(0x[0-9a-fA-F]+),')
    with open(path, encoding='utf-8') as f:
        for line in f:
            m = pat.match(line)
            if m:
                names.setdefault(int(m.group(2), 16), m.group(1)[len('KONA_'):])
    return names


def constant_token(value):
    """Low byte of a word whose expression ends in an OR with a constant byte, or the
    value itself when it is a constant."""
    if value is None:
        return None
    if re.fullmatch(r'0x[0-9a-fA-F]+', value):
        return int(value, 16)
    m = re.search(r'\| (0x[0-9a-fA-F]+)\)$', value)
    if m and int(m.group(1), 16) < 0x100:
        return int(m.group(1), 16)
    return None


def path_dependent(fs, last_addr):
    """True when the words stored up to last_addr depend on a branch or a call: a
    conditional branch before the last store or one that loops back over it, a jump
    through a register other than the return, or a call before the last store."""
    for b in fs.get('branches', []):
        a = int(b['address'], 16)
        if b['mnemonic'] == 'jr' and b['text'] != 'jr ra':
            if a < last_addr:
                return True
            continue
        if b['mnemonic'] in UNCONDITIONAL:
            continue
        if a < last_addr or ('target' in b and int(b['target'], 16) <= last_addr):
            return True
    return any(int(c['address'], 16) < last_addr for c in fs.get('calls', []))


def build_rows(binary, tokens):
    img = facts.image(binary)
    table = img.read(img.byname[TABLE_SYMBOL][0][0], TABLE_SIZE)
    if table is None:
        raise SystemExit('gl_command_map: no contents for %s' % TABLE_SYMBOL)
    slots = [int.from_bytes(table[4 * i:4 * i + 4], 'big') for i in range(TABLE_SIZE // 4)]
    names = {}
    for (addr, size, name, sec, isfn, src) in img.syms:
        if name and isfn and addr not in names:
            names[addr] = name
    rows = []
    for name, stub, off in sorted(entry_stubs(img), key=lambda x: x[1]):
        slot = (off - GLOBAL_TABLE_BASE) // 4
        row = {'entry': name, 'entry_address': '0x%x' % stub, 'global_slot': '0x%x' % off,
               'table_index': slot, 'sender': '', 'sender_address': '', 'token': '', 'token_name': '',
               'first_store': '', 'words': '', 'grade': 'located', 'note': ''}
        rows.append(row)
        if (off - GLOBAL_TABLE_BASE) % 4 or not 0 <= slot < len(slots):
            row['note'] = 'slot outside the immediate table'
            continue
        target = slots[slot]
        row['sender_address'] = '0x%x' % target
        row['sender'] = names.get(target, 'sub_%x' % target)
        if target not in names:
            row['note'] = 'no symbol at the slot target'
            continue
        fs = facts.fact_sheet(binary, '0x%x' % target)
        stores = [a for a in fs['accesses'] if a.get('absolute') == '0x%x' % COMMAND_PORT and a['kind'] == 'store']
        if not stores:
            calls = sorted({str(c.get('callee') or ('indirect call' if c.get('kind') == 'register' else c.get('target')))
                            for c in fs.get('calls', [])})
            row['note'] = 'stores no command word' + ('; calls ' + ', '.join(str(c) for c in calls[:3]) if calls else '')
            continue
        first = stores[0]
        words = ['%s:%s' % (s['address'], s.get('value', '?')) for s in stores]
        row['words'] = '; '.join(words)
        row['first_store'] = first.get('value', '?')
        if target_name(names, target) in MANUAL:
            tok, grade, note, words_text = MANUAL[target_name(names, target)]
            row['words'] = words_text
            row['grade'], row['note'] = grade, note
            if tok is not None:
                row['token'] = '0x%03x' % tok
                row['token_name'] = tokens.get(tok, '')
            row['first_store'] = ''
            continue
        tok = constant_token(first.get('value'))
        if tok is None:
            row['note'] = 'first command-port store is not a constant'
            continue
        last_addr = int(stores[-1]['address'], 16)
        if path_dependent(fs, last_addr):
            row['grade'] = 'inferred'
            row['note'] = 'path-dependent: a branch or call comes before a command-port store'
            if target_name(names, target) in SENDER_NOTES:
                row['note'] += '; ' + SENDER_NOTES[target_name(names, target)]
            if target_name(names, target) in RECT_FORMAT:
                row['note'] += ('; the second word is the vertex format (%d), not a command; '
                                'the four vertex calls between it and the END send their own words'
                                % RECT_FORMAT[target_name(names, target)])
        else:
            row['grade'] = 'established'
            row['token'] = '0x%03x' % tok
            row['token_name'] = tokens.get(tok, '')
            if any(s.get('value', '?') == '?' for s in stores):
                row['note'] = 'token read whole; a payload word is not evaluated by the fact sheet'
    return rows, names, slots


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--binary', default=DEFAULT_BINARY)
    ap.add_argument('--ge-header', default=DEFAULT_GE)
    ap.add_argument('--out', default=DEFAULT_OUT)
    a = ap.parse_args(argv)
    tokens = ge_tokens(a.ge_header)
    rows, names, slots = build_rows(a.binary, tokens)
    cols = ['entry', 'entry_address', 'global_slot', 'table_index', 'sender', 'sender_address',
            'token', 'token_name', 'grade', 'first_store', 'words', 'note']
    buf = io.StringIO()
    w = csv.writer(buf, delimiter='\t', lineterminator='\n')
    w.writerow(cols)
    for r in rows:
        w.writerow([r[c] for c in cols])
    with open(a.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(buf.getvalue())
    counts = collections.Counter(r['grade'] for r in rows)
    print('entries %d: %s' % (len(rows), ', '.join('%s %d' % (k, counts[k]) for k in
                                                   ('established', 'inferred', 'located'))))
    agree = sum(1 for r in rows if r['sender'] and r['sender'].startswith('__glkonim_') and
                r['entry'][2:].split('SGIX')[0].split('SGIS')[0].split('EXT')[0] in r['sender'])
    print('sender names that contain the entry name: %d' % agree)


if __name__ == '__main__':
    main()
