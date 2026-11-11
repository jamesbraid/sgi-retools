#!/usr/bin/env python3
"""List the environment variables IRIX MIPS binaries read, from their call sites.

Usage: retools/tools/re-run python3 retools/tools/envscan.py [--root DIR] [--context N]
           [--wrapper NAME]... [--no-auto-wrappers] [--string-match REGEX] [--out FILE] PATH...

PATH is an ELF file (o32, n32 or n64; executable, shared object or relocatable object), a `.a`
archive (members are scanned and keyed BINARY:MEMBER as in the inventory) or a directory, walked
recursively. Files that are not ELF are skipped. Run it in the toolchain container: the decoder is
hostfacts.py (Capstone) and the register tracking is facts.py's, so a call's first argument is the
value the routine built, not a guess from the listing.

One TSV row per call to getenv, putenv, setenv or unsetenv (or `_`/`__` spellings):

  install_path  path of the file relative to --root (default: the current directory)
  member        archive member, empty for a plain file
  function      the routine holding the call, as the symbol tables name it
  call_site     address of the call instruction
  callee        the routine called
  string        the first argument read from the file, or `?` when the tool could not resolve it,
                or `(a0 of FUNCTION)` when the routine passes its own argument on (a wrapper)
  sha256        sha256 of the file or archive member
  text_offset   call_site minus the start of its section (equal to call_site in an object file)
  kind          `env` for a call to getenv and its kin, `wrapper` for a call to a wrapper (below),
                `string` for a --string-match row
  context       with --context N only: N instructions either side of the call

A wrapper is a routine that hands one of its own arguments to getenv (`(aK of FUNCTION)`, K the
argument index), or a routine whose result is passed to getenv, a builder of the variable name
(`(ret of FUNCTION)`). Callers of each wrapper found are scanned in further passes (three at most)
and reported with the wrapper as callee and its argument as the string. --wrapper NAME[:ARG]
names one up front, for a routine the tool cannot see calling getenv (a constructor that only keeps
the name); --no-auto-wrappers turns the extra passes off.

--string-match REGEX adds rows (kind `string`) for the strings in read-only sections that match
REGEX and that no call already named, so a variable name held in a table, or handed to a routine
the tool does not know reads the environment, still shows up. Each such string is followed to the
call that passes it as one of its first four arguments: callee is that routine, string the text,
function and call_site the caller. A string the routines build the address of with no such call
shows `(ref)` as callee and the instruction that builds it as call_site; one no routine refers to
shows `(string)` and its own address. These rows are candidates to read, not reads; a routine
they name that wraps getenv can be given back with --wrapper.

Calls through a multi-GOT executable are followed (facts.py names their GOT slots from the dynamic
relocations). A file without a .symtab names only its exported routines: the others are found
from their `addu gp,t9,at` prologue and called fn_ADDRESS.

A value this tool cannot follow is `?`. It never guesses one. A file with no function symbols
cannot be split into routines and is reported on stderr, not scanned.
"""
import argparse
import bisect
import hashlib
import os
import re
import struct
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import facts  # noqa: E402
import hostfacts  # noqa: E402
import inventory  # noqa: E402

ENV_FUNCS = ('getenv', 'putenv', 'setenv', 'unsetenv', 'secure_getenv',
             '_getenv', '__getenv', '_putenv', '__putenv', '_setenv', '__setenv')
READ_FUNCS = ('getenv', 'secure_getenv', '_getenv', '__getenv')
COLUMNS = ['install_path', 'member', 'function', 'call_site', 'callee', 'string', 'sha256', 'text_offset', 'kind']
MAX_ROUTINE = 0x20000          # bytes; a longer symbol is read up to this
MAX_STRING = 256
RELOC_CALLS = ('R_MIPS_26', 'R_MIPS_CALL16', 'R_MIPS_CALL_HI16', 'R_MIPS_CALL_LO16', 'R_MIPS_GOT_DISP',
               'R_MIPS_GOT16', 'R_MIPS_PC16')


def sx16(v):
    return v - 0x10000 if v & 0x8000 else v


def cpload_gp(words, addr):
    """The global pointer a routine sets from its own address, or None when it does not.

    PIC routines start with `lui at,HI; addiu at,at,LO; addu gp,t9,at` (the two feeding words may
    sit apart); t9 holds the routine's own address on entry. The value is 32 bits wide: a 64-bit
    routine uses daddu and the same constants, and the high half of t9 is zero in the linked files
    this tool reads.
    """
    consts = {}                                     # register -> value built so far
    for w in words[:10]:
        op, rs, rt = w >> 26, (w >> 21) & 31, (w >> 16) & 31
        if op == 0x0f:                              # lui
            consts[rt] = (w & 0xffff) << 16
        elif op in (0x09, 0x19) and rs in consts:  # addiu / daddiu
            consts[rt] = (consts[rs] + sx16(w & 0xffff)) & 0xffffffff
        elif op == 0 and (w & 0x3f) in (0x21, 0x2d) and ((w >> 11) & 31) == 28:   # addu/daddu gp
            other = rt if rs == 25 else rs if rt == 25 else None
            if other in consts:
                return (addr + consts[other]) & 0xffffffff
            return None
    return None


class EnvImage(hostfacts.HostImage):
    """A HostImage that also knows the addresses of the environment routines and their wrappers."""

    def __init__(self, path, member=None, wrappers=None):
        super().__init__(path, member)
        self.names = set(ENV_FUNCS)
        self.argidx = {}            # wrapper name -> index of the argument holding the variable name
        self.stub_addr = {}         # address of a call stub or of a local definition -> name
        self.dynnames = {}          # name -> stub address, for the undefined dynamic functions
        if self.elf is not None and self.kind != 'object':
            dsym = self.elf.get_section_by_name('.dynsym')
            for k, nm in enumerate(self.dynsym):
                if nm and dsym.get_symbol(k)['st_value']:
                    self.dynnames.setdefault(nm, []).append(dsym.get_symbol(k)['st_value'])
        self.add_wrappers(wrappers or {})
        self.add_names(ENV_FUNCS)

    def add_wrappers(self, wrappers):
        for nm, idx in wrappers.items():
            self.argidx[nm] = idx
        self.add_names(wrappers)

    def add_names(self, names):
        for nm in names:
            self.names.add(nm)
            for addr in self.dynnames.get(nm, []):
                self.stub_addr[addr] = nm                       # an undefined function's call stub
            for s in self.byname.get(nm, []):                   # a routine this file defines itself
                if s[4]:
                    self.stub_addr[s[0]] = nm

    def name_function_at(self, addr):
        """A name for the routine at addr, made up of its address when the symbols do not give one."""
        nm = self.func_name_at(addr)
        if nm is None:
            nm = 'fn_%x' % addr
            self.stub_addr[addr] = nm
        return nm

    def string_at(self, addr):
        """The NUL-terminated string at a virtual address of a linked file, or None."""
        for seg in self.elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            lo, fs = seg['p_vaddr'], seg['p_filesz']
            if lo <= addr < lo + fs:
                o = seg['p_offset'] + addr - lo
                end = min(o + MAX_STRING, seg['p_offset'] + fs)
                raw = self.data[o:end]
                return text_of(raw)
        return None

    def section_string(self, secname, off):
        sec = self.elf.get_section_by_name(secname)
        if sec is None or sec['sh_type'] == 'SHT_NOBITS' or off < 0 or off >= sec['sh_size']:
            return None
        return text_of(sec.data()[off:off + MAX_STRING])

    def section_start(self, addr):
        name = self.section_of(addr)
        if self.kind == 'object':
            return 0
        sec = self.elf.get_section_by_name(name) if name else None
        return sec['sh_addr'] if sec is not None else 0


def text_of(raw):
    end = raw.find(b'\0')
    if end < 0:
        return None
    s = raw[:end]
    if not s or any(c < 0x20 or c > 0x7e for c in s):
        return None
    return s.decode('ascii')


def got_slot(img, addr):
    """(word, bound symbol name or None) of the GOT slot at addr, or None, by facts.py's own rule."""
    hit = facts.Routine.got_info(types.SimpleNamespace(img=img), facts.C(addr))
    if hit is None:
        return None
    info, word = hit
    return word, info.get('name') if info['kind'] == 'global' else None


def executable_sections(img):
    out = []
    for s in img.elf.iter_sections():
        if s['sh_flags'] & 4 and s['sh_type'] == 'SHT_PROGBITS' and s['sh_size']:
            out.append((s['sh_addr'], s['sh_size'], s.name, s.data()))
    return sorted(out)


CPLOAD_GP = b'\x03\x21\xe0\x21'      # addu gp,t9,at


def anonymous_routines(img, covered):
    """Routines the symbol tables do not name, found from their `addu gp,t9,at` prologue.

    A file without a .symtab names only its exported routines; its internal ones (a static
    initializer, a file-local helper) sit between them. A PIC routine opens with a `lui at,HI`
    shortly before `addu gp,t9,at`, so each such site not inside a named routine starts one.
    Routines without that prologue (leaf routines) make no calls and cannot read the environment.
    """
    out = []
    for base, n, secname, data in executable_sections(img):
        i = data.find(CPLOAD_GP)
        while i >= 0:
            if i % 4 == 0:
                start = None
                for j in range(i - 4, max(i - 24, -4), -4):
                    if j >= 0 and data[j] >> 2 == 0x0f and (data[j + 1] & 0x1f) == 1:
                        start = j      # lui $at, HI
                        break
                if start is not None:
                    addr = base + start
                    k = bisect.bisect_right(covered, (addr, 1 << 62)) - 1
                    if k < 0 or not (covered[k][0] <= addr < covered[k][1]):
                        out.append((addr, secname))
            i = data.find(CPLOAD_GP, i + 1)
    return out


def routines(img):
    """[(address, size, name, section)] for every function symbol, sized by the symbol or the next one,
    and for each routine the symbols do not name (called fn_ADDRESS)."""
    seen = {}
    for a, sz, name, sec, func, src in img.syms:
        if not func:
            continue
        cur = seen.get(a)
        if cur is None or (src == 'symtab' and cur[3] != 'symtab') or (sz > cur[0] and src == cur[3]):
            seen[a] = (sz, name, sec, src)
    addrs = sorted(seen)
    out = []
    for k, a in enumerate(addrs):
        sz, name, sec, src = seen[a]
        nxt = addrs[k + 1] if k + 1 < len(addrs) else None
        if not sz and nxt:
            sz = nxt - a
        out.append((a, min(sz, MAX_ROUTINE), name, sec))
    if img.kind != 'object' and img.elf is not None:
        covered = sorted((a, a + sz) for a, sz, _, _ in out if sz)
        extra = anonymous_routines(img, covered)
        if extra:
            starts = sorted({a for a, _, _, _ in out} | {a for a, _ in extra})
            for a, sec in extra:
                k = bisect.bisect_right(starts, a)
                nxt = starts[k] if k < len(starts) else a + MAX_ROUTINE
                out.append((a, min(nxt - a, MAX_ROUTINE), 'fn_%x' % a, sec))
            out.sort()
    return out


def candidates_linked(img):
    """Routines whose code reaches an environment routine: a load from a GOT slot that holds its
    address, or a direct call to its stub. A superset filter; facts.py decides what the call is."""
    cands = []
    secs = executable_sections(img)
    starts = [s[0] for s in secs]
    for a, sz, name, _ in routines(img):
        i = bisect.bisect_right(starts, a) - 1
        if i < 0:
            continue
        base, n, _, data = secs[i]
        if not (base <= a < base + n) or sz < 8:
            continue
        o = a - base
        words = struct.unpack('>%dI' % (min(sz, n - o) // 4), data[o:o + (min(sz, n - o) // 4) * 4])
        gp = cpload_gp(words, a)
        if gp is None:
            gp = img.gp
        hit = False
        for w in words:
            op = w >> 26
            if op in (0x23, 0x37) and ((w >> 21) & 31) == 28 and gp is not None:
                hit_slot = got_slot(img, (gp + sx16(w & 0xffff)) & 0xffffffff)
                if hit_slot is not None and hit_slot[1] in img.names:
                    hit = True
                    break
            elif op == 3:
                if (((a & 0xf0000000) | ((w & 0x3ffffff) << 2)) in img.stub_addr):
                    hit = True
                    break
        if hit:
            cands.append((a, sz, name, secs[i][2]))
    return cands


def candidates_object(img):
    """Routines of a relocatable object with a call relocation against an environment routine."""
    cands = {}
    funcs = routines(img)
    for rel in img.elf.iter_sections():
        if rel['sh_type'] not in ('SHT_REL', 'SHT_RELA'):
            continue
        target = img.elf.get_section(rel['sh_info'])
        symtab = img.elf.get_section(rel['sh_link'])
        for r in rel.iter_relocations():
            sym = symtab.get_symbol(r['r_info_sym'])
            if sym.name not in img.names:
                continue
            for a, sz, name, sec in funcs:
                if sec == target.name and a <= r['r_offset'] < a + max(sz, 4):
                    cands[(a, sec)] = (a, sz, name, sec)
    return sorted(cands.values())


def resolve(img, text):
    """(string, wrapper) for an argument expression.

    string is the text the argument names, or None. wrapper is (routine, index) when the argument
    is not a constant but the routine's own incoming argument aK (index K), or the result of
    another routine (index 0 of that routine, a function that builds the variable name); the
    caller then names the enclosing routine for the first case. Otherwise None.
    """
    if text is None:
        return None, None
    t = text.strip()
    m = re.fullmatch(r'a([0-7])', t)
    if m:
        return None, ('self', int(m.group(1)))
    m = re.fullmatch(r'ret\((?:(0x[0-9a-fA-F]+)|([^)]+))\)', t)
    if m:
        if m.group(1):
            return None, (img.name_function_at(int(m.group(1), 16)), 0)
        return None, (m.group(2), 0)
    m = re.fullmatch(r'(-?)(0x[0-9a-fA-F]+|\d+)', t)
    if m and img.kind != 'object':
        v = int(m.group(2), 0) * (-1 if m.group(1) else 1)
        return img.string_at(v & 0xffffffff), None
    m = re.fullmatch(r'sym\(([^)]+)\)\s*([+-](?:0x[0-9a-fA-F]+|\d+))?', t)
    if m and img.kind == 'object':
        name, off = m.group(1), int(m.group(2), 0) if m.group(2) else 0
        if name.startswith('.'):
            return img.section_string(name, off), None
        for s in img.byname.get(name, []):
            if s[3]:
                sec = img.elf.get_section_by_name(s[3])
                if sec is not None:
                    return img.section_string(s[3], s[0] - (sec['sh_addr'] if img.kind != 'object' else 0) + off), None
    return None, None


def callee_name(img, c):
    name = c.get('callee') or ''
    if name.split('+')[0] in img.names:
        return name.split('+')[0]
    t = c.get('target')
    if t:
        addr = int(t, 16)
        if addr in img.stub_addr:
            return img.stub_addr[addr]
    return None


def context_window(img, addr, section, n):
    if n <= 0:
        return ''
    lo = max(addr - 4 * n, 0)
    try:
        ins = img.disassemble(lo, 4 * (2 * n + 1), section)
    except Exception:           # context is a convenience; the row stands without it
        return ''
    return ' | '.join('%x: %s %s' % (i['addr'], i['mn'], ','.join(i['ops'])) for i in ins)


def scan_image(img, label, context=0):
    """Rows for one image: (function, call_site, callee, string, text_offset, context, new wrappers)."""
    out = []
    if not img.func_addrs:
        sys.stderr.write('envscan: %s has no function symbols; not scanned\n' % label)
        return out
    cands = candidates_object(img) if img.kind == 'object' else candidates_linked(img)
    for a, sz, name, sec in cands:
        try:
            r = facts.Routine(img, name, a, sz, sec, 'symbol', facts.DEFAULT_ERRORS)
            fs = r.facts(False)
        except (SystemExit, Exception) as exc:      # one unreadable routine must not hide the file's others
            sys.stderr.write('envscan: %s %s at 0x%x: %s\n' % (label, name, a, exc))
            continue
        for c in fs['calls']:
            callee = callee_name(img, c)
            if callee is None:
                continue
            idx = img.argidx.get(callee, 0)
            reg_name = img.regnames[4 + idx]
            text = c.get('args', {}).get(reg_name)
            if text is None and reg_name in c.get('incoming', ()):
                text = reg_name
            arg, wrap = resolve(img, text)
            site = int(c['address'], 16)
            new = None
            if arg is None and wrap is not None:
                who, k = wrap
                if who == 'self':
                    new, arg = (name, k), '(a%d of %s)' % (k, name)
                elif callee in READ_FUNCS:
                    new, arg = (who, 0), '(ret of %s)' % who
                else:       # putenv and its kin take a buffer the routine filled in: no name to follow
                    arg = '(ret of %s)' % who
            out.append((name, site, callee, arg if arg is not None else '?',
                        '0x%x' % (site - img.section_start(site)), context_window(img, site, sec, context),
                        new, 'env' if callee in ENV_FUNCS else 'wrapper'))
    return out


def rodata_strings(img, pattern):
    """{address: text} of the strings in read-only data sections that match PATTERN."""
    out = {}
    for s in img.elf.iter_sections():
        if s['sh_type'] != 'SHT_PROGBITS' or s['sh_flags'] & 4 or not s['sh_size']:
            continue
        if not s.name.startswith(('.rodata', '.srdata')):
            continue
        d = s.data()
        for m in re.finditer(rb'[\x20-\x7e]{3,%d}(?=\0)' % MAX_STRING, d):
            text = m.group().decode('ascii')
            if pattern.fullmatch(text):
                out[(s['sh_addr'] if img.kind != 'object' else 0) + m.start()] = text
    return out


def referencing_routines(img, addrs):
    """[(address, size, name, section, [(site, string address)])] for routines that build one of
    the ADDRS. A superset filter for linked files: the address comes as a GOT page plus an offset
    (`addiu`, `ori`, or the offset of a load or store), as the global pointer plus an offset, or as
    `lui` plus an offset, each tracked per routine on the registers it writes."""
    out = []
    secs = executable_sections(img)
    starts = [x[0] for x in secs]
    for a, sz, name, _ in routines(img):
        i = bisect.bisect_right(starts, a) - 1
        if i < 0 or sz < 8:
            continue
        base, n, secname, data = secs[i]
        if not (base <= a < base + n):
            continue
        o = a - base
        cnt = min(sz, n - o) // 4
        words = struct.unpack('>%dI' % cnt, data[o:o + cnt * 4])
        gp = cpload_gp(words, a)
        if gp is None:
            gp = img.gp
        regs, hits = {}, []
        for k, w in enumerate(words):
            op, rs, rt = w >> 26, (w >> 21) & 31, (w >> 16) & 31
            if op == 0x0f:
                regs[rt] = (w & 0xffff) << 16
            elif op in (0x23, 0x37) and rs == 28 and gp is not None:
                slot = got_slot(img, (gp + sx16(w & 0xffff)) & 0xffffffff)
                if slot is not None and not slot[1]:
                    if slot[0] in addrs:        # the page word is the address itself
                        hits.append((a + 4 * k, slot[0]))
                    regs[rt] = slot[0]
                else:
                    regs.pop(rt, None)
            elif op in (0x09, 0x19, 0x0d) or 0x20 <= op < 0x30:       # addiu, ori and every load or store
                base_v = gp if rs == 28 else regs.get(rs)
                if base_v is not None:
                    v = (base_v + sx16(w & 0xffff)) & 0xffffffff
                    if v in addrs:
                        hits.append((a + 4 * k, v))
                if op in (0x09, 0x19, 0x0d) or op < 0x28:
                    regs.pop(rt, None)
        if hits:
            out.append((a, sz, name, secname, hits))
    return out


def string_rows(img, pattern, named, context=0):
    """Rows for matching strings that no env-routine call already named (kind `string`).

    A string passed as one of the first four arguments of a call gives a row with that call's
    callee. One the routines build the address of without such a call gives callee `(ref)` and the
    instruction that builds it, which is where to look. One no routine refers to (a table in data,
    or a reference the filter cannot see) gives `(string)` and the string's own address."""
    strings = rodata_strings(img, pattern)
    pending = {a: t for a, t in strings.items() if t not in named}
    if not pending or img.kind == 'object':
        return [('', a, '(string)', t, '0x%x' % (a - img.section_start(a)), '', None, 'string')
                for a, t in sorted(pending.items())]
    out, seen = [], set()
    texts = set(pending.values())
    refs = {}
    for a, sz, name, sec, hits in referencing_routines(img, set(pending)):
        for site, v in hits:
            refs.setdefault(pending[v], []).append((name, site, sec))
        try:
            fs = facts.Routine(img, name, a, sz, sec, 'symbol', facts.DEFAULT_ERRORS).facts(False)
        except (SystemExit, Exception) as exc:
            sys.stderr.write('envscan: %s at 0x%x: %s\n' % (name, a, exc))
            continue
        for c in fs['calls']:
            for reg_name in ('a0', 'a1', 'a2', 'a3'):
                text, _ = resolve(img, c.get('args', {}).get(reg_name))
                if text is not None and text in texts:
                    site = int(c['address'], 16)
                    callee = c.get('callee') or c.get('register') or '?'
                    out.append((name, site, callee, text, '0x%x' % (site - img.section_start(site)),
                                context_window(img, site, sec, context), None, 'string'))
                    seen.add(text)
    for t in sorted(set(refs) - seen):
        for name, site, sec in refs[t]:
            out.append((name, site, '(ref)', t, '0x%x' % (site - img.section_start(site)),
                        context_window(img, site, sec, context), None, 'string'))
        seen.add(t)
    for a, t in sorted(pending.items()):
        if t not in seen:
            out.append(('', a, '(string)', t, '0x%x' % (a - img.section_start(a)), '', None, 'string'))
    return out


def elf_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for d, dirs, files in os.walk(p):
                dirs.sort()
                for f in sorted(files):
                    yield os.path.join(d, f)
        else:
            yield p


def units(path):
    """(member or None, bytes) for each ELF the path holds: the file, or each ELF member of an archive."""
    with open(path, 'rb') as fh:
        head = fh.read(8)
    if head[:4] == b'\x7fELF':
        with open(path, 'rb') as fh:
            yield None, fh.read()
    elif head == b'!<arch>\n':
        with open(path, 'rb') as fh:
            data = fh.read()
        for name, body in inventory.unpack_ar(data):
            if body[:4] == b'\x7fELF':
                yield name, body


def scan_file(path, root, wrappers, auto, context, string_re):
    rel = os.path.relpath(path, root)
    rows = []
    for member, data in units(path):
        sha = hashlib.sha256(data).hexdigest()
        label = rel + (':' + member if member else '')
        found, img = [], None
        try:
            img = EnvImage(path, member, dict(wrappers))
        except Exception as exc:            # a damaged ELF is reported, not fatal to the walk
            sys.stderr.write('envscan: %s: %s\n' % (label, exc))
            continue
        for _ in range(3 if auto else 1):
            found = scan_image(img, label, context)
            new = {f[6][0]: f[6][1] for f in found if f[6] and f[6][0] not in img.argidx and f[6][0] not in ENV_FUNCS}
            if not new:
                break
            img.add_wrappers(new)
        if string_re is not None and img.elf is not None:
            found += string_rows(img, string_re, {f[3] for f in found}, context)
        for fn, site, callee, arg, off, ctx, _w, kind in found:
            rows.append([rel, member or '', fn, '0x%x' % site, callee, arg, sha, off, kind]
                        + ([ctx] if context else []))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--root', default='.', help='install paths are relative to this directory')
    ap.add_argument('--context', type=int, default=0, help='instructions of context either side of each call')
    ap.add_argument('--wrapper', action='append', default=[],
                    help='NAME[:ARG]: a routine that passes its argument ARG (default 0) to getenv')
    ap.add_argument('--no-auto-wrappers', action='store_true')
    ap.add_argument('--string-match', help='also list read-only strings matching this regular expression')
    ap.add_argument('--out', help='write the TSV here instead of standard output')
    a = ap.parse_args(argv)
    pat = re.compile(a.string_match) if a.string_match else None
    wrappers = {}
    for w in a.wrapper:
        nm, _, idx = w.partition(':')
        wrappers[nm] = int(idx or 0)
    cols = COLUMNS + (['context'] if a.context else [])
    rows = []
    for path in elf_files(a.paths):
        rows += scan_file(path, a.root, wrappers, not a.no_auto_wrappers, a.context, pat)
    rows.sort(key=lambda r: (r[0], r[1], int(r[3], 16), r[4]))
    text = '\t'.join(cols) + '\n' + ''.join('\t'.join(r) + '\n' for r in rows)
    if a.out:
        with open(a.out, 'w') as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
