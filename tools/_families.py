"""Family readings: one written entry for a large uniform group of routines, credited member by member.

A family entry is a fenced block with the info string `family` inside a prose page the inventory reads:

    ```family
    binaries: usr/lib/libx.so
    members: lock_*
    match: 8c 19 .. ..  03 20 00 08  00 00 00 00
    field: slot = u16be@2
    shape: Each wrapper loads a function pointer into t9 and jumps to it.
    varies: The slot, the byte offset of the pointer.
    role: Inferred. ...
    ```

`binaries` and `members` are comma-separated globs on the binary label and the function name. `match` is the
function's bytes: `HH` exact, `..` any, `HH/MM` the bits of MM only. The function's size must equal the
pattern's length to be a candidate. Each `field` reads one value out of the bytes of a match. A candidate
that matches is understood and records its field values; one that does not is left as the documents
leave it. Without a `match` there is no family: the byte check is what stands in for a sentence per member.
Every bit the pattern leaves open must be read by a field, and at most a quarter of the bits may be open, so
the members are the same code with named operands, not any function of that size.
"""
import fnmatch
import re

REQUIRED = ('binaries', 'members', 'match', 'shape', 'varies', 'role')
KEYS = REQUIRED + ('field',)
MIN_FIXED_BITS = 32      # a pattern that fixes fewer bits than this matches almost any function of that size
MAX_OPEN_SHARE = 4       # at most 1 bit in this many may be open: a looser pattern is not one routine's shape
FIELD = re.compile(r'^([a-z][a-z0-9_]*)\s*=\s*([us])(8|16|32|64)(be|le)@(0x[0-9a-fA-F]+|\d+)'
                   r'(?:\s*&\s*(0x[0-9a-fA-F]+|\d+))?$')
KEY_LINE = re.compile(r'^([a-z]+):\s*(.*)$')


class Family:
    __slots__ = ('where', 'section', 'ref', 'binaries', 'members', 'value', 'mask', 'fields', 'shape', 'varies',
                 'role')

    def length(self):
        return len(self.value)

    def covers(self, labels, name):
        return (any(fnmatch.fnmatchcase(lab, g) for lab in labels for g in self.binaries)
                and any(fnmatch.fnmatchcase(name, g) for g in self.members))

    def check(self, data):
        """({field: value}, '') for the bytes of a member that match, ({}, why) for ones that do not."""
        if len(data) != len(self.value):
            return {}, 'size %d, the pattern is %d bytes' % (len(data), len(self.value))
        for i, (b, v, m) in enumerate(zip(data, self.value, self.mask)):
            if b & m != v:
                return {}, 'byte %d is 0x%02x, the pattern wants 0x%02x under mask 0x%02x' % (i, b, v, m)
        return {name: read_field(data, f) for name, f in self.fields}, ''


def blocks(lines):
    """[(index of the opening line, nearest heading, [body lines])] for each family block of a page."""
    out, heading, i = [], '', 0
    while i < len(lines):
        s = lines[i].strip()
        if s == '```family':
            j = i + 1
            while j < len(lines) and lines[j].strip() != '```':
                j += 1
            out.append((i, heading, lines[i + 1:j]))
            i = j
        elif s.startswith('```'):
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                i += 1
        elif re.match(r'#{1,6}\s', lines[i]):
            heading = re.sub(r'^#+\s*', '', lines[i]).strip()
        i += 1
    return out


def read_field(data, f):
    signed, bits, order, off, mask = f
    v = int.from_bytes(data[off:off + bits // 8], order)
    if mask is not None:
        return '0x%x' % (v & mask)
    if signed and v >> (bits - 1):
        return str(v - (1 << bits))
    return '0x%x' % v


def covered_bits(fields, length):
    """Per byte of a pattern, the bits that the fields read."""
    got = bytearray(length)
    for _name, (_signed, bits, order, off, mask) in fields:
        width = bits // 8
        for k in range(bits):
            if mask is None or mask >> k & 1:
                got[off + (width - 1 - k // 8 if order == 'big' else k // 8)] |= 1 << k % 8
    return got


def wild_glob(globs):
    """True when a glob list names every binary or function: a glob of wildcards alone."""
    return any(not re.sub(r'[*?\[\]!]', '', g) for g in globs)


def parse_pattern(text):
    """(value bytes, mask bytes) of a `match` line, or a reason it cannot be read."""
    value, mask = [], []
    for tok in text.split():
        if tok == '..':
            value.append(0)
            mask.append(0)
        elif re.fullmatch(r'[0-9a-fA-F]{2}', tok):
            value.append(int(tok, 16))
            mask.append(0xff)
        elif re.fullmatch(r'[0-9a-fA-F]{2}/[0-9a-fA-F]{2}', tok):
            v, m = (int(x, 16) for x in tok.split('/'))
            value.append(v & m)
            mask.append(m)
        else:
            raise ValueError('"%s" is not a byte (HH), a wildcard (..) or a masked byte (HH/MM)' % tok)
    if not value:
        raise ValueError('the pattern is empty')
    fixed = sum(bin(m).count('1') for m in mask)
    if fixed < MIN_FIXED_BITS:
        raise ValueError('the pattern fixes %d bits and a family needs at least %d, or any function of that '
                         'size matches' % (fixed, MIN_FIXED_BITS))
    return bytes(value), bytes(mask)


def parse(body, role_why=None):
    """(Family, []) for the lines of a family block, or (None, [problem, ...]). role_why(text) returns '' when
    the text is a role the inventory would credit and the reason it is not otherwise."""
    problems, got, key = [], {}, None
    for ln in body:
        if not ln.strip():
            continue
        m = None if ln[:1].isspace() else KEY_LINE.match(ln.rstrip())
        if m:
            key = m.group(1)
            if key not in KEYS:
                problems.append('unknown key "%s" (keys: %s)' % (key, ', '.join(KEYS)))
            elif key != 'field' and key in got:
                problems.append('key "%s" is given twice' % key)
            else:
                got.setdefault(key, []).append(m.group(2).strip())
        elif key in got and ln[:1].isspace():
            got[key][-1] = (got[key][-1] + ' ' + ln.strip()).strip()
        else:
            problems.append('line "%s" is not "key: value" or an indented continuation' % ln.strip()[:60])
    for key in REQUIRED:
        if not ' '.join(got.get(key, [])).strip():
            problems.append('no "%s" line' % key)
    if problems:
        return None, problems
    fam = Family()
    fam.binaries = [x.strip() for x in got['binaries'][0].split(',') if x.strip()]
    fam.members = [x.strip() for x in got['members'][0].split(',') if x.strip()]
    fam.shape, fam.varies, fam.role = got['shape'][0], got['varies'][0], got['role'][0]
    try:
        fam.value, fam.mask = parse_pattern(got['match'][0])
    except ValueError as ex:
        return None, ['match: %s' % ex]
    fam.fields, seen = [], set()
    for spec in got.get('field', []):
        m = FIELD.match(spec)
        if not m:
            problems.append('field "%s" is not NAME = u|s 8|16|32|64 be|le @OFFSET [& MASK]' % spec)
            continue
        name, sign, bits, order, off, mask = m.groups()
        bits, off = int(bits), int(off, 0)
        mask = int(mask, 0) if mask else None
        if name in seen:
            problems.append('field "%s" is given twice' % name)
        elif off + bits // 8 > len(fam.value):
            problems.append('field "%s" reads past the %d-byte pattern' % (name, len(fam.value)))
        elif mask is not None and sign == 's':
            problems.append('field "%s" is signed and masked; mask an unsigned read' % name)
        elif not re.search(r'\b%s\b' % re.escape(name), fam.varies):
            problems.append('field "%s" is not named in the varies text, which has to say what it is' % name)
        seen.add(name)
        fam.fields.append((name, (sign == 's', bits, 'big' if order == 'be' else 'little', off, mask)))
    if not problems:
        total = 8 * len(fam.value)
        free = [~m & 0xff for m in fam.mask]
        nfree = sum(bin(b).count('1') for b in free)
        unread = sum(bin(b & ~c & 0xff).count('1') for b, c in zip(free, covered_bits(fam.fields, len(free))))
        if nfree * MAX_OPEN_SHARE > total:
            problems.append('the pattern leaves %d of its %d bits open and a family may leave at most 1 in %d: '
                            'fix more of the shape' % (nfree, total, MAX_OPEN_SHARE))
        if unread:
            problems.append('the pattern leaves %d bits open that no field reads: name each varying operand '
                            'with a field' % unread)
        for what, globs in (('binaries', fam.binaries), ('members', fam.members)):
            if wild_glob(globs):
                problems.append('"%s" has a glob of wildcards alone, which names every one: say which code the '
                                'family is' % what)
    if role_why is not None and not problems:
        why = role_why(fam.role)
        if why:
            problems.append('the role is not one the inventory credits: %s' % why)
    return (fam, []) if not problems else (None, problems)


def function_bytes(elf, section, addr, size):
    """The bytes of a function from its section, or from the loadable segment that holds it; b'' when the
    image does not hold them. An ARM symbol's low bit marks Thumb code, not an address."""
    if elf.header['e_machine'] == 'EM_ARM':
        addr &= ~1
    sec = elf.get_section_by_name(section) if section else None
    if sec is not None and sec['sh_type'] != 'SHT_NOBITS':
        off = addr - sec['sh_addr']
        if 0 <= off and off + size <= sec['sh_size']:
            elf.stream.seek(sec['sh_offset'] + off)
            return elf.stream.read(size)
        return b''
    if sec is None:
        for sg in elf.iter_segments():
            if (sg['p_type'] == 'PT_LOAD' and sg['p_vaddr'] <= addr and addr + size <= sg['p_vaddr'] + sg['p_filesz']):
                elf.stream.seek(sg['p_offset'] + addr - sg['p_vaddr'])
                return elf.stream.read(size)
    return b''


def verify(families, imgs, rows, elf_of):
    """One result per candidate: {'family', 'row', 'ok', 'values', 'why'}. A candidate is a function row whose
    binary and name a family covers and whose size is the pattern's length. elf_of(data) opens an image."""
    by_label = {img['label']: img for img in imgs}
    opened = {}
    out = []
    for fam in families:
        for row in rows:
            size = row.get('size')
            if size != fam.length() or not fam.covers(
                    [row['binary']] + by_label[row['binary']]['copies'], row['name']):
                continue
            lab = row['binary']
            if lab not in opened:
                try:
                    opened[lab] = elf_of(by_label[lab]['data']) if by_label[lab].get('data') else None
                except Exception:
                    opened[lab] = None
            data = b''
            if opened[lab] is not None and row['address'] and not row.get('_unknown'):
                data = function_bytes(opened[lab], row['elf_section'], int(row['address'], 16), size)
            values, why = fam.check(data) if data else ({}, 'the image does not hold the function\'s bytes')
            out.append({'family': fam, 'row': row, 'ok': not why, 'values': values, 'why': why})
    return out


def values_text(values):
    return ';'.join('%s=%s' % kv for kv in values.items())
