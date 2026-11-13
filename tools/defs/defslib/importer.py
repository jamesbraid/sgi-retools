"""Convert a repo's annotated decode and census headers into register-map sources.

Reads the old defs.toml for the header list and per-header settings, and
each header's annotations:

  decode headers  REG / WORD / FIELD / ENUM / TESTVEC lines (regs form), or the
                  older FIELD-only form with an explicit macro table (legacy)
  census headers  `#define PFX_NAME 0xOFF /* [E] width N byte(s), access rw; ... */`
  plain tables    graded numeric #defines and nothing else

and writes one devices/<unit>/registers.toml per header, devices/<unit>/helpers.h for
the function-like macros it cannot turn into data, and tools/config/defs-check.toml (a
repository still on the old layout gets defs/<unit>.toml, defs/<unit>_helpers.h and
defs/check.toml). Nothing is
guessed silently: the report lists every constant it could not grade, every
grade it defaulted, every macro it could not carry over and every legacy name
that differs from the naming rule (those become the forwarding header's aliases).
"""
import copy
import os
import re
import tomllib

from . import gen_c, toml_emit
from .c_scan import (block_comment_before, extract_code, include_guard, num_literal, scan_defines,
                     unknown_annotation_lines, unknown_annotations)
from .checks import eval_c
from .model import GRADES, normalize
from .modelcheck import check_overlap, check_unit

GRADE_RE = re.compile(r"\b(established|inferred|unknown)\b")
CENSUS_GRADE = {"E": "established", "I": "inferred", "U": "unknown"}
RANK = {g: i for i, g in enumerate(GRADES)}

REG_RE = re.compile(r"^\s*/\*\s*REG:\s*(\w+)\.(\w+)\s+(0x[0-9a-fA-F]+)\s+(r|w|rw)(\d+)(?:\s+count=(\d+))?"
                    r"(?:\s+space=(\w+))?\s+reset=(\w+)\s+(\w+)\s*\*/\s*$")
WORD_RE = re.compile(r"/\*\s*WORD:\s*([A-Z][A-Z_0-9]*)\s+(32|64)\s*\*/")
FIELD_RE = re.compile(r"/\*\s*FIELD:\s*(\w+)\.(\w+)(?:\.(\w+))?\s+(\d+):(\d+)\s+(\w+)\s*\*/")
ENUM_RE = re.compile(r"/\*\s*ENUM:\s*(\w+)\.(\w+)(?:\.(\w+))?\s+(0x[0-9a-fA-F]+|\d+)\s+(\w+)\s+(\w+)\s*\*/")
TV_RE = re.compile(r"(TESTVEC|EXAMPLE \(unverified\)):\s*(0x[0-9a-fA-F]+) as (\w+)(?:\.(\w+))? => (.+)")
CENSUS_RE = re.compile(r"\[([EIU])\]\s*(.*)$")
TITLE_RE = re.compile(r"^\s*\*\s*[\w./-]+\s+-\s+(.+?)\s*$", re.M)


class Report:
    def __init__(self):
        self.ungraded = []      # (unit, macro, value, why)
        self.defaulted = []     # (unit, what)
        self.dropped = []       # (unit, what, why)
        self.aliases = []       # (unit, old, new)
        self.unmapped = []      # (unit, macro, value)
        self.mismatched = []    # (unit, macro, old, new)
        self.helpers = []       # (unit, macro)
        self.spaces = []        # (unit, space)
        self.notes = []

    def lines(self):
        o = []

        def sect(title, rows, fmt):
            rows = list(dict.fromkeys(rows))
            o.append("%s: %d" % (title, len(rows)))
            for r in rows:
                o.append("  " + fmt(r))
        sect("constants with no grade (grade them in defs/<unit>.toml or list them in defs/legacy-dropped.txt)",
             self.ungraded, lambda r: "%s: %s = %s (%s)" % r)
        sect("macros whose value differs between the old header and the generated one (fix before migrating)",
             self.mismatched, lambda r: "%s: %s old %s new %s" % r)
        sect("old macros with no counterpart (alias them under [c.aliases], or list them in defs/legacy-dropped.txt)",
             self.unmapped, lambda r: "%s: %s = %s" % r)
        sect("legacy names that differ from the naming rule (now [c.aliases]; the forwarding header defines them)",
             self.aliases, lambda r: "%s: %s -> %s" % r)
        sect("grades defaulted by the importer", self.defaulted, lambda r: "%s: %s" % r)
        sect("dropped from the data", self.dropped, lambda r: "%s: %s (%s)" % r)
        sect("code copied to defs/<unit>_helpers.h (function-like macros and C outside the #defines)", self.helpers, lambda r: "%s: %s" % r)
        sect("address spaces declared in register-index units", self.spaces, lambda r: "%s: %s" % r)
        for n in self.notes:
            o.append("note: %s" % n)
        return o


class Result:
    def __init__(self):
        self.units = {}         # name -> source dict (ordered like the header list)
        self.helpers = {}       # name -> helper header text
        self.check = {}
        self.report = Report()
        self.header_of = {}     # unit -> header path
        self.no_prose_check = set()   # units whose old header was never scanned for spelled-out offsets


# ---------------------------------------------------------------------------
def unit_name_for(path, taken):
    base = os.path.basename(path)
    stem = re.sub(r"\.h$", "", base)
    stem = re.sub(r"_DECODE$", "", stem, flags=re.I)
    name = re.sub(r"[^a-z0-9]+", "_", stem.lower()).strip("_")
    if not re.match(r"^[a-z]", name):
        name = "u_" + name
    n, i = name, 2
    while n in taken:
        n, i = "%s_%d" % (name, i), i + 1
    return n


def weakest(grades):
    gs = [g for g in grades if g in RANK]
    # RANK counts up from the strongest grade, so the weakest is the highest rank
    return max(gs, key=lambda g: RANK[g]) if gs else "established"


def common_prefix(names):
    """Longest run of leading underscore-separated tokens shared by every name."""
    toks = [n.split("_") for n in names]
    if not toks:
        return ""
    out = []
    for parts in zip(*toks):
        if len(set(parts)) != 1:
            break
        out.append(parts[0])
    if len(out) == len(toks[0]) and len(toks) == 1:
        out = out[:1]
    return "_".join(out)


def pick_prefix(unit, hc, names):
    """The macro prefix: the configured one, else the unit's name if most macros start with it,
    else what all the macros share ("heart_extra" holds HEART_ macros, not HEART_EXTRA_)."""
    names = list(names)
    cands = [hc.get("prefix"), unit.upper(), re.sub(r"_(EXTRA|REQUESTS)$", "", unit.upper()), common_prefix(names)]
    for c in cands:
        if c and names and sum(n.startswith(c + "_") for n in names) * 5 >= len(names) * 4:
            return c
    return cands[-1] or unit.upper()


def foreign_constant(unit, d, res, consts):
    """A graded numeric macro whose name does not start with the unit's prefix keeps its
    full name through the constant's `macro` key; an ungraded one is reported."""
    m = CENSUS_RE.match(d.comment)
    gm = GRADE_RE.search(d.comment)
    g = CENSUS_GRADE[m.group(1)] if m else (gm.group(1) if gm else None)
    if g is None:
        res.report.ungraded.append((unit, d.name, d.body, "no grade in the header"))
        return
    c = {"value": num_literal(d.body), "grade": g, "macro": d.name}
    if d.comment and len(d.comment) < 600:
        c["doc"] = re.sub(r"^\[[EIU]\]\s*", "", d.comment)
    consts[d.name] = c
    res.report.notes.append("%s: %s does not start with the unit prefix; kept under its own name (constant `macro` key)" % (unit, d.name))


def parse_expect(s):
    out = {}
    for kv in s.split(","):
        k, _, v = kv.strip().partition("=")
        v = v.strip()
        out[k.strip()] = v if v.startswith("@") else int(v, 0)
    return out


def classify(text):
    for ln in text.splitlines():
        if "<" in ln:
            continue
        if REG_RE.match(ln) or WORD_RE.search(ln) or FIELD_RE.search(ln):
            return "decode"
    for d in scan_defines(text):
        m = CENSUS_RE.match(d.comment)
        if m and d.indent >= 1 and re.search(r"width [\d/]+ byte", d.comment) and "access" in d.comment:
            return "census"
    return "table"


# ---------------------------------------------------------------------------
def import_decode(text, hc, unit, frm, res, space_units):
    """REG/WORD/FIELD/ENUM/TESTVEC headers. Returns (source dict, aliases)."""
    rep = res.report
    lines = text.splitlines()
    defs = scan_defines(text)
    guard = include_guard(text)
    regs, words, consts, fld = {}, {}, {}, {}
    block = hc.get("block")
    explicit_prefix = hc.get("prefix")
    word_width = {m.group(1): int(m.group(2)) for ln in lines if "<" not in ln for m in [WORD_RE.search(ln)] if m}
    reg_lines = []
    for i, ln in enumerate(lines):
        m = REG_RE.match(ln) if "<" not in ln else None
        if not m:
            continue
        blk, n, off, acc, wd, cnt, sp, rst, g = m.groups()
        r = {"offset": int(off, 16), "access": acc, "width": int(wd), "grade": g,
             "reset": "unknown" if rst == "unknown" else int(rst, 0)}
        if cnt:
            r["count"] = int(cnt)
        space = sp or hc.get("space")
        if space:
            r["space"] = space
        doc = block_comment_before(lines, i)
        if doc:
            r["doc"] = doc
        r["fields"], r["tests"] = {}, []
        reg_lines.append((blk, n, r))
    # a header may name several register blocks; a unit has one `block`, so such a header becomes
    # block-less (macros use the prefix) and any block whose offsets collide gets its own address space
    blocks = sorted({b for b, _, _ in reg_lines})
    multi = not hc.get("block") and len(blocks) > 1
    regkey, taken_names = {}, {}
    for blk, n, r in reg_lines:
        taken_names.setdefault(n, set()).add(blk)
    for blk, n, r in reg_lines:
        key = "%s_%s" % (blk.lower(), n) if multi and len(taken_names[n]) > 1 else n
        regkey[(blk, n)] = key
        regs[key] = r
    if multi:
        trial = normalize({"unit": unit, "prefix": "X", "from": "x", "registers": copy.deepcopy(regs)})
        if check_overlap([trial]):
            by_block = {regkey[(b, n)]: b for b, n, _ in reg_lines}
            for key, r in regs.items():
                if not r.get("space"):
                    r["space"] = "%s_%s" % (unit, by_block[key].lower())
            rep.spaces.append((unit, "one per register block (%s): the blocks' offsets collide in one space" % ", ".join(b.lower() for b in blocks)))
        rep.notes.append("%s: REG lines name %d register blocks (%s) and the header configures none; the unit has no block, so register macros use the prefix"
                         % (unit, len(blocks), ", ".join(blocks)))
    elif reg_lines:
        block = block or reg_lines[0][0]
    for i, ln in enumerate(lines):
        m = FIELD_RE.search(ln) if "<" not in ln else None
        if not m:
            continue
        a, b, c, hi, lo, g = m.groups()
        f = {"bits": [int(hi), int(lo)], "grade": g}
        if c is None:
            w = words.setdefault(a, {"width": word_width.get(a, 32), "fields": {}, "tests": []})
            if "doc" not in w:
                d = block_comment_before(lines, i)
                if d:
                    w["doc"] = d
            w["fields"][b] = f
            fld[(a, b)] = f
        elif (a, b) in regkey:
            key = regkey[(a, b)]
            regs[key]["fields"][c] = f
            fld[(key, c)] = f
        else:
            rep.dropped.append((unit, "FIELD %s.%s.%s" % (a, b, c), "names no REG line"))
    for w, x in word_width.items():
        words.setdefault(w, {"width": x, "fields": {}, "tests": []})
    for w in words.values():
        if any(f["bits"][0] > 31 for f in w["fields"].values()):
            w["width"] = 64
    # a word's grade is the weakest of its fields
    for n, w in words.items():
        w["grade"] = weakest(f["grade"] for f in w["fields"].values())
    if words:
        rep.defaulted.append((unit, "%d word grades set to the weakest grade of their fields (the header grades fields, not words)" % len(words)))
    # prefix
    prefix = explicit_prefix or block
    if not prefix:
        for d in defs:
            mm = re.match(r"(\w+?)_(" + "|".join(re.escape(w) for w in words) + r")_\w+_SHIFT$", d.name) if words else None
            if mm:
                prefix = mm.group(1)
                break
    if not prefix:
        prefix = common_prefix([d.name for d in defs if num_literal(d.body) is not None]) or unit.upper()
    enum_macro_names = set()
    family_names = set()
    families = hc.get("enum_families", [])
    if families:
        enums = {}
        for fam in families:
            en = fam["prefix"].lower()
            enums[en] = {"doc": fam.get("doc", ""), "values": {}}
            fam["_en"] = en
        order = sorted(families, key=lambda f: -len(f["prefix"]))
        for d in defs:
            nm = d.name
            val = num_literal(d.body)
            if val is None or d.params:
                continue
            for fam in order:
                tag = "%s_%s_" % (prefix, fam["prefix"])
                if nm.startswith(tag):
                    lab = nm[len(tag):].lower()
                    gm = GRADE_RE.search(d.comment)
                    ev = {"value": val, "grade": gm.group(1) if gm else None}
                    enums[fam["_en"]]["values"][lab] = ev
                    family_names.add(nm)
                    break
        for fam in families:
            e = enums[fam["_en"]]
            first = fam["fields"][0].split(".")
            fgrade = fld[tuple(first)]["grade"] if tuple(first) in fld else "inferred"
            inherited = [lab for lab, ev in e["values"].items() if ev["grade"] is None]
            for lab in inherited:
                e["values"][lab]["grade"] = fgrade
            if inherited:
                rep.defaulted.append((unit, "enum %s: %d of %d values have no grade in the header and inherit %s from field %s (%s)"
                                      % (fam["_en"], len(inherited), len(e["values"]), fgrade, fam["fields"][0], ", ".join(inherited))))
            for t in fam["fields"]:
                key = tuple(t.split(".")) if t.count(".") == 1 else tuple(t.split(".")[-2:])
                if key in fld:
                    fld[key]["enum"] = fam["_en"]
    else:
        enums = {}
    for m in (ENUM_RE.finditer(text)):
        a, b, c, v, lab, g = m.groups()
        key = (regkey.get((a, b), b), c) if c else (a, b)
        if key not in fld:
            rep.dropped.append((unit, "ENUM %s" % ".".join(x for x in (a, b, c) if x), "names no FIELD"))
            continue
        fld[key].setdefault("enums", {})[lab] = {"value": int(v, 0), "grade": g}
        head = (block or prefix) if key[0] in regs else prefix
        enum_macro_names.add("%s_%s_%s_%s" % (head, key[0].upper(), key[1].upper(), lab.upper()))
    for m in TV_RE.finditer(text):
        kind, val, a, b, exp = m.groups()
        tgt = regs.get(regkey.get((a, b), b)) if b else words.get(a)
        if tgt is None:
            rep.dropped.append((unit, "%s 0x%x" % (kind, int(val, 16)), "names no register or word"))
            continue
        try:
            e = parse_expect(exp)
        except ValueError:
            rep.dropped.append((unit, "%s %s" % (kind, val), "a clause the parser cannot read: %s" % exp[:40]))
            continue
        e = {k: ("@%s" % v[1:] if isinstance(v, str) else v) for k, v in e.items()}
        tgt["tests"].append({"value": int(val, 16), "kind": "vector" if kind == "TESTVEC" else "example", "expect": e})
    # numeric constants: graded #defines that are not layout macros
    cp = hc.get("const_prefix") or prefix
    layout = set(legacy_tables(hc, unit))
    for (owner, fname), _f in fld.items():
        head = (block or prefix) if owner in regs else prefix
        for suf in ("_SHIFT", "_MASK", "_INPLACE"):
            layout.add("%s_%s_%s%s" % (head, owner.upper(), fname.upper(), suf))
    for d in defs:
        if d.params or d.name == guard or d.name in layout or d.name in family_names:
            continue
        val = num_literal(d.body)
        if val is None:
            continue
        if d.name in enum_macro_names:
            continue
        gm = GRADE_RE.search(d.comment)
        if not d.name.startswith(cp + "_"):
            foreign_constant(unit, d, res, consts)
            continue
        if not gm:
            rep.ungraded.append((unit, d.name, d.body, "no grade in the header"))
            continue
        c = {"value": val, "grade": gm.group(1)}
        if d.comment and len(d.comment) < 200:
            c["doc"] = re.sub(r"\s*\b(established|inferred|unknown)\b:?\s*", "", d.comment, count=1).strip(" ,;:") or ""
            if not c["doc"]:
                del c["doc"]
        consts[d.name[len(cp) + 1:]] = c
    src = {"unit": unit, "prefix": prefix}
    if block and block != prefix:
        src["block"] = block
    src["from"] = frm
    if hc.get("description"):
        src["doc"] = " ".join(hc["description"]) if isinstance(hc["description"], list) else hc["description"]
    for n, (tname, tdoc) in {k: v for k, v in hc.get("words", {}).items() if len(v) == 2}.items():
        if n in words:
            words[n]["type_name"], words[n]["doc"] = tname, tdoc
    if hc.get("const_prefix"):
        src["c"] = {"const_prefix": hc["const_prefix"]}
    if regs:
        src["registers"] = regs
    if words:
        src["words"] = words
    if consts:
        src["constants"] = consts
    if enums:
        src["enums"] = enums
    if hc.get("space") or any("space" in r for r in regs.values()):
        names = {r["space"] for r in regs.values() if r.get("space")}
        src["spaces"] = {n: {"unit": "byte"} for n in sorted(names)}
    return src


def import_census(text, hc, unit, frm, res):
    rep = res.report
    defs = scan_defines(text)
    guard = include_guard(text)
    prefix = pick_prefix(unit, hc, [d.name for d in defs if not d.params and d.name != guard and CENSUS_RE.match(d.comment)])
    regs, consts, spaces = {}, {}, {}
    aliases = {}
    as_const = 0
    for d in defs:
        if d.params or d.name == guard:
            continue
        if not d.name.startswith(prefix + "_"):
            if num_literal(d.body) is not None and d.indent <= 1 and d.name not in aliases:
                foreign_constant(unit, d, res, consts)
            continue
        val = num_literal(d.body)
        m = CENSUS_RE.match(d.comment)
        if val is None or not m:
            continue
        g = CENSUS_GRADE[m.group(1)]
        rest = m.group(2)
        name = d.name[len(prefix) + 1:]
        if d.indent > 1:
            consts[name] = {"value": val, "grade": g}
            continue
        wd = re.search(r"width ([\d/]+) byte", rest)
        acc = re.search(r"width [\d/]+ byte\(s\)(?: at slot\+\d+)?, access (rw|r|w)\b", rest)
        if not (wd and acc) or max(int(x) for x in wd.group(1).split("/")) == 0:
            as_const += 1
            consts[name] = {"value": val, "grade": g}
            if len(d.comment) < 600:
                consts[name]["doc"] = re.sub(r"^\[[EIU]\]\s*", "", d.comment)
            continue
        width = max(int(x) for x in wd.group(1).split("/")) * 8
        win = re.search(r"through the ([\w -]+?) window", rest)
        space = "%s_%s" % (unit, re.sub(r"[^a-z0-9]+", "_", win.group(1).lower()).strip("_")) if win else None
        if "indexed (family base)" in rest:
            twin = [k for k, r in regs.items() if r["offset"] == val and r.get("space") == space]
            if twin:
                aliases[d.name] = "%s_%s" % (prefix, twin[-1].upper())
                continue
        r = {"offset": val, "access": acc.group(1), "width": width, "grade": g, "fields": {}, "tests": []}
        if space:
            r["space"] = space
            spaces.setdefault(space, {"unit": "byte", "doc": "Registers reached through the %s window." % win.group(1)})
        sites = re.search(r"reached in (\d+) sites?, (\d+) routines?", rest)
        if sites:
            r["from"] = "census: %s sites, %s routines" % sites.groups()
        regs[name.lower()] = r
    # the old header already carried "reached in N sites" text, publicly, so a census source may stay public
    src = {"unit": unit, "prefix": prefix, "from": frm, "public_from": ["census:"], "c": {"offset_macro": "bare"}}
    if aliases:
        src["c"]["aliases"] = aliases
    t = TITLE_RE.search(text)
    if t:
        src["title"] = t.group(1)
    if spaces:
        src["spaces"] = spaces
        rep.notes.append("%s: census lines 'through the <name> window' are in their own address space (%s)" % (unit, ", ".join(sorted(spaces))))
    if regs:
        src["registers"] = regs
    if consts:
        src["constants"] = consts
    rep.notes.append("%s: census header; load masks and written constants are constants (probes, not a layout)" % unit)
    if as_const:
        rep.notes.append("%s: %d top-level census lines have no 'width N byte(s), access r|w|rw' in the comment and are carried as constants, not registers"
                         % (unit, as_const))
    return src


def import_table(text, hc, unit, frm, res):
    rep = res.report
    guard = include_guard(text)
    defs = [d for d in scan_defines(text) if not d.params and d.name != guard and num_literal(d.body) is not None]
    prefix = pick_prefix(unit, hc, [d.name for d in defs])
    consts = {}
    for d in defs:
        if not d.name.startswith(prefix + "_"):
            foreign_constant(unit, d, res, consts)
            continue
        m = CENSUS_RE.match(d.comment)
        gm = GRADE_RE.search(d.comment)
        g = CENSUS_GRADE[m.group(1)] if m else (gm.group(1) if gm else None)
        if g is None:
            rep.ungraded.append((unit, d.name, d.body, "no grade in the header"))
            continue
        c = {"value": num_literal(d.body), "grade": g}
        if d.comment and len(d.comment) < 600:
            c["doc"] = re.sub(r"^\[[EIU]\]\s*", "", d.comment)
        consts[d.name[len(prefix) + 1:]] = c
    src = {"unit": unit, "prefix": prefix, "from": frm}
    t = TITLE_RE.search(text)
    if t:
        src["title"] = t.group(1)
    src["constants"] = consts
    return src


# ---------------------------------------------------------------------------
def legacy_tables(hc, unit):
    """Old macro name -> new name for the explicit legacy macro tables."""
    out = {}
    for f, sh, mk in hc.get("macro_pairs", []):
        w, fn = f.split(".")
        out[sh] = "%s_%s_%s_SHIFT" % ("{P}", w, fn.upper())
        out[mk] = "%s_%s_%s_MASK" % ("{P}", w, fn.upper())
    for f, mk in hc.get("inplace", []):
        w, fn = f.split(".")
        out[mk] = "%s_%s_%s_INPLACE" % ("{P}", w, fn.upper())
    return out


def evaluate_old(defs):
    names = {}
    pending = [d for d in defs if not d.params]
    for _ in range(len(pending) + 1):
        left = []
        for d in pending:
            v = eval_c(d.body, names)
            if v is None:
                left.append(d)
            else:
                names[d.name] = v
        if len(left) == len(pending):
            break
        pending = left
    return names


def drop_redundant_constants(unit, src, res):
    """A constant whose macro the register, field or enum rules already generate (`RE_SCRMASK_COUNT`
    beside a register array of that size) would define the macro twice. It is dropped, with the
    report saying so when the generated value is the same, and flagging it as a mismatch when it is not."""
    consts = src.get("constants")
    if not consts:
        return
    bare = copy.deepcopy(src)
    bare.pop("constants")
    try:
        _, names = gen_c.gen_c(normalize(bare), "x")
    except Exception:  # the unit does not render at all; the report of that comes later
        return
    cp = src.get("c", {}).get("const_prefix", src["prefix"])
    for n in list(consts):
        macro = consts[n].get("macro") or "%s_%s" % (cp, n)
        if macro in names:
            if names[macro] == consts[n]["value"]:
                res.report.dropped.append((unit, macro, "the same macro is generated from the layout, with the same value"))
            # a different value is reported by the comparison of old and generated macros (discover_aliases)
            del consts[n]
    if not consts:
        src.pop("constants")


def discover_aliases(unit, src, text, hc, res):
    """Old names that differ from the naming rule become [c.aliases], verified by value."""
    rep = res.report
    model = normalize(src)
    try:
        _, new_names = gen_c.gen_c(model, "x")
    except Exception as e:  # a collision: report and let the migrating agent fix the source
        rep.notes.append("%s: cannot render C to compare names: %s" % (unit, e))
        return
    guard = include_guard(text)
    defs = [d for d in scan_defines(text) if d.name != guard and not d.name.startswith("__")]
    old = evaluate_old(defs)
    table = {k: v.replace("{P}", model["prefix"]) for k, v in legacy_tables(hc, unit).items()}
    aliases = dict(src.get("c", {}).get("aliases", {}))
    known = set(new_names) | set(aliases)
    ungraded = {r[1] for r in rep.ungraded if r[0] == unit}
    todo = []
    for d in defs:
        if d.params:
            continue
        if d.name in new_names:
            if d.name in old and old[d.name] != new_names[d.name]:
                rep.mismatched.append((unit, d.name, hex(old[d.name]), hex(new_names[d.name])))
            continue
        if d.name in aliases or d.name in ungraded:
            continue
        todo.append(d)
    for d in list(todo):
        val = old.get(d.name)
        target = table.get(d.name)
        if target and target in new_names:
            if val is not None and new_names[target] != val:
                rep.mismatched.append((unit, d.name, hex(val), "%s = %s" % (target, hex(new_names[target]))))
            else:
                aliases[d.name] = target
                known.add(d.name)
                todo.remove(d)
                continue
        if val is not None:
            for suf in ("_INPLACE", "_MASK", "_SHIFT", "_OFFSET", "_COUNT"):
                if d.name + suf in new_names and new_names[d.name + suf] == val:
                    aliases[d.name] = d.name + suf
                    known.add(d.name)
                    todo.remove(d)
                    break
    progress = True
    while progress:
        progress = False
        for d in list(todo):
            ids = set(re.findall(r"\b[A-Za-z_]\w*\b", re.sub(r"\b0[xX][0-9a-fA-F]+[uUlL]*\b", "", d.body)))
            ids = {i for i in ids if not re.fullmatch(r"[uUlL]+", i)}
            if d.body and ids and ids <= known:
                aliases[d.name] = d.body
                known.add(d.name)
                todo.remove(d)
                progress = True
    for d in todo:
        rep.unmapped.append((unit, d.name, d.body))
    for old_name, new in sorted(aliases.items()):
        if old_name not in src.get("c", {}).get("aliases", {}):
            rep.aliases.append((unit, old_name, new))
    if aliases:
        src.setdefault("c", {})["aliases"] = aliases


def helpers_from(text, unit, res, guard=None):
    """Function-like macros (with the comment above each) and any C code outside the
    #defines, copied verbatim: they are code, not data."""
    lines = text.splitlines()
    found = [d for d in scan_defines(text) if d.params]
    code = extract_code(text, guard)
    notes = [ln for _kw, ln in unknown_annotation_lines(text)]
    if not found and not code and not notes:
        return None
    body = ["/* Hand-written helpers for %s, carried over from the old header. Included by the generated header; this is code, not data. */" % unit, ""]
    for d in found:
        com = block_comment_before(lines, d.line - 1)
        if com:
            body += ["/*"] + [" * %s" % l if l else " *" for l in com.splitlines()] + [" */"]
        body += d.raw
        res.report.helpers.append((unit, d.name))
    if code:
        if found:
            body.append("")
        body.append(code)
        n = len([l for l in code.splitlines() if l.strip()])
        res.report.helpers.append((unit, "%d lines of C code outside the #defines (check it against the new macro names)" % n))
    if notes:
        body += ["", "/*", " * Annotations the importer does not read, kept verbatim for a repo plugin that does:"] + notes + [" */"]
        res.report.helpers.append((unit, "%d annotation comment lines kept for the repo plugin" % len(notes)))
    return "\n".join(body) + "\n"


# ---------------------------------------------------------------------------
def detect_register_index_spaces(src, unit, res, forced):
    """A space whose registers overlap when counted in bytes but not when counted in registers."""
    spaces = src.get("spaces", {})
    for name in list(spaces):
        if name in forced:
            spaces[name]["unit"] = "reg"
            res.report.spaces.append((unit, "%s (set by --space-unit)" % name))
    trial = normalize(src)
    problems = check_overlap([trial])
    if not problems:
        return
    spaces_used = {r.get("space") for r in src.get("registers", {}).values()}
    for sp in spaces_used:
        if sp is None:
            sp = "%s_regs" % unit
            src.setdefault("spaces", {})[sp] = {"unit": "byte"}
            for r in src["registers"].values():
                if not r.get("space"):
                    r["space"] = sp
        spaces = src["spaces"]
        if spaces.get(sp, {}).get("unit") == "reg":
            continue
        spaces[sp]["unit"] = "reg"
        if check_overlap([normalize(src)]):
            spaces[sp]["unit"] = "byte"
        else:
            res.report.spaces.append((unit, "%s (registers overlap in bytes, not in register indexes)" % sp))
            return


def read_config(root, config_rel):
    path = os.path.join(root, config_rel)
    with open(path, "rb") as f:
        return tomllib.load(f)


def import_repo(root, config_rel="defs.toml", frm=None, space_units=(), names=None):
    cfg = read_config(root, config_rel)
    settings = {"checks": cfg.get("checks", {})}
    res = Result()
    names = names or {}
    taken = set()
    for hc in cfg.get("headers", []):
        rel = hc["file"]
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            text = f.read()
        unit = names.get(rel) or (hc.get("module") if re.match(r"^[a-z][a-z0-9_]*$", hc.get("module") or "") else None) \
            or unit_name_for(rel, taken)
        taken.add(unit)
        kind = classify(text)
        if kind != "decode" or not (hc.get("block") or any(REG_RE.match(ln) for ln in text.splitlines() if "<" not in ln)):
            res.no_prose_check.add(unit)
            res.report.notes.append("%s: the old check did not scan this header for spelled-out register offsets; written as prose_offsets = false" % unit)
        src_from = frm or "imported from %s; the source was not recorded" % os.path.basename(rel)
        hc = copy.deepcopy(hc)
        if kind == "decode":
            src = import_decode(text, hc, unit, src_from, res, space_units)
        elif kind == "census":
            src = import_census(text, hc, unit, src_from, res)
        else:
            src = import_table(text, hc, unit, src_from, res)
            res.report.notes.append("%s: %s has no REG, FIELD or census annotations; imported its graded constants only" % (unit, rel))
        t = TITLE_RE.search(text)
        if t and not src.get("title"):
            src["title"] = t.group(1)
        src.setdefault("c", {})["legacy_header"] = rel
        guard = include_guard(text)
        if guard:
            src["c"]["legacy_guard"] = guard
        detect_register_index_spaces(src, unit, res, set(space_units))
        drop_redundant_constants(unit, src, res)
        helpers = helpers_from(text, unit, res, guard)
        for kw, n in sorted(unknown_annotations(text).items()):
            res.report.notes.append("%s: %d comment lines starting '%s:' are not data the importer reads; kept verbatim in %s_helpers.h" % (unit, n, kw, unit))
        if helpers:
            res.helpers[unit] = helpers
        discover_aliases(unit, src, text, hc, res)
        res.units[unit] = src
        res.header_of[unit] = rel
        for p in check_unit(normalize(src), settings):
            res.report.notes.append("layout: " + p)
    res.check = check_settings(cfg, res)
    return res


def check_settings(cfg, res):
    """defs/check.toml: what defs.toml held, minus the header list."""
    out = {"project": {k: v for k, v in cfg.get("project", {}).items() if k in ("name", "plugin")}}
    for sect in ("checks", "banned", "allowlists", "docs_scan"):
        if cfg.get(sect):
            out[sect] = copy.deepcopy(cfg[sect])
    rust_extra = cfg.get("rust", {}).get("banned_extra", [])
    if rust_extra:
        out.setdefault("banned", {}).setdefault("extra", []).extend(rust_extra)
        res.report.notes.append("[rust] banned_extra moved to [[banned.extra]]; it now applies to every generated output")
    units = {}
    for hc in cfg.get("headers", []):
        unit = next((u for u, rel in res.header_of.items() if rel == hc["file"]), None)
        if not unit:
            continue
        u = {"group": hc.get("group", os.path.basename(hc["file"]))}
        for k in ("notes_corpus", "no_addresses", "size_limit_macro", "address_field_prefix"):
            if k in hc:
                u[k] = hc[k]
        if hc.get("form") == "legacy":
            u["plugin_form"] = "legacy"
        if unit in res.no_prose_check:
            u["prose_offsets"] = False
        units[unit] = u
    if units:
        out["units"] = units
    if cfg.get("claims"):
        out["claims"] = copy.deepcopy(cfg["claims"])
    return out


def write_current(root, res, force=False):
    """Write the sources in the current layout: devices/<unit>/registers.toml and helpers.h, and
    tools/config/defs-check.toml. Returns the files written."""
    written = []

    def put(rel, text):
        path = os.path.join(root, rel)
        if os.path.exists(path) and not force:
            raise FileExistsError("%s exists; pass --force to overwrite" % rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        written.append(rel)
    for unit, src in res.units.items():
        put("devices/%s/registers.toml" % unit,
            toml_emit.emit_unit(normalize(src), "# Imported from %s. Review the sources and grades, then maintain by hand." % res.header_of[unit]))
    for unit, text in res.helpers.items():
        put("devices/%s/helpers.h" % unit, text)
    put("tools/config/defs-check.toml", toml_emit.emit_check(res.check))
    return written


def write_result(root, res, out_dir="defs", force=False):
    """Write sources, helpers and check.toml into one flat directory (the old layout); return the files written."""
    base = os.path.join(root, out_dir)
    os.makedirs(base, exist_ok=True)
    written = []

    def put(rel, text):
        path = os.path.join(base, rel)
        if os.path.exists(path) and not force:
            raise FileExistsError("%s exists; pass --force to overwrite" % os.path.join(out_dir, rel))
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        written.append(os.path.join(out_dir, rel))
    for unit, src in res.units.items():
        put("%s.toml" % unit, toml_emit.emit_unit(normalize(src), "# Imported from %s. Review the sources and grades, then maintain by hand." % res.header_of[unit]))
    for unit, text in res.helpers.items():
        put("%s_helpers.h" % unit, text)
    put("check.toml", toml_emit.emit_check(res.check))
    return written
