"""QEMU headers: one per unit, in the hw/registerfields.h style, every name prefixed with board and unit.

  REG8/16/32/64(<P>_<REG>, byte offset)        a register; a register array adds <P>_<REG>_COUNT and _STRIDE (bytes)
  FIELD(<P>_<REG>, <FIELD>, shift, length)     a field; a word (a command or descriptor, no offset) has fields only
  #define <P>_<REG>_RESET | _RO | _W1C | _COR | _RSVD   reset value and bit masks, where the register has them
  #define <P>_<REG>_<FIELD>_<LABEL> value              a field's enum value
  #define <P>_<REG>_INDEX n                            a register of a register-indexed space, in place of REG*
  #define <P>_<NAME> value                     a constant

<P> is the board prefix and the unit name from [gen.qemu] in defs-check.toml, so the headers of several
repositories can share one translation unit (defs-names dups checks that they do). The grade is a trailing
comment, and so is the name provenance of an item that differs from its unit's. The masks mean what QEMU's
RegisterAccessInfo members of the same names do. A register-indexed space has no byte offset: its register
is the plain index and _STRIDE counts indices; FIELD does not need the REG anchor, so fields are unchanged.
A header is refused while any name in the unit is still imported-unchecked.
"""
import re

from .genutil import COMMENT_WIDTH, GenError, banner, lit, one_line, wrap_comment
from .model import enum_values, items, name_source

QEMU_DIR = "qemu"
DEFAULT_INCLUDE = "hw/core/registerfields.h"
WIDE = {8: "REG8", 16: "REG16", 32: "REG32", 64: "REG64"}
SIZE = {"REG8": 1, "REG16": 2, "REG32": 4, "REG64": 8}
MAX_OFFSET = 0x7fffffff         # the offsets become enumerators
MASKS = ("ro", "w1c", "cor", "rsvd")
UNCHECKED_SHOWN = 8

REG_RE = re.compile(r"^(REG(?:8|16|32|64))\((\w+), ", re.M)
FIELD_RE = re.compile(r"^FIELD\((\w+), (\w+), ", re.M)
DEFINE_RE = re.compile(r"^#define (\w+)", re.M)


def identifiers(text):
    """Every C identifier a QEMU header defines, as registerfields.h expands it."""
    out = [d for d in DEFINE_RE.findall(text)]
    for _w, reg in REG_RE.findall(text):
        out += ["A_" + reg, "R_" + reg]
    for reg, f in FIELD_RE.findall(text):
        out += ["R_%s_%s_%s" % (reg, f, s) for s in ("SHIFT", "LENGTH", "MASK")]
    return out


def _src(u, node):
    s, cite = name_source(u, node)
    return s + (" (%s)" % one_line(cite) if cite else "")


def unchecked(m):
    """Names of the unit's registers, words, fields and constants whose source is still imported-unchecked
    (a field without its own source takes its register's)."""
    return [n for _k, n, node, parent, _w in items(m)
            if name_source(m, node if node.get("name_source") else parent)[0] == "imported-unchecked"]


def gen_qemu(m, src, board, name, include=None):
    bad = unchecked(m)
    if bad:
        raise GenError("%s: %d name(s) are imported-unchecked, so no QEMU header is written; give them a name_source: %s%s"
                       % (m["unit"], len(bad), ", ".join(bad[:UNCHECKED_SHOWN]),
                          ", ..." if len(bad) > UNCHECKED_SHOWN else ""))
    P = "%s_%s" % (board, name or m["unit"].upper())
    guard = "HW_SGI_GPU_%s_REGS_H" % P
    unit_src = _src(m, None)
    out = [*wrap_comment(banner(src, "", "").strip()), *wrap_comment(m.get("title") or m["unit"]),
           *wrap_comment("Names are %s; name source: %s." % (P + "_*", unit_src))]
    if any(r["space"] and m["spaces"][r["space"]]["unit"] == "reg" for r in m["registers"].values()):
        out += wrap_comment("A register-indexed space has _INDEX numbers, not byte offsets.")
    out += ["#ifndef %s\n#define %s\n" % (guard, guard), '#include "%s"' % (include or DEFAULT_INCLUDE)]

    def tail(node, extra=""):
        t = [node["grade"]] if node.get("grade") else []
        if node.get("name_source") and _src(m, node) != unit_src:
            t.append("name source: " + _src(m, node))
        return "; ".join(t) + extra

    def put(line, note):
        """The line with its note beside it, or the note above it when that passes 80 columns."""
        if not note:
            out.append(line)
        elif len(line) + len(note) + 6 <= COMMENT_WIDTH:
            out.append("%s /* %s */" % (line, note))
        else:
            out.extend(wrap_comment(note))
            out.append(line)

    def fields(reg, node):
        for fn, f in node["fields"].items():
            hi, lo = f["bits"]
            put("FIELD(%s, %s, %d, %d)" % (reg, fn.upper(), lo, hi - lo + 1), tail(f))
            for lab, ev in enum_values(m, f).items():
                put("#define %s_%s_%s %d" % (reg, fn.upper(), lab.upper(), ev["value"]), tail(ev))

    for n, r in m["registers"].items():
        reg = "%s_%s" % (P, n.upper())
        in_regs = r["space"] and m["spaces"][r["space"]]["unit"] == "reg"
        wide = r["width"] == 64
        if not in_regs and r["offset"] + max(r["count"] - 1, 0) * r["stride"] > MAX_OFFSET:
            raise GenError("%s: register %s lies beyond 0x%x" % (m["unit"], n, MAX_OFFSET))
        out.append("")
        if in_regs:
            put("#define %s_INDEX %d" % (reg, r["offset"]), tail(r))
        else:
            put("%s(%s, 0x%x)" % (WIDE[r["width"]], reg, r["offset"]), tail(r))
        if r["count"] > 1:
            out.append("#define %s_COUNT %d" % (reg, r["count"]))
            out.append("#define %s_STRIDE %s" % (reg, r["stride"] if in_regs else "0x%x" % r["stride"]))
        if isinstance(r["reset"], int):
            put("#define %s_RESET %s" % (reg, lit(r["reset"], wide)), r.get("reset_grade", r["grade"]))
        for k in MASKS:
            if r.get(k):
                put("#define %s_%s %s" % (reg, k.upper(), lit(r[k], wide)), r["grade"])
        fields(reg, r)
    for n, w in m["words"].items():
        reg = "%s_%s" % (P, n)
        out.append("")
        put("#define %s_WIDTH %d" % (reg, w["width"]), tail(w, "; word"))
        fields(reg, w)
    if m["constants"]:
        out.append("")
    for n, k in m["constants"].items():
        c = "%s_%s" % (P, n)
        if k.get("count", 1) > 1:
            put("#define %s(i) (%s + (i) * %d)" % (c, lit(k["value"]), k.get("stride", 1)), tail(k))
            out.append("#define %s_COUNT %d" % (c, k["count"]))
        else:
            put("#define %s %s" % (c, lit(k["value"])), tail(k))
    out.append("\n#endif /* %s */\n" % guard)
    text = "\n".join(out)
    seen = {}
    for i in identifiers(text):
        if i in seen:
            raise GenError("%s: %s is defined twice in the QEMU header" % (m["unit"], i))
        seen[i] = True
    return text


def render_qemu(repo, models):
    """Return ({relative path: text}, [errors]) for the units [gen.qemu] names."""
    cfg = repo.settings.get("gen", {}).get("qemu")
    files, errors = {}, []
    if not cfg:
        return files, errors
    for name, ucfg in sorted(cfg["units"].items()):
        if name not in models:
            errors.append("gen.qemu.units.%s: not a unit" % name)
            continue
        try:
            files["%s/%s/%s.h" % (repo.layout.gen_root(), QEMU_DIR, name)] = gen_qemu(
                models[name], repo.units[name].path, cfg["board"], ucfg.get("name"), cfg.get("include"))
        except GenError as e:
            errors.append(str(e))
    return files, errors
