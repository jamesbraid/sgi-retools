"""QEMU headers: one per unit, in the hw/registerfields.h style, every name prefixed with board and unit.

  REG8/16/32/64(<P>_<REG>, byte offset)        a register; a register array adds <P>_<REG>_COUNT and _STRIDE (bytes)
  FIELD(<P>_<REG>, <FIELD>, shift, length)     a field; a word (a command or descriptor, no offset) has fields only
  #define <P>_<NAME> value                     a constant

<P> is the board prefix and the unit name from [gen.qemu] in defs-check.toml, so the headers of several
repositories can share one translation unit (defs-names dups checks that they do). The grade is a trailing
comment, and so is the name provenance of an item that differs from its unit's. A unit in a register-indexed
space is written in bytes: offset = index * register size.
"""
import re

from .genutil import GenError, banner, lit, one_line
from .model import name_source

QEMU_DIR = "qemu"
DEFAULT_INCLUDE = "hw/core/registerfields.h"
WIDE = {8: "REG8", 16: "REG16", 32: "REG32", 64: "REG64"}
SIZE = {"REG8": 1, "REG16": 2, "REG32": 4, "REG64": 8}
MAX_OFFSET = 0x7fffffff         # the offsets become enumerators

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


def gen_qemu(m, src, board, name, include=None):
    P = "%s_%s" % (board, name or m["unit"].upper())
    guard = "HW_SGI_GPU_%s_REGS_H" % P
    unit_src = _src(m, None)
    out = [banner(src), "/* %s */" % one_line(m.get("title") or m["unit"]),
           "/* Names are %s; name source: %s. */" % (P + "_*", unit_src)]
    if any(r["space"] and m["spaces"][r["space"]]["unit"] == "reg" for r in m["registers"].values()):
        out.append("/* Offsets are bytes; registers of a register-indexed space are written as index * size. */")
    out += ["#ifndef %s\n#define %s\n" % (guard, guard), '#include "%s"' % (include or DEFAULT_INCLUDE)]

    def tail(node, extra=""):
        t = [node["grade"]] if node.get("grade") else []
        if node.get("name_source") and _src(m, node) != unit_src:
            t.append("name source: " + _src(m, node))
        return " /* %s%s */" % ("; ".join(t), extra)

    def fields(reg, node):
        for fn, f in node["fields"].items():
            hi, lo = f["bits"]
            out.append("FIELD(%s, %s, %d, %d)%s" % (reg, fn.upper(), lo, hi - lo + 1, tail(f)))

    for n, r in m["registers"].items():
        reg = "%s_%s" % (P, n.upper())
        in_regs = r["space"] and m["spaces"][r["space"]]["unit"] == "reg"
        size = r["width"] // 8
        off = r["offset"] * size if in_regs else r["offset"]
        if off + max(r["count"] - 1, 0) * (r["stride"] * size if in_regs else r["stride"]) > MAX_OFFSET:
            raise GenError("%s: register %s lies beyond 0x%x" % (m["unit"], n, MAX_OFFSET))
        out.append("")
        out.append("%s(%s, 0x%x)%s" % (WIDE[r["width"]], reg, off, tail(r)))
        if r["count"] > 1:
            out.append("#define %s_COUNT %d" % (reg, r["count"]))
            out.append("#define %s_STRIDE 0x%x" % (reg, r["stride"] * size if in_regs else r["stride"]))
        fields(reg, r)
    for n, w in m["words"].items():
        reg = "%s_%s" % (P, n)
        out.append("")
        out.append("#define %s_WIDTH %d%s" % (reg, w["width"], tail(w, "; word")))
        fields(reg, w)
    if m["constants"]:
        out.append("")
    for n, k in m["constants"].items():
        c = "%s_%s" % (P, n)
        if k.get("count", 1) > 1:
            out.append("#define %s(i) (%s + (i) * %d)%s" % (c, lit(k["value"]), k.get("stride", 1), tail(k)))
            out.append("#define %s_COUNT %d" % (c, k["count"]))
        else:
            out.append("#define %s %s%s" % (c, lit(k["value"]), tail(k)))
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
