"""C header per unit, a self-test program and the forwarding header.

The header names follow one rule:

  <BLOCK>_<REG>_OFFSET | <BLOCK>_<REG>_COUNT | _STRIDE      registers
  <BLOCK>_<REG>_<FIELD>_SHIFT | _MASK | _INPLACE            fields of a register
  <PREFIX>_<WORD>_WIDTH, <PREFIX>_<WORD>_<FIELD>_SHIFT ...  non-register words
  <FIELD macro>_<LABEL>                                     a field's own enum values
  <PREFIX>_<ENUM>_<LABEL>                                   shared enum values
  <CONST PREFIX>_<NAME>                                     constants

`[c] offset_macro = "bare"` drops the _OFFSET suffix. A hand-written
defs/<unit>_helpers.h, when present, is included at the end.
"""
import os

from .genutil import GenError, banner, cblock, field_macro, lit, one_line
from .model import block_of, eff_from, mask


def gen_c(u, src, helpers_include=None):
    """Return (text, names) where names maps every object-like macro to its value."""
    P = u["prefix"]
    CP = u["c"].get("const_prefix", P)
    names, out = {}, []

    def d(name, val, intval, grade=None, extra=""):
        if name in names:
            raise GenError("%s: C macro %s is defined twice%s" % (u["unit"], name, extra))
        names[name] = intval
        c = " /* %s%s */" % (grade, extra) if grade else (" /* %s */" % extra if extra else "")
        out.append("#define %-44s %s%s" % (name, val, c))

    out.append(banner(src))
    out.append("/* %s */" % one_line(u.get("title") or u["unit"]))
    out.append("#ifndef %s_GEN_H\n#define %s_GEN_H\n" % (P, P))
    out.append("#include <stdint.h>\n")

    def emit_fields(kind, owner, node, wide):
        for fn, f in node["fields"].items():
            hi, lo = f["bits"]
            m = field_macro(u, kind, owner, fn)
            fm = mask(hi - lo + 1)
            d(m + "_SHIFT", str(lo), lo, f["grade"])
            d(m + "_MASK", lit(fm, wide), fm)
            d(m + "_INPLACE", "(%s_MASK << %s_SHIFT)" % (m, m), fm << lo)
            for lab, ev in (f.get("enums") or {}).items():
                d("%s_%s" % (m, lab.upper()), str(ev["value"]), ev["value"], ev["grade"])

    for en, e in u["enums"].items():
        out.append("")
        out.append("/* enum %s%s */" % (en, ": " + one_line(e["doc"]) if e.get("doc") else ""))
        for lab, ev in e["values"].items():
            d("%s_%s_%s" % (P, en.upper(), lab.upper()), str(ev["value"]), ev["value"], ev["grade"])
    for n, r in u["registers"].items():
        out.append("")
        if r.get("doc"):
            out.append(cblock(r["doc"]).rstrip())
        c = eff_from(u, r)
        sp = ", space %s" % r["space"] if r["space"] else ""
        out.append("/* %s: %s%d%s, reset %s%s */" % (n, r["access"], r["width"], sp,
                                                     "unknown" if r["reset"] == "unknown" else hex(r["reset"]),
                                                     "; " + one_line(c) if c else ""))
        base = "%s_%s" % (block_of(u), n.upper())
        bare = u["c"]["offset_macro"] == "bare"
        d(base if bare else base + "_OFFSET", "0x%06x" % r["offset"] if bare else lit(r["offset"]), r["offset"], r["grade"])
        if r["count"] > 1:
            d(base + "_COUNT", str(r["count"]), r["count"])
            d(base + "_STRIDE", str(r["stride"]), r["stride"])
        emit_fields("register", n, r, r["width"] == 64)
    for n, w in u["words"].items():
        out.append("")
        if w.get("doc"):
            out.append(cblock(w["doc"]).rstrip())
        c = eff_from(u, w)
        out.append("/* word %s: %d bits%s */" % (n, w["width"], "; " + one_line(c) if c else ""))
        d("%s_%s_WIDTH" % (P, n), str(w["width"]), w["width"], w["grade"])
        emit_fields("word", n, w, w["width"] == 64)
    if u["constants"]:
        out.append("")
    for n, k in u["constants"].items():
        macro = k.get("macro") or "%s_%s" % (CP, n)      # `macro` names the C macro in full when the prefix rule does not fit
        if k.get("count", 1) > 1:
            name = "%s(i)" % macro
            if name in names:
                raise GenError("%s: C macro %s is defined twice" % (u["unit"], name))
            out.append("#define %-44s (%s + (i) * %d) /* %s */" % (name, lit(k["value"]), k.get("stride", 1), k["grade"]))
            names[name] = None
            d("%s_COUNT" % macro, str(k["count"]), k["count"])
        else:
            d(macro, lit(k["value"]), k["value"], k["grade"])
    if helpers_include:
        out.append("\n/* hand-written helper macros */")
        out.append('#include "%s"' % helpers_include)
    out.append("\n#endif /* %s_GEN_H */\n" % P)
    return "\n".join(out), {k: v for k, v in names.items() if v is not None}


def helpers_rel(unit_name):
    """Path from gen/c/<unit>.h to defs/<unit>_helpers.h."""
    return "../../defs/%s_helpers.h" % unit_name


def gen_c_test(u, hdr):
    """A C program that decodes every vector with the generated macros."""
    out = ["/* generated self-test: every vector decodes with the generated macros */",
           '#include <stdio.h>\n#include "%s"\n' % hdr,
           "static int fails;",
           "#define CK(v, sh, mk, want, what) do { unsigned long long g = ((unsigned long long)(v) >> (sh)) & (mk); \\",
           "  if (g != (unsigned long long)(want)) { printf(\"FAIL %s: got %llu want %llu\\n\", what, g, (unsigned long long)(want)); fails++; } } while (0)",
           "int main(void)\n{"]
    n = 0
    for sect, kind in (("registers", "register"), ("words", "word")):
        for name, node in u[sect].items():
            for t in node["tests"]:
                if t["kind"] != "vector":
                    continue
                for fn, want in t["expect"].items():
                    m = field_macro(u, kind, name, fn)
                    out.append("    CK(%s, %s_SHIFT, %s_MASK, %d, \"%s.%s @0x%x\");"
                               % (lit(t["value"], node["width"] == 64), m, m, want, name, fn, t["value"]))
                    n += 1
    out.append("    printf(\"%s: %d C field checks, %%d failed\\n\", fails);\n    return fails != 0;\n}\n" % (u["unit"], n))
    return "\n".join(out)


def gen_forwarding(u, src, c_rel_from_legacy):
    """The header left at an old path: it includes the generated one and
    defines the old names that differ from the naming rule. Each alias value
    is a C expression over the new names."""
    c = u["c"]
    guard = c.get("legacy_guard") or "%s_FWD_H" % u["prefix"]
    out = [banner(src),
           "/* Transition header: include %s instead. It keeps the names this header" % c_rel_from_legacy,
           " * had before the definitions moved to generated headers. */",
           "#ifndef %s\n#define %s\n" % (guard, guard),
           '#include "%s"' % c_rel_from_legacy]
    if c["aliases"]:
        out.append("")
        for old, expr in sorted(c["aliases"].items()):
            out.append("#define %-44s %s" % (old, expr))
    out.append("\n#endif /* %s */\n" % guard)
    return "\n".join(out)


def rel_include(from_file, to_file):
    return os.path.relpath(to_file, os.path.dirname(from_file) or ".")
