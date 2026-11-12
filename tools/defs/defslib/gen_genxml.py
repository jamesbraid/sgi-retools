"""Export a unit in the Intel/Mesa genxml dialect (as Asahi and Panfrost use it).

Words and registers become <struct> elements (size in bytes) whose <field>
elements carry start, size and type; enums are top-level <enum> elements.
Everything genxml has no place for rides in extra attributes and elements
that the upstream generators ignore: grade and from on every item, offset,
access, count, stride, space and reset on a register struct, <constant>,
<space> and <test> elements. No extension uses the element names the
upstream parser acts on (genxml, struct, field, enum, value).

Where the vendored pack generator needs the export to adjust, the export
adjusts: it reads a `uint` field of exactly 33 bits as a 32-bit integer, so
that width is written as type "address", which it keeps in 64 bits.
"""
import re
import xml.sax.saxutils as sx

from .genutil import GenError, banner
from .model import block_of, eff_from, fwidth, mask


C_KEYWORDS = {"auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern",
              "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short",
              "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
              "while", "bool", "true", "false"}


def cfield(name):
    """The C struct member the upstream generator writes for a field: it takes the name as it is, so a C keyword
    gets an underscore here, in the export."""
    return name + "_" if name in C_KEYWORDS else name


def _q(v):
    return sx.quoteattr(str(v))


def _attrs(**kw):
    return " ".join("%s=%s" % (k.replace("_", "-") if k == "public_from" else k, _q(v))
                    for k, v in kw.items() if v is not None)


def _ftype(f, enum_name):
    if enum_name:
        return enum_name
    return "address" if fwidth(f) == 33 else "uint"


def gen_genxml(u, src):
    o = ['<?xml version="1.0" ?>', "<!-- %s -->" % banner(src, "", "").strip()]
    o.append("<genxml %s>" % _attrs(unit=u["unit"], prefix=u["prefix"], block=block_of(u) if u.get("block") else None,
                                    title=u.get("title") or None, **{"from": eff_from(u, u) if u.get("from") else None}))
    if u.get("doc"):
        o.append("  <doc>%s</doc>" % sx.escape(u["doc"]))
    for n, sp in u["spaces"].items():
        o.append("  <space %s/>" % _attrs(name=n, unit=sp["unit"]))
    enum_names = set()

    def enum_block(name, vals, doc=""):
        if name in enum_names:
            raise GenError("%s: genxml enum name %s is used twice" % (u["unit"], name))
        enum_names.add(name)
        o.append("  <enum %s>" % _attrs(name=name))
        for lab, ev in vals.items():
            o.append("    <value %s/>" % _attrs(name=lab, value=ev["value"], grade=ev["grade"], **{"from": ev.get("from")}))
        o.append("  </enum>")

    for en, e in u["enums"].items():
        enum_block(en, e["values"])
    inline = {}
    for sect in ("registers", "words"):
        for n, x in u[sect].items():
            for fn, f in x["fields"].items():
                if f.get("enums"):
                    nm = "%s_%s" % (n.lower(), fn)
                    inline[(n, fn)] = nm
                    enum_block(nm, f["enums"])
    names = set()
    for sect in ("registers", "words"):
        for n, x in u[sect].items():
            sname = n.upper()
            if sname in names:
                raise GenError("%s: genxml struct name %s is used twice" % (u["unit"], sname))
            names.add(sname)
            extra = {}
            if sect == "registers":
                extra = dict(register="yes", offset="0x%x" % x["offset"], access=x["access"], count=x["count"] if x["count"] > 1 else None,
                             stride=x["stride"] if x["count"] > 1 else None, space=x["space"],
                             reset=("0x%x" % x["reset"]) if isinstance(x["reset"], int) else "unknown")
            o.append("  <struct %s>" % _attrs(name=sname, size=x["width"] // 8, grade=x["grade"],
                                              **{"from": eff_from(u, x)}, **extra))
            if x.get("doc"):
                o.append("    <doc>%s</doc>" % sx.escape(x["doc"]))
            for fn, f in x["fields"].items():
                hi, lo = f["bits"]
                en = f.get("enum") or inline.get((n, fn))
                o.append("    <field %s/>" % _attrs(name=cfield(fn), start=lo, size=hi - lo + 1, type=_ftype(f, en), grade=f["grade"],
                                                    **{"from": f.get("from")}))
            for t in x["tests"]:
                o.append("    <test %s>" % _attrs(value="0x%x" % t["value"], kind=t["kind"]))
                for fn, v in t["expect"].items():
                    o.append("      <expect %s/>" % _attrs(field=fn, value=v))
                o.append("    </test>")
            o.append("  </struct>")
    for n, k in u["constants"].items():
        o.append("  <constant %s/>" % _attrs(name=n, value="0x%x" % k["value"], grade=k["grade"], count=k.get("count"),
                                             stride=k.get("stride") if k.get("count") else None, **{"from": k.get("from")}))
    o.append("</genxml>")
    return "\n".join(o) + "\n"


def _cname(s):
    return re.sub(r"\W", "_", s)


def genxml_selftest_c(u, pack_header):
    """A C program over the header the upstream generator wrote: every vector
    is unpacked, compared with its stated fields, and packed back to the same
    bits (those covered by a field)."""
    out = ["/* generated: unpack, compare and repack every vector through the upstream pack code */",
           '#include "%s"' % pack_header, "static int fails;",
           "#define CHK(c, what) do { if (!(c)) { printf(\"FAIL %s\\n\", what); fails++; } } while (0)",
           "int main(void)\n{"]
    n = 0
    for sect in ("registers", "words"):
        for name, x in u[sect].items():
            st = "AGX_%s" % _cname(name.upper())
            covered = 0
            for f in x["fields"].values():
                covered |= mask(fwidth(f)) << f["bits"][1]
            for t in x["tests"]:
                if t["kind"] != "vector":
                    continue
                v = t["value"]
                out.append("    {")
                out.append("        uint32_t in[2] = { 0x%xu, 0x%xu }, back[2] = { 0, 0 };" % (v & 0xffffffff, v >> 32))
                out.append("        struct %s s;" % st)
                out.append("        %s_unpack(NULL, (const uint8_t *)in, &s);" % st)
                for fn, want in t["expect"].items():
                    out.append("        CHK((uint64_t)s.%s == %dull, \"%s.%s unpack 0x%x\");" % (cfield(fn), want, name, fn, v))
                    n += 1
                out.append("        %s_pack(back, &s);" % st)
                out.append("        CHK((((uint64_t)back[1] << 32) | back[0]) == 0x%xull, \"%s repack 0x%x\");" % (v & covered, name, v))
                out.append("    }")
                n += 1
    out.append("    printf(\"%s: %d genxml checks, %%d failed\\n\", fails);\n    return fails != 0;\n}\n" % (u["unit"], n))
    return "\n".join(out)
