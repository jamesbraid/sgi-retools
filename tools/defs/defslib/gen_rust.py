"""One Rust crate (gen/rust) with a module per unit.

Per register or word: a module with OFFSET, WIDTH, COUNT and STRIDE constants,
and per field a module with SHIFT, MASK, get and set, plus an enum type with an
`Other` variant where the field has values. Constants become `pub const`; an
indexed constant family becomes a function. Every test vector becomes a test.
"""
import re

from .genutil import banner, one_line
from .model import fwidth, mask

RUST_KW = {"as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if", "impl",
           "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static", "struct", "super",
           "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become",
           "box", "do", "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "self",
           "Self"}


def rid(s):
    return "r#" + s if s in RUST_KW and s not in ("self", "Self", "super", "crate") else (s + "_" if s in RUST_KW else s)


def rconst(label):
    s = label.upper()
    return "V" + s if s[0].isdigit() else s


def rvariant(label):
    s = "".join(p.capitalize() for p in label.split("_"))
    s = "V" + s if s[0].isdigit() else s
    return s + "_" if s == "Self" else s


def variants(vals):
    """One Rust variant name per enum label. Two labels can reduce to the same name (k9_6 and k96 both
    give K96), which rustc refuses; the later one takes its value as a suffix."""
    out, seen = {}, set()
    for lab, ev in vals.items():
        v = rvariant(lab)
        if v in seen:
            v = "%s_%d" % (v, ev["value"])
        seen.add(v)
        out[lab] = v
    return out


def _enum_block(ty, vals, pad):
    vn = variants(vals)
    o = []
    for lab, ev in vals.items():
        o.append("%spub const %s: %s = %d; // %s" % (pad, rconst(lab), ty, ev["value"], ev["grade"]))
    o.append("%s#[derive(Debug, Clone, Copy, PartialEq, Eq)]" % pad)
    o.append("%spub enum Value {" % pad)
    for lab in vals:
        o.append("%s    %s," % (pad, vn[lab]))
    o.append("%s    Other(%s)," % (pad, ty))
    o.append("%s}" % pad)
    o.append("%simpl Value {" % pad)
    o.append("%s    pub const fn from_raw(v: %s) -> Self {" % (pad, ty))
    o.append("%s        match v {" % pad)
    for lab, ev in vals.items():
        o.append("%s            %d => Self::%s," % (pad, ev["value"], vn[lab]))
    o.append("%s            _ => Self::Other(v)," % pad)
    o.append("%s        }" % pad)
    o.append("%s    }" % pad)
    o.append("%s    pub const fn raw(self) -> %s {" % (pad, ty))
    o.append("%s        match self {" % pad)
    for lab, ev in vals.items():
        o.append("%s            Self::%s => %d," % (pad, vn[lab], ev["value"]))
    o.append("%s            Self::Other(v) => v," % pad)
    o.append("%s        }" % pad)
    o.append("%s    }" % pad)
    o.append("%s}" % pad)
    return o


def _fields(node, ty, indent="    "):
    o = []
    for fn, f in node["fields"].items():
        hi, lo = f["bits"]
        o.append("%spub mod %s { // bits %d:%d, %s" % (indent, rid(fn), hi, lo, f["grade"]))
        o.append("%s    pub const SHIFT: u32 = %d;" % (indent, lo))
        o.append("%s    pub const MASK: %s = 0x%x;" % (indent, ty, mask(hi - lo + 1)))
        o.append("%s    pub const fn get(v: %s) -> %s {" % (indent, ty, ty))
        o.append("%s        (v >> SHIFT) & MASK" % indent)
        o.append("%s    }" % indent)
        o.append("%s    pub const fn set(v: %s, x: %s) -> %s {" % (indent, ty, ty, ty))
        o.append("%s        (v & !(MASK << SHIFT)) | ((x & MASK) << SHIFT)" % indent)
        o.append("%s    }" % indent)
        if f.get("enums"):
            o += _enum_block(ty, f["enums"], indent + "    ")
        elif f.get("enum"):
            o.append("%s    pub use super::super::enums::%s::Value;" % (indent, rid(f["enum"])))
        o.append("%s}" % indent)
    return o


def _shared_enum_fields(u, en):
    return [f for sect in ("registers", "words") for x in u[sect].values() for f in x["fields"].values() if f.get("enum") == en]


def gen_rust(u, src):
    out = ["// " + banner(src, "", "").strip(), "// " + one_line(u.get("title", "")), "#![allow(dead_code)]", ""]
    if u["enums"]:
        out.append("pub mod enums {")
        for en, e in u["enums"].items():
            maxbits = max([fwidth(f) for f in _shared_enum_fields(u, en)] or [32])
            ty = "u64" if maxbits > 32 else "u32"
            out.append("    pub mod %s {" % rid(en))
            out += _enum_block(ty, e["values"], "        ")
            out.append("    }")
        out.append("}\n")
    for sect in ("registers", "words"):
        for n, x in u[sect].items():
            ty = "u64" if x["width"] == 64 else "u32"
            doc = one_line(x.get("doc", ""))[:150]
            out.append("/// %s(%s)" % (doc + " " if doc else "", x["grade"]))
            out.append("pub mod %s {" % rid(n.lower()))
            out.append("    pub const WIDTH: u32 = %d;" % x["width"])
            if sect == "registers":
                out.append("    pub const OFFSET: u64 = 0x%x;" % x["offset"])
                if x["count"] > 1:
                    out.append("    pub const COUNT: u32 = %d;\n    pub const STRIDE: u64 = %d;" % (x["count"], x["stride"]))
            out += _fields(x, ty)
            out.append("}")
    for n, k in u["constants"].items():
        ty = "u64" if k["value"] > 0xffffffff else "u32"
        name = ("N" + n) if n[0].isdigit() else n
        if k.get("count", 1) > 1:
            out.append("pub const fn %s(i: %s) -> %s {\n    0x%x + i * %d\n}" % (name.lower(), ty, ty, k["value"], k.get("stride", 1)))
            out.append("pub const %s_COUNT: u32 = %d;" % (name, k["count"]))
        else:
            out.append("pub const %s: %s = 0x%x; // %s" % (name, ty, k["value"], k["grade"]))
    tests = []
    for sect in ("registers", "words"):
        for n, x in u[sect].items():
            for t in x["tests"]:
                if t["kind"] != "vector":
                    continue
                body = ["        assert_eq!(%s::%s::get(0x%x), %d);" % (rid(n.lower()), rid(fn), t["value"], v)
                        for fn, v in t["expect"].items()]
                tests.append("    #[test]\n    fn %s_%x() {\n%s\n    }" % (re.sub(r"\W", "_", n.lower()), t["value"], "\n".join(body)))
    if tests:
        out.append("\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n" + "\n\n".join(tests) + "\n}")
    return "\n".join(out) + "\n"


DEFAULT_CRATE = "hwdefs"


def crate_name(name=None):
    """The crate is named neutrally by default: a generated crate must not name its project."""
    return re.sub(r"[^a-z0-9_-]", "-", (name or DEFAULT_CRATE).lower())


def gen_cargo(name, label):
    return ("# " + banner(label, "", "").strip() + "\n[package]\nname = \"%s\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
            "publish = false\n\n[lib]\npath = \"src/lib.rs\"\n" % crate_name(name))


def gen_lib(unit_names, label):
    return "// %s\n%s" % (banner(label, "", "").strip(), "".join("pub mod %s;\n" % n for n in sorted(unit_names)))
