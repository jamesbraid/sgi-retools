#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Generate plain Rust modules from publish-safe decode headers (config-driven).

Usage (from anywhere):
    uv run retools/tools/defs/gen_decode_rust.py --config defs.toml
            [--root DIR] [-o OUTDIR] [--commit C] [--check]

Reads the headers listed in defs.toml that carry a `module` key and writes one
`<module>.rs` each to `[rust] out_dir`. A consumer copies those files and
nothing else; it never needs the headers.

Per header the output has: a typed accessor for every FIELD line (bit range
and grade in the doc comment), an enum with an `Other` variant for every
ENUM line, a constant per REG line (offset, width, and count where the header
gives one), a constant per plain numeric #define, and one test per TESTVEC
line. EXAMPLE lines are layout illustrations and are never asserted. The
header is the single source of truth: bit ranges, offsets and values are read
from it, never retyped here. Commentary in the header is not copied beyond the
short trailing comment on a #define.

--check regenerates in memory and fails when a file in OUTDIR differs from
the result, is missing, or is an extra .rs file. The commit named in each
banner is not compared (it only says which commit last changed the header);
everything else is.

The banner commit is the last commit that touched the header, so the same
header always yields the same bytes however far the branch has since moved. A
header with uncommitted edits gets "-dirty" appended, which the publish-safe
check refuses.

Output is plain Rust with no dependencies and is formatted to pass
`rustfmt --check` (edition 2021, default settings).
"""

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defs_common import ConfigError, load_config  # noqa: E402

GRADES = "established|inferred|unknown"
FIELD_RE = re.compile(r"/\*\s*FIELD:\s*(\w+(?:\.\w+)?)\.(\w+)\s+(\d+):(\d+)\s+(%s)\s*\*/" % GRADES)
REG_RE = re.compile(
    r"/\*\s*REG:\s*(\w+)\.(\w+)\s+(0x[0-9a-fA-F]+)\s+(rw|r|w)(\d+)(?:\s+count=(\d+))?"
    r"(?:\s+space=\w+)?\s+reset=(\S+)\s+(%s)\s*\*/" % GRADES
)
WORD_RE = re.compile(r"/\*\s*WORD:\s*([A-Z][A-Z_0-9]*)\s+(32|64)\s*\*/")
ENUM_RE = re.compile(r"/\*\s*ENUM:\s*([\w.]+)\s+(0x[0-9a-fA-F]+|\d+)\s+(\w+)\s+(%s)\s*\*/" % GRADES)
TV_RE = re.compile(r"TESTVEC:\s*(0x[0-9a-fA-F]+)\s+as\s+([\w.]+)\s*=>\s*(.+?)\s*$")
DEF_RE = re.compile(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)[uU]?[lL]{0,2}(?:\s*/\*(.*))?$")
FUNC_RE = re.compile(r"^#define\s+(\w+)\(i\)\s+\(\s*(0x[0-9a-fA-F]+)[uU]?\s*\+\s*\(i\)\s*\)")

KEYWORDS = {
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
    "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "async",
    "await", "dyn", "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof",
    "unsized", "virtual", "yield", "try",
}

# A Rust identifier cannot start with a digit, but a header name can once the
# prefix is stripped (KONA_TOKEN_1D_... becomes 1D_...). Such a constant gets
# this word in front, the same default enum variants use (see Header.variant).
# Stripping the digit instead would make two names collide.
DIGIT_PREFIX = "V"
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
DECL_RE = re.compile(r"^\s*(?:pub )?(?:const (?:fn )?|fn |struct |enum |mod )([^\s:(<{;]+)")
VARIANT_RE = re.compile(r"^    ([^\s(,:{}]+)[(,]")

def camel(s):
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"_+", s.lower()) if p)


def ident(name):
    return name + "_" if name in KEYWORDS else name


def digit_safe(name):
    return DIGIT_PREFIX + name if name[:1].isdigit() else name


# Every name the generator declares must be a plain identifier. A digit-led
# name or a stray character makes the module fail to compile, and rustc is not
# installed everywhere ci-check runs, so the generator checks it itself.
def check_identifiers(text):
    bad = []
    for line in text.splitlines():
        m = DECL_RE.match(line) or VARIANT_RE.match(line)
        if m and (not IDENT_RE.match(m.group(1)) or m.group(1) in KEYWORDS):
            bad.append(m.group(1))
    assert not bad, f"generated names are not Rust identifiers: {bad}"


def mask_of(hi, lo):
    return (1 << (hi - lo + 1)) - 1


def doc(comment):
    c = " ".join(comment.replace("*/", "").replace("/*", "").split())
    return c.rstrip(".") + "." if c else ""


# Header commentary can point at note files a public reader cannot open. A
# file pointer, or the project's own name, must never reach the output.
def pointer_re(project):
    return re.compile(r"docs/|\.md\b|\.(?:c|s|h)\b|" + re.escape(project), re.I)


class Header:
    """Everything parsed from one header, plus its config entry."""

    def __init__(self, hc, text):
        self.name = os.path.basename(hc["file"])
        self.file = hc["file"]
        self.mod = hc["module"]
        self.prefix = hc.get("rust_prefix", "")
        self.desc = hc.get("description", [])
        self.reg_noun = hc.get("register_doc", "Register")
        # word key -> (Rust type, doc); a word not listed gets its CamelCase name
        self.words = {k: tuple(v) for k, v in hc.get("words", {}).items()}
        # #define families that stand in for ENUM lines (see README.md)
        self.families = hc.get("enum_families", [])
        self.regs = []  # (block, name, offset, acc, width, count, reset, grade)
        self.fields = {}  # key -> [(name, hi, lo, grade)]
        self.enum_lines = []  # (target, value, label, grade)
        self.defs = []  # (name, value, comment)
        self.funcs = []  # (name, base)
        self.vecs = []  # (value, target, [(field, text)])
        self.wwords = {}  # non-register word -> declared width
        self.parse(text)

    def parse(self, text):
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            if "<" in line and ("FIELD:" in line or "REG:" in line or "ENUM:" in line):
                continue  # grammar line in the header preamble
            m = REG_RE.search(line)
            if m:
                b, n, off, acc, w, cnt, rst, g = m.groups()
                self.regs.append((b, n, int(off, 16), acc, int(w), int(cnt) if cnt else None, rst, g))
                continue
            m = WORD_RE.search(line)
            if m:
                self.wwords[m.group(1)] = int(m.group(2))
                continue
            m = FIELD_RE.search(line)
            if m:
                key, name, hi, lo, g = m.group(1), m.group(2), int(m.group(3)), int(m.group(4)), m.group(5)
                assert 0 <= lo <= hi <= 63, line
                self.fields.setdefault(key, []).append((name, hi, lo, g))
                continue
            m = ENUM_RE.search(line)
            if m:
                self.enum_lines.append((m.group(1), int(m.group(2), 0), m.group(3), m.group(4)))
                continue
            if "EXAMPLE" in line:
                continue
            m = TV_RE.search(line)
            if m:
                kv = [tuple(p.strip().split("=", 1)) for p in m.group(3).split(",")]
                self.vecs.append((int(m.group(1), 16), m.group(2), kv))
                continue
            if not line.startswith("#define"):
                continue
            m = FUNC_RE.match(line)
            if m:
                self.funcs.append((m.group(1), int(m.group(2), 16)))
                continue
            # A trailing comment may continue on following lines.
            full = line.strip()
            if "/*" in full and "*/" not in full:
                while i < len(lines) and "*/" not in full:
                    full += " " + lines[i].strip().lstrip("*").strip()
                    i += 1
            m = DEF_RE.match(full.replace("*/", "").rstrip() if "/*" in full else full)
            if m:
                self.defs.append((m.group(1), int(m.group(2), 0), (m.group(3) or "").strip()))
        for key, fs in self.fields.items():
            used = 0
            top = max(hi for _, hi, _, _ in fs)
            assert top < self.bits(key), f"{key} field reaches bit {top}"
            for name, hi, lo, _ in fs:
                bits = mask_of(hi, lo) << lo
                assert not used & bits, f"{key}.{name} overlaps another field"
                used |= bits
        self.blocks = {r[0] for r in self.regs}
        self.reg_offset = {f"{r[0]}.{r[1]}": r[2] for r in self.regs}

    def bits(self, key):
        """Width of a word: 64 for a WORD declared so, or a 64-bit register with a
        field above bit 31 (a 64-bit register with only low fields stays u32, as
        before 64-bit support), else 32."""
        if key in self.wwords:
            return self.wwords[key]
        for r in self.regs:
            if f"{r[0]}.{r[1]}" == key and r[4] == 64 and any(f[1] > 31 for f in self.fields.get(key, [])):
                return 64
        return 32

    def word_type(self, key):
        if key in self.words:
            return self.words[key][0]
        parts = key.split(".")
        if parts[0] in self.blocks:
            parts = parts[1:]
        return camel("_".join(parts))

    def word_desc(self, key):
        if key in self.words:
            return self.words[key][1]
        if "." in key:
            return f"The `{key.split('.', 1)[1]}` register word."
        return f"The `{key}` word."

    def field_width(self, key, fname):
        for n, hi, lo, _ in self.fields[key]:
            if n == fname:
                return hi - lo + 1
        raise KeyError(f"{key}.{fname}")

    def build_enums(self):
        """Return (enums, field_enum): enums is a list of dicts, field_enum
        maps 'WORD.field' to the enum's Rust type."""
        enums = []
        field_enum = {}
        used_in_enum = set()
        if self.families:
            # Longest prefix first so SAMPLER_MIN wins over SAMPLER.
            fams = sorted(self.families, key=lambda f: len(f["prefix"]), reverse=True)
            vals = {f["prefix"]: [] for f in self.families}
            for name, val, cmt in self.defs:
                n = name[len(self.prefix):] if name.startswith(self.prefix) else name
                for f in fams:
                    if n.startswith(f["prefix"] + "_"):
                        vals[f["prefix"]].append((n[len(f["prefix"]) + 1:], val, cmt))
                        used_in_enum.add(name)
                        break
            for f in self.families:
                vs = vals[f["prefix"]]
                if not vs:
                    continue
                dpfx = f.get("digit_prefix", "V")
                width = max(self.field_width(*k.rsplit(".", 1)) for k in f["fields"])
                enums.append({
                    "ty": f["type"], "desc": f["doc"], "width": width,
                    "vals": [(self.variant(n, dpfx), v, doc(c)) for n, v, c in vs],
                })
                for k in f["fields"]:
                    field_enum[k] = f["type"]
        by_target = {}
        for target, val, label, grade in self.enum_lines:
            by_target.setdefault(target, []).append((label, val, grade))
        for target, vs in by_target.items():
            key, fname = target.rsplit(".", 1)
            ty = self.word_type(key) + camel(fname)
            enums.append({
                "ty": ty, "desc": f"Values of `{fname}` in `{self.word_type(key)}` that the header names.",
                "width": self.field_width(key, fname),
                "vals": [(self.variant(l, "V"), v, f"{g}.") for l, v, g in vs],
            })
            field_enum[target] = ty
            tgt = target.upper().replace(".", "_")
            for name, _, _ in self.defs:
                for l, _, _ in vs:
                    if name.endswith(f"{tgt}_{l.upper()}"):
                        used_in_enum.add(name)
        for e in enums:
            names = [n for n, _, _ in e["vals"]]
            vals = [v for _, v, _ in e["vals"]]
            assert len(set(names)) == len(names), (e["ty"], names)
            assert len(set(vals)) == len(vals), f"duplicate values in {e['ty']}"
        self.used_in_enum = used_in_enum
        return enums, field_enum

    @staticmethod
    def variant(name, prefix):
        v = camel(name)
        if v[0].isdigit():
            v = prefix + (v[:-1] if prefix == "Bytes" and v.endswith("b") else v)
        return v


    @staticmethod
    def variant(name, prefix):
        v = camel(name)
        if v[0].isdigit():
            v = prefix + (v[:-1] if prefix == "Bytes" and v.endswith("b") else v)
        return v


def extract(h, key, name, value):
    for n, hi, lo, _ in h.fields[key]:
        if n == name:
            return (value >> lo) & mask_of(hi, lo)
    raise KeyError(f"{key}.{name}")


def resolve(v, headers):
    """A TESTVEC value: a number, or @BLOCK.name naming a register address."""
    if v.startswith("@"):
        for h in headers.values():
            if v[1:] in h.reg_offset:
                return h.reg_offset[v[1:]]
        raise KeyError(v)
    return int(v, 0)


def check_vectors(h, headers):
    # The header's own vectors must hold for the ranges we are about to emit.
    for value, target, kv in h.vecs:
        assert value >> h.bits(target) == 0, f"TESTVEC {value:#x} is wider than a word"
        for k, v in kv:
            got = extract(h, target, k, value)
            want = resolve(v, headers)
            assert got == want, f"TESTVEC {value:#x} as {target}: {k} is {got}, header says {v}"


def emit_enum(e):
    ty = e["ty"]
    other = "u8" if e["width"] <= 8 else "u32"
    o = [f"/// {e['desc']}", "#[derive(Clone, Copy, Debug, PartialEq, Eq)]", f"pub enum {ty} {{"]
    for n, v, d in e["vals"]:
        o.append(f"    /// {d or f'Value {v:#x}.'}")
        o.append(f"    {n},")
    o += ["    /// A value the notes do not name.", f"    Other({other}),", "}", "", f"impl {ty} {{"]
    o += ["    pub const fn from_bits(v: u32) -> Self {", "        match v {"]
    for n, v, _ in e["vals"]:
        o.append(f"            {v:#x} => Self::{n},")
    o += [f"            _ => Self::Other(v as {other}),", "        }", "    }", "",
          "    pub const fn bits(self) -> u32 {", "        match self {"]
    for n, v, _ in e["vals"]:
        o.append(f"            Self::{n} => {v:#x},")
    o += ["            Self::Other(v) => v as u32,", "        }", "    }", "}", ""]
    return o


def emit_word(h, key, field_enum):
    ty = h.word_type(key)
    wb = h.bits(key)
    ut = f"u{wb}"
    o = []
    for l in h.word_desc(key).split("\n"):
        o.append(f"/// {l}")
    o += ["#[derive(Clone, Copy, Debug, PartialEq, Eq)]", f"pub struct {ty}({ut});", "", f"impl {ty} {{",
          f"    pub const fn new(word: {ut}) -> Self {{", "        Self(word)", "    }", "",
          f"    pub const fn raw(self) -> {ut} {{", "        self.0", "    }", ""]
    seen = {"new", "raw"}
    for name, hi, lo, grade in h.fields[key]:
        fn = ident(name)
        assert fn not in seen, f"accessor {fn} collides in {key}"
        seen.add(fn)
        rng = f"Bit {hi}" if hi == lo else f"Bits {hi}:{lo}"
        o.append(f"    /// {rng}, {grade}.")
        fk = f"{key}.{name}"
        expr = f"(self.0 >> {lo})" if lo else "self.0"
        width = hi - lo + 1
        if fk in field_enum:
            ety = field_enum[fk]
            arg = expr if width == 32 else f"{expr} & {mask_of(hi, lo):#x}"
            if hi == 31 and lo:
                arg = f"self.0 >> {lo}"
            if wb == 64:
                assert width <= 32, f"enum field {fk} is wider than 32 bits"
                arg = f"({expr} & {mask_of(hi, lo):#x}) as u32"
            o += [f"    pub const fn {fn}(self) -> {ety} {{", f"        {ety}::from_bits({arg})", "    }"]
        elif width == 1:
            o += [f"    pub const fn {fn}(self) -> bool {{", f"        {expr} & 1 != 0", "    }"]
        elif width == wb:
            o += [f"    pub const fn {fn}(self) -> {ut} {{", "        self.0", "    }"]
        elif hi == wb - 1:
            o += [f"    pub const fn {fn}(self) -> {ut} {{", f"        self.0 >> {lo}", "    }"]
        else:
            o += [f"    pub const fn {fn}(self) -> {ut} {{", f"        {expr} & {mask_of(hi, lo):#x}", "    }"]
        o.append("")
    o[-1:] = ["}", ""]
    return o


def emit_regs(h):
    o = []
    for b, n, off, acc, width, cnt, rst, grade in h.regs:
        access = {"r": "read", "w": "write", "rw": "read/write"}[acc]
        cname = n.upper()
        extra = f", {cnt} consecutive registers" if cnt else ""
        o.append(f"/// {h.reg_noun} `{n}`: {access}, {width}-bit{extra}; reset {rst}; {grade}.")
        o.append(f"pub const REG_{cname}: u32 = {off:#06x};")
        o.append(f"pub const REG_{cname}_WIDTH: u32 = {width};")
        if cnt:
            o.append(f"pub const REG_{cname}_COUNT: u32 = {cnt};")
    if o:
        o.append("")
    return o


def emit_consts(h):
    o = []
    names = set()
    for name, val, cmt in h.defs:
        if name in h.used_in_enum or name.endswith(("_SHIFT", "_MASK")) or name.endswith("_H"):
            continue
        n = name[len(h.prefix):] if name.startswith(h.prefix) else name
        n = digit_safe(n)
        assert n not in names, f"constant {n} defined twice"
        names.add(n)
        d = doc(cmt)
        if d:
            o.append(f"/// {d}")
        ct = "u64" if val > 0xFFFFFFFF else "u32"
        o.append(f"pub const {n}: {ct} = {val:#x};" if val >= 0x100 else f"pub const {n}: {ct} = {val};")
    for name, base in h.funcs:
        n = digit_safe((name[len(h.prefix):] if name.startswith(h.prefix) else name).lower())
        o += ["", f"/// `{n}(i)` is the opcode of descriptor `i`: `{base:#06x}` plus `i`.",
              f"pub const fn {n}(i: u32) -> u32 {{", f"    {base:#06x} + i", "}"]
    if o:
        o.append("")
    return o


def emit_tests(h, field_enum, headers):
    o = ["#[cfg(test)]", "mod tests {", "    use super::*;", ""]
    seen = {}
    for value, target, kv in h.vecs:
        ty = h.word_type(target)
        base = ("testvec_" + target.lower().replace(".", "_") + f"_{value:x}")
        n = seen.get(base, 0)
        seen[base] = n + 1
        name = base + (f"_{n}" if n else "")
        o += ["    #[test]", f"    fn {name}() {{", f"        let w = {ty}::new({value:#x});"]
        for k, v in kv:
            fk = f"{target}.{k}"
            acc = f"w.{ident(k)}()"
            width = h.field_width(target, k)
            if fk in field_enum:
                acc += ".bits()"
            elif width == 1:
                acc += " as u32"
            want = resolve(v, headers)
            lit = f"{want:#x}" if v.startswith("@") or want >= 1000000 else str(want)
            label = f"{k}={v}" if v.startswith("@") else k
            line = f'        assert_eq!({acc}, {lit}, "{label}");'
            if len(line) > 100:
                line = f'        assert_eq!(\n            {acc},\n            {lit},\n            "{label}"\n        );'
            o.append(line)
        o += ["    }", ""]
    o[-1:] = ["}"]
    return o


def banner(project, header, commit):
    return f"// generated from {project} {commit} {header} - do not edit, regenerate in {project}"


def generate(project, h, headers, commit):
    check_vectors(h, headers)
    enums, field_enum = h.build_enums()
    o = [banner(project, h.name, commit), "//!"]
    o += [f"//! {l}" for l in h.desc]
    if h.desc:
        o.append("//!")
    o += [
        "//! Grades on each item say what is known about it: `established` is what the",
        "//! shipped driver software does, read in full; `inferred` is a reasoned",
        "//! reading; `unknown` is not derived. None of them is a measurement of the",
        "//! silicon.",
        "",
        "#![allow(dead_code)]",
        "",
    ]
    o += emit_consts(h)
    o += emit_regs(h)
    for e in enums:
        o += emit_enum(e)
    for key in h.fields:
        o += emit_word(h, key, field_enum)
    if h.vecs:
        o += emit_tests(h, field_enum, headers)
    else:
        o.pop()
    out = "\n".join(o).rstrip("\n") + "\n"
    bad = [l for l in out.splitlines()[1:] if pointer_re(project).search(l)]
    assert not bad, f"pointer text in output: {bad}"
    check_identifiers(out)
    return out


def git_commit(root, header):
    def run(*a):
        return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True, check=True).stdout.strip()

    commit = run("log", "-1", "--format=%H", "--", header)[:12]
    assert commit, f"no commit touches {header}"
    return commit


def git_dirty(root, header):
    r = subprocess.run(["git", "-C", root, "status", "--porcelain", "--", header], capture_output=True, text=True)
    return bool(r.stdout.strip())


def strip_banner(text):
    lines = text.split("\n")
    return "\n".join(["// generated from <project> <commit>"] + lines[1:])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", required=True, help="path to the repo defs.toml")
    ap.add_argument("--root", default=None, help="checkout holding the headers (default: from the config)")
    ap.add_argument("-o", "--out", default=None, help="output directory (default: [rust] out_dir under the root)")
    ap.add_argument("--commit", help="commit to name in every banner (default: last commit touching each header)")
    ap.add_argument("--check", action="store_true", help="fail if OUT is stale against the headers")
    a = ap.parse_args()
    try:
        cfg, root = load_config(a.config)
    except ConfigError as e:
        print(f"gen_decode_rust: {e}", file=sys.stderr)
        return 2
    root = a.root or root
    project = cfg["project"]["name"]
    regen = cfg["project"].get("regenerate", "retools/tools/defs/gen_decode_rust.py --config defs.toml")
    out_dir = a.out or os.path.join(root, cfg.get("rust", {}).get("out_dir", "generated"))
    headers = {}
    for hc in cfg["headers"]:
        if not hc.get("module"):
            continue
        with open(os.path.join(root, hc["file"]), encoding="utf-8") as f:
            headers[hc["file"]] = Header(hc, f.read())
    if not headers:
        print("gen_decode_rust: no header has a `module` key", file=sys.stderr)
        return 2
    results = {}
    for name, h in headers.items():
        commit = a.commit[:12] if a.commit else git_commit(root, name)
        results[h.mod + ".rs"] = (generate(project, h, headers, commit), name)
    if a.check:
        bad = False
        for fname, (text, name) in results.items():
            path = os.path.join(out_dir, fname)
            try:
                with open(path, encoding="utf-8") as f:
                    have = f.read()
            except OSError:
                print(f"{path} is missing; regenerate it", file=sys.stderr)
                bad = True
                continue
            if strip_banner(have) != strip_banner(text):
                print(f"{path} is stale against {name}; run {regen}", file=sys.stderr)
                bad = True
        if os.path.isdir(out_dir):
            for extra in sorted(set(os.listdir(out_dir)) - set(results)):
                print(f"{os.path.join(out_dir, extra)} is not generated from any header", file=sys.stderr)
                bad = True
        return 1 if bad else 0
    os.makedirs(out_dir, exist_ok=True)
    for fname, (text, name) in results.items():
        if not a.commit and git_dirty(root, name):
            first, rest = text.split("\n", 1)
            text = re.sub(r"(%s [0-9a-f]{12})" % re.escape(project), r"\1-dirty", first, 1) + "\n" + rest
        with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, KeyError) as e:
        print(f"gen_decode_rust: {e!r}", file=sys.stderr)
        sys.exit(1)
