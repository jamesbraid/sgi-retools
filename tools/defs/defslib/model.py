"""The shared model every generator and check reads.

A source file is one unit: a hardware block, a family of command or
descriptor words, or a table of constants.

  unit, prefix, block?, title, doc, from, public_from[], c{...}
  spaces{name: {unit: byte|reg, doc}}
  enums{name: {doc, values{label: {value, grade, from?, doc?}}}}
  registers{name: {offset, access, width, count, stride, space, reset, grade,
                   from?, doc, notes, fields{}, tests[]}}
  words{NAME: {width, grade, from?, doc, type_name?, fields{}, tests[]}}
  constants{NAME: {value, grade, from?, doc, count?, stride?}}
  field: {bits:[hi,lo], grade, from?, doc?, notes?, enum? | enums{label: {...}}}
  test:  {value, kind: vector|example, expect{field: int | "@register"}}

`from` is free text naming where an item comes from. It defaults from the
file, then from the register or word, and an item sets its own only when it
differs. The grade is on every item: established, inferred or unknown.
"""
import copy
import re

GRADES = ("established", "inferred", "unknown")
ACCESS = ("r", "w", "rw")

RE_UNIT = re.compile(r"^[a-z][a-z0-9_]*$")
RE_PREFIX = re.compile(r"^[A-Z][A-Z0-9_]*$")
RE_REG = re.compile(r"^[a-z][a-z0-9_]*$")
RE_WORD = re.compile(r"^[A-Z][A-Z0-9_]*$")
RE_CONST = re.compile(r"^[A-Z0-9][A-Z0-9_]*$")
RE_LABEL = re.compile(r"^[a-z0-9][a-z0-9_]*$")


class Problems(list):
    def add(self, where, msg):
        self.append("%s: %s" % (where, msg))


def mask(width):
    return (1 << width) - 1


def fwidth(f):
    return f["bits"][0] - f["bits"][1] + 1


def block_of(u):
    """The register block name: `block`, else the prefix."""
    return u.get("block") or u["prefix"]


def unit_size(u, r):
    """Address units one register occupies: bytes in a byte space, one in a
    register-indexed space."""
    sp = u["spaces"].get(r.get("space")) if r.get("space") else None
    return 1 if sp and sp["unit"] == "reg" else r["width"] // 8


def normalize(src):
    """Fill defaults and put everything in one order. Checks nothing."""
    u = copy.deepcopy(src)
    u.setdefault("title", "")
    u.setdefault("doc", "")
    u.setdefault("public_from", [])
    u.setdefault("c", {})
    u["c"].setdefault("offset_macro", "suffix")
    u["c"].setdefault("aliases", {})
    for sect in ("enums", "registers", "words", "constants", "spaces"):
        u.setdefault(sect, {})
    for sp in u["spaces"].values():
        sp.setdefault("unit", "byte")
        sp.setdefault("doc", "")
    for e in u["enums"].values():
        e.setdefault("doc", "")
    for r in u["registers"].values():
        r.setdefault("count", 1)
        r.setdefault("space", None)
        r.setdefault("reset", "unknown")
        r.setdefault("fields", {})
        r.setdefault("tests", [])
        r.setdefault("doc", "")
        r.setdefault("notes", "")
        r["stride"] = r.get("stride") or unit_size(u, r)
    for w in u["words"].values():
        w.setdefault("fields", {})
        w.setdefault("tests", [])
        w.setdefault("doc", "")
        w.setdefault("notes", "")
    for sect in ("registers", "words"):
        for x in u[sect].values():
            for t in x["tests"]:
                t.setdefault("kind", "vector")
    return canonical_sort(u)


def canonical_sort(u):
    """One order for every output: registers by space and address, words,
    constants and enums by name, fields high bit first, enum values by value."""
    def sort_fields(x):
        x["fields"] = dict(sorted(x["fields"].items(), key=lambda kv: -kv[1]["bits"][0]))
        for f in x["fields"].values():
            if f.get("enums"):
                f["enums"] = dict(sorted(f["enums"].items(), key=lambda kv: (kv[1]["value"], kv[0])))
        x["tests"] = sorted(x["tests"], key=lambda t: (t["value"], t["kind"]))
    for sect in ("registers", "words"):
        for x in u[sect].values():
            sort_fields(x)
    u["registers"] = dict(sorted(u["registers"].items(),
                                 key=lambda kv: (kv[1].get("space") or "", kv[1]["offset"], kv[0])))
    u["words"] = dict(sorted(u["words"].items()))
    u["constants"] = dict(sorted(u["constants"].items()))
    u["enums"] = {n: dict(e, values=dict(sorted(e["values"].items(), key=lambda kv: (kv[1]["value"], kv[0]))))
                  for n, e in sorted(u["enums"].items())}
    return u


def eff_from(unit, node, parent=None):
    """Nearest `from`: the item, its register or word, then the file."""
    for n in (node, parent, unit):
        if n and n.get("from"):
            return n["from"]
    return None


def is_public(unit, text):
    return bool(text) and any(text.startswith(p) for p in unit.get("public_from", []))


def items(u):
    """Yield (kind, name, node, parent_node_or_None, width)."""
    for n, r in u["registers"].items():
        yield "register", n, r, None, r["width"]
        for fn, f in r["fields"].items():
            yield "field", "%s.%s" % (n, fn), f, r, r["width"]
    for n, w in u["words"].items():
        yield "word", n, w, None, w["width"]
        for fn, f in w["fields"].items():
            yield "field", "%s.%s" % (n, fn), f, w, w["width"]
    for n, c in u["constants"].items():
        yield "constant", n, c, None, 64


def layout_of(u, target):
    """(width, fields) of a register or word name, else (None, None)."""
    if target in u["registers"]:
        return u["registers"][target]["width"], u["registers"][target]["fields"]
    if target in u["words"]:
        return u["words"][target]["width"], u["words"][target]["fields"]
    return None, None


def decode(fields, value):
    return {n: (value >> f["bits"][1]) & mask(fwidth(f)) for n, f in fields.items()}


def enum_values(u, f):
    if f.get("enum"):
        return u["enums"].get(f["enum"], {}).get("values", {})
    return f.get("enums") or {}


def last_unit(u, r):
    """Address of the last element of a register array, in address units."""
    return r["offset"] + (r["count"] - 1) * r["stride"]


def publish_profile(u):
    """What a public output may carry: no notes, and `from` text only when it
    starts with one of the unit's public_from prefixes."""
    u = copy.deepcopy(u)

    def clean(node):
        node["notes"] = ""
        if node.get("from") and not is_public(u, node["from"]):
            node.pop("from")
    clean(u)
    for sect in ("registers", "words", "constants"):
        for x in u[sect].values():
            clean(x)
            for f in x.get("fields", {}).values():
                clean(f)
                for ev in (f.get("enums") or {}).values():
                    if ev.get("from") and not is_public(u, ev["from"]):
                        ev.pop("from")
    for e in u["enums"].values():
        for ev in e["values"].values():
            if ev.get("from") and not is_public(u, ev["from"]):
                ev.pop("from")
    return u
