"""A reference page per unit, in Markdown, for publishing.

Every register, word, field, enum value and constant appears with its grade and
source. The internal profile adds each item's notes; the public one leaves out
notes and any source that is not in public_from.
"""
from .genutil import banner
from .model import block_of, eff_from, enum_values

GRADE_NOTE = ("Every item has a grade: established, inferred or unknown. A grade says how the item was derived "
              "from its source; it does not claim the item was measured on silicon.")


def _cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def _hex(v, w=0):
    return "0x%0*x" % (w, v)


def _table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for r in rows:
        out.append("| " + " | ".join(_cell(c) for c in r) + " |")
    return out


def _fields_table(u, x):
    rows = []
    for fn, f in x["fields"].items():
        hi, lo = f["bits"]
        bits = "%d" % hi if hi == lo else "%d:%d" % (hi, lo)
        ev = enum_values(u, f)
        vals = ", ".join("%s=%d" % (lab, v["value"]) for lab, v in ev.items())
        if f.get("enum"):
            vals = "%s (%s)" % (f["enum"], vals) if vals else f["enum"]
        rows.append([bits, "`%s`" % fn, f["grade"], vals, eff_from(u, f, x) or "", f.get("doc", "")])
    return _table(["Bits", "Field", "Grade", "Values", "Source", "Description"], rows)


def _note(node):
    return ["Notes: %s" % node["notes"].strip(), ""] if node.get("notes") else []


def gen_docs(u, src, profile="public"):
    title = u.get("title") or u["unit"]
    out = ["# %s" % title, "", "<!-- %s -->" % banner(src, "", "").strip(), ""]
    if u.get("doc"):
        out += [u["doc"].strip(), ""]
    meta = ["Unit `%s`, macro prefix `%s`" % (u["unit"], u["prefix"])]
    if u.get("block"):
        meta[0] += ", register block `%s`" % block_of(u)
    out.append(meta[0] + ".")
    if u.get("from"):
        out.append("Default source: %s." % u["from"])
    out += ["", GRADE_NOTE, ""]

    if u["spaces"]:
        out += ["## Address spaces", ""]
        out += _table(["Space", "Offset unit", "Description"],
                      [[n, "register index" if s["unit"] == "reg" else "byte", s.get("doc", "")] for n, s in u["spaces"].items()])
        out.append("")
    if u["registers"]:
        out += ["## Registers", ""]
        rows = []
        for n, r in u["registers"].items():
            rows.append(["`%s`" % n, _hex(r["offset"]), r["access"], r["width"], r["count"] if r["count"] > 1 else "",
                         r["space"] or "", _hex(r["reset"]) if isinstance(r["reset"], int) else "unknown", r["grade"],
                         eff_from(u, r) or ""])
        out += _table(["Register", "Offset", "Access", "Width", "Count", "Space", "Reset", "Grade", "Source"], rows)
        out.append("")
        for n, r in u["registers"].items():
            out += ["### Register `%s`" % n, ""]
            if r.get("doc"):
                out += [r["doc"].strip(), ""]
            if r["count"] > 1:
                out += ["Array of %d registers, stride %d." % (r["count"], r["stride"]), ""]
            if r["fields"]:
                out += _fields_table(u, r) + [""]
            out += _note(r)
    if u["words"]:
        out += ["## Words", ""]
        out += _table(["Word", "Width", "Grade", "Source"],
                      [["`%s`" % n, w["width"], w["grade"], eff_from(u, w) or ""] for n, w in u["words"].items()])
        out.append("")
        for n, w in u["words"].items():
            out += ["### Word `%s`%s" % (n, " (%s)" % w["type_name"] if w.get("type_name") else ""), ""]
            if w.get("doc"):
                out += [w["doc"].strip(), ""]
            if w["fields"]:
                out += _fields_table(u, w) + [""]
            out += _note(w)
    if u["enums"]:
        out += ["## Enums", ""]
        for n, e in u["enums"].items():
            out += ["### Enum `%s`" % n, ""]
            if e.get("doc"):
                out += [e["doc"].strip(), ""]
            out += _table(["Label", "Value", "Grade", "Source"],
                          [["`%s`" % lab, v["value"], v["grade"], v.get("from") or u.get("from", "")] for lab, v in e["values"].items()])
            out.append("")
    if u["constants"]:
        out += ["## Constants", ""]
        rows = []
        for n, k in u["constants"].items():
            val = _hex(k["value"])
            if k.get("count", 1) > 1:
                val += " + i * %d, i < %d" % (k.get("stride", 1), k["count"])
            rows.append(["`%s`" % n, val, k["grade"], eff_from(u, k) or "", k.get("doc", "")])
        out += _table(["Constant", "Value", "Grade", "Source", "Description"], rows)
        out.append("")
    vecs = [(n, t) for sect in ("registers", "words") for n, x in u[sect].items() for t in x["tests"]]
    if vecs:
        out += ["## Test vectors", "",
                "A vector is a value recorded from a source. An example only shows the layout.", ""]
        out += _table(["Target", "Value", "Kind", "Decoded"],
                      [["`%s`" % n, _hex(t["value"]), t["kind"], ", ".join("%s=%d" % kv for kv in t["expect"].items())]
                       for n, t in vecs])
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"
