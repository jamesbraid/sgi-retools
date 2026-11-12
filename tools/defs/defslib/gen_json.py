"""Flat JSON per unit: one row per register, word, field, enum value and constant."""
import json

from .model import eff_from, enum_values


def gen_json(u, src, profile="public"):
    rows = []

    def row(kind, name, node, parent=None, **kw):
        c = eff_from(u, node, parent)
        r = {"unit": u["unit"], "kind": kind, "name": name}
        r.update(kw)
        r["grade"] = node.get("grade")
        if c:
            r["from"] = c
        rows.append(r)
    for sect, kind in (("registers", "register"), ("words", "word")):
        for n, x in u[sect].items():
            if kind == "register":
                row(kind, n, x, offset=x["offset"], access=x["access"], width=x["width"], count=x["count"],
                    stride=x["stride"], space=x["space"], reset=x["reset"])
            else:
                row(kind, n, x, width=x["width"])
            for fn, f in x["fields"].items():
                row("field", "%s.%s" % (n, fn), f, x, hi=f["bits"][0], lo=f["bits"][1])
                for lab, ev in enum_values(u, f).items():
                    row("enum_value", "%s.%s.%s" % (n, fn, lab), ev, f, value=ev["value"])
    for n, k in u["constants"].items():
        row("constant", n, k, value=k["value"], count=k.get("count", 1))
    return json.dumps({"schema": "defs-flat/1", "source": src, "profile": profile, "rows": rows}, indent=1) + "\n"
