"""Structural checks over the model: the layout rules every unit must meet.

Overlap, width, enum fit, test vectors, a grade on every item and a `from`
that reaches every item. The leak, prose and notes checks are in checks.py.
"""
from .model import (ACCESS, GRADES, Problems, RE_CONST, RE_LABEL, RE_REG, RE_WORD, block_of, decode,
                    eff_from, enum_values, fwidth, items, last_unit, mask, unit_size)


def check_unit(u, settings=None):
    """Return Problems for one normalised unit."""
    chk = (settings or {}).get("checks", {})
    max_addr = (1 << chk.get("address_bits", 14)) - 1
    max_off = chk.get("max_reg_offset", 0xffff)
    p = Problems()
    w0 = u["unit"]

    def req(cond, where, msg):
        if not cond:
            p.add(where, msg)

    for n in u["registers"]:
        req(RE_REG.match(n), "%s.%s" % (w0, n), "register names are lower_snake")
    for n in u["words"]:
        req(RE_WORD.match(n), "%s.%s" % (w0, n), "word names are UPPER_SNAKE")
    for n in u["constants"]:
        req(RE_CONST.match(n), "%s.%s" % (w0, n), "constant names are UPPER_SNAKE")
    if set(u["registers"]) & {w.lower() for w in u["words"]}:
        p.add(w0, "a register and a word share a name (%s); the genxml export needs distinct names"
              % ", ".join(sorted(set(u["registers"]) & {w.lower() for w in u["words"]})))

    for kind, name, node, parent, width in items(u):
        at = "%s.%s" % (w0, name)
        req(node.get("grade") in GRADES, at, "%s needs a grade (%s)" % (kind, "/".join(GRADES)))
        req(eff_from(u, node, parent) is not None, at, "no `from` on the item, its block or the file")

    for n, r in u["registers"].items():
        at = "%s.%s" % (w0, n)
        req(r["access"] in ACCESS, at, "access must be r/w/rw")
        if isinstance(r["reset"], int):
            req(r["reset"] <= mask(r["width"]), at, "reset does not fit the width")
        req(r["stride"] >= unit_size(u, r), at, "stride smaller than the register")
        req(r["space"] is None or r["space"] in u["spaces"], at, "space %r not declared in spaces" % r["space"])
        req(r["offset"] <= max_off and last_unit(u, r) <= max_addr, at,
            "offset/count 0x%x/%d outside the register space (address_bits %d, max_reg_offset 0x%x)"
            % (r["offset"], r["count"], max_addr.bit_length(), max_off))

    for kind, name, node, parent, width in items(u):
        if kind not in ("register", "word"):
            continue
        spans = []
        for fn, f in node["fields"].items():
            at = "%s.%s.%s" % (w0, name, fn)
            hi, lo = f["bits"]
            req(0 <= lo <= hi < width, at, "bits %d:%d do not fit %d-bit %s" % (hi, lo, width, kind))
            for (n2, h2, l2) in spans:
                req(hi < l2 or lo > h2, at, "overlaps field %s" % n2)
            spans.append((fn, hi, lo))
            if f.get("enum") and f.get("enums"):
                p.add(at, "enum and enums are exclusive")
            if f.get("enum") and f["enum"] not in u["enums"]:
                p.add(at, "unknown shared enum %r" % f["enum"])
                continue
            for lab, ev in enum_values(u, f).items():
                req(0 <= ev["value"] <= mask(fwidth(f)), "%s.%s" % (at, lab),
                    "value %d does not fit %d bits" % (ev["value"], fwidth(f)))
    for n, e in u["enums"].items():
        for lab in e["values"]:
            req(RE_LABEL.match(lab), "%s.enum.%s" % (w0, n), "enum label %r" % lab)
        vals = [v["value"] for v in e["values"].values()]
        req(len(vals) == len(set(vals)), "%s.enum.%s" % (w0, n), "duplicate values")

    for kind, name, node, parent, width in items(u):
        if kind not in ("register", "word"):
            continue
        for t in node["tests"]:
            at = "%s.%s test 0x%x" % (w0, name, t["value"])
            req(t["value"] <= mask(width), at, "value wider than %d bits" % width)
            got = decode(node["fields"], t["value"])
            for fn, want in t["expect"].items():
                if fn not in got:
                    p.add(at, "unknown field %r" % fn)
                elif isinstance(want, str):
                    continue            # an unresolved @register reference; the loader resolves these
                elif got[fn] != want:
                    p.add(at, "field %s decodes to %d (0x%x), stated %d" % (fn, got[fn], got[fn], want))
    return p


def register_runs(u, r):
    """Address intervals (lo, hi) in address units a register array occupies."""
    size = unit_size(u, r)
    if r["stride"] == size:
        return [(r["offset"], r["offset"] + r["count"] * size - 1)]
    return [(r["offset"] + i * r["stride"], r["offset"] + i * r["stride"] + size - 1) for i in range(r["count"])]


def check_overlap(units):
    """Registers collide only inside one address space. A register with no
    space is in its unit's own default space; a named space is shared by every
    unit that names it."""
    p = Problems()
    by_space = {}
    for u in units:
        for n, r in u["registers"].items():
            key = r["space"] if r["space"] else "\0" + u["unit"]
            for lo, hi in register_runs(u, r):
                by_space.setdefault(key, []).append((lo, hi, "%s.%s" % (block_of(u), n), u["unit"]))
    for key, runs in by_space.items():
        runs.sort()
        reach, who = -1, None
        for lo, hi, name, unit in runs:
            if lo <= reach and who != name:
                p.add(unit, "%s (0x%x-0x%x) overlaps %s (to 0x%x)" % (name, lo, hi, who, reach))
            if hi > reach:
                reach, who = hi, name
    return p
