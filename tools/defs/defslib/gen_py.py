"""Python decode helpers per unit: tables of the layout plus decode, encode and a self-test."""
from .genutil import banner, one_line
from .model import enum_values


def gen_py(u, src):
    regs = {n: {k: r[k] for k in ("offset", "access", "width", "count", "stride", "space", "reset", "grade")}
            for n, r in u["registers"].items()}
    words = {n: {"width": w["width"], "grade": w["grade"]} for n, w in u["words"].items()}
    flds, enums, fenum = {}, {}, {}
    for sect in ("registers", "words"):
        for n, x in u[sect].items():
            flds[n] = {fn: (f["bits"][0], f["bits"][1]) for fn, f in x["fields"].items()}
            for fn, f in x["fields"].items():
                ev = enum_values(u, f)
                if ev:
                    key = f["enum"] if f.get("enum") else "%s.%s" % (n, fn)
                    enums[key] = {v["value"]: lab for lab, v in ev.items()}
                    fenum["%s.%s" % (n, fn)] = key
    consts = {n: {"value": k["value"], "count": k.get("count", 1), "stride": k.get("stride", 1)}
              for n, k in u["constants"].items()}
    tests = [(n, t["value"], t["expect"]) for sect in ("registers", "words") for n, x in u[sect].items()
             for t in x["tests"] if t["kind"] == "vector"]
    py = ['"""%s' % banner(src, "", "").strip(), one_line(u.get("title", "")) + '"""', "",
          "UNIT = %r" % u["unit"], "REGISTERS = %r" % regs, "WORDS = %r" % words, "FIELDS = %r" % flds,
          "ENUMS = %r" % enums, "FIELD_ENUM = %r" % fenum, "CONSTANTS = %r" % consts, "TESTS = %r" % tests, "",
          "", "def decode(name, value):", "    \"\"\"Field name -> value for a register or word.\"\"\"",
          "    return {f: (value >> lo) & ((1 << (hi - lo + 1)) - 1) for f, (hi, lo) in FIELDS[name].items()}", "",
          "", "def encode(name, **fields):", "    v = 0", "    for f, x in fields.items():",
          "        hi, lo = FIELDS[name][f]", "        if x >> (hi - lo + 1):",
          "            raise ValueError('%s.%s: %d does not fit' % (name, f, x))", "        v |= x << lo",
          "    return v", "",
          "", "def describe(name, value):", "    \"\"\"decode, with enum labels where the field has an enum.\"\"\"", "    out = {}",
          "    for f, x in decode(name, value).items():", "        e = ENUMS.get(FIELD_ENUM.get('%s.%s' % (name, f)))",
          "        out[f] = e.get(x, x) if e else x", "    return out", "",
          "", "def selftest():", "    for name, value, expect in TESTS:", "        got = decode(name, value)",
          "        for f, want in expect.items():", "            assert got[f] == want, (name, hex(value), f, got[f], want)",
          "    return len(TESTS)", "",
          "", "if __name__ == '__main__':", "    print('%s: %d vectors ok' % (UNIT, selftest()))", ""]
    return "\n".join(py)
