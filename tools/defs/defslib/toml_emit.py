"""Write a unit (or check settings) as TOML source text.

Used by the importer. The text is meant to be maintained by hand afterwards, so
it is laid out for review: one line per field and per enum value, long prose as
multi-line strings, defaults left out.
"""
import json
import re

HEXKEYS = {"offset", "reset"}


def _s(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    v = str(v)
    if "\\" in v and "'" not in v and "\n" not in v and not re.search(r"[\x00-\x08\x0a-\x1f\x7f]", v):
        return "'%s'" % v          # a literal string keeps regular expressions readable
    return json.dumps(v, ensure_ascii=False)


def _val(k, v, ctx=""):
    if isinstance(v, int) and not isinstance(v, bool) and (k in HEXKEYS or (k == "value" and ctx in ("const", "test"))):
        return hex(v)
    if isinstance(v, list):
        return "[" + ", ".join(_val(k, x) if isinstance(x, (list, dict)) else _s(x) for x in v) + "]"
    if isinstance(v, dict):
        return _inline(v, ctx)
    return _s(v)


def _key(k):
    return k if re.match(r"^[A-Za-z0-9_-]+$", k) else json.dumps(k)


def _inline(d, ctx=""):
    return "{ " + ", ".join("%s = %s" % (_key(k), _val(k, v, ctx)) for k, v in d.items()) + " }"


def _scalars(d, ctx, out, skip=()):
    for k, v in d.items():
        if k in skip:
            continue
        if isinstance(v, str) and "\n" in v:
            body = v.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
            out.append('%s = """\n%s"""' % (_key(k), body))
        else:
            out.append("%s = %s" % (_key(k), _val(k, v, ctx)))


def trimmed(u):
    """Drop what the loader restores by default."""
    o = {}
    for k in ("unit", "prefix", "block", "title", "doc", "from", "public_from"):
        if u.get(k):
            o[k] = u[k]
    c = {k: v for k, v in u["c"].items() if v and not (k == "offset_macro" and v == "suffix")}
    if c:
        o["c"] = c
    if u["spaces"]:
        o["spaces"] = {n: {k: v for k, v in s.items() if v and not (k == "unit" and v == "byte")} for n, s in u["spaces"].items()}
    if u["enums"]:
        o["enums"] = {n: {k: v for k, v in e.items() if v != ""} for n, e in u["enums"].items()}
    for sect in ("registers", "words"):
        if not u[sect]:
            continue
        o[sect] = {}
        for n, x in u[sect].items():
            d = {}
            for k, v in x.items():
                if k == "count" and v == 1:
                    continue
                if k == "stride" and (x.get("count", 1) == 1 or v == _natural_stride(u, x)):
                    continue
                if k == "space" and v is None:
                    continue
                if k == "reset" and v == "unknown":
                    continue
                if v in (None, "", {}, []):
                    continue
                if k == "tests":
                    v = [{a: b for a, b in t.items() if not (a == "kind" and b == "vector")} for t in v]
                d[k] = v
            o[sect][n] = d
    if u["constants"]:
        o["constants"] = u["constants"]
    return o


def _natural_stride(u, r):
    sp = u["spaces"].get(r.get("space")) if r.get("space") else None
    return 1 if sp and sp["unit"] == "reg" else r.get("width", 32) // 8


def emit_unit(u, header=""):
    t = trimmed(u)
    out = [header] if header else []
    top = {k: v for k, v in t.items() if k not in ("c", "spaces", "enums", "registers", "words", "constants")}
    _scalars(top, "", out)
    if "c" in t:
        c = dict(t["c"])
        aliases = c.pop("aliases", {})
        if c:
            out += ["", "[c]"]
            _scalars(c, "", out)
        if aliases:
            out += ["", "[c.aliases]"]
            for k, v in sorted(aliases.items()):
                out.append("%s = %s" % (_key(k), _s(v)))
    for n, s in t.get("spaces", {}).items():
        out += ["", "[spaces.%s]" % _key(n)]
        _scalars(s, "", out)
    for n, e in t.get("enums", {}).items():
        out += ["", "[enums.%s]" % _key(n)]
        if e.get("doc"):
            out.append("doc = %s" % _s(e["doc"]))
        out += ["", "[enums.%s.values]" % _key(n)]
        for lab, ev in e["values"].items():
            out.append("%s = %s" % (_key(lab), _inline(ev, "enum")))
    for sect in ("registers", "words"):
        for n, x in t.get(sect, {}).items():
            out += ["", "[%s.%s]" % (sect, _key(n))]
            _scalars(x, "", out, skip=("fields", "tests"))
            fl = x.get("fields", {})
            simple = {f: v for f, v in fl.items() if set(v) <= {"bits", "grade", "from", "enum"}}
            cplx = {f: v for f, v in fl.items() if f not in simple}
            if simple:
                out += ["", "[%s.%s.fields]" % (sect, _key(n))]
                for f, v in simple.items():
                    out.append("%s = %s" % (_key(f), _inline(v)))
            for f, v in cplx.items():
                out += ["", "[%s.%s.fields.%s]" % (sect, _key(n), _key(f))]
                _scalars(v, "", out, skip=("enums",))
                if v.get("enums"):
                    out += ["", "[%s.%s.fields.%s.enums]" % (sect, _key(n), _key(f))]
                    for lab, ev in v["enums"].items():
                        out.append("%s = %s" % (_key(lab), _inline(ev, "enum")))
            for tt in x.get("tests", []):
                out += ["", "[[%s.%s.tests]]" % (sect, _key(n))]
                _scalars(tt, "test", out)
    if t.get("constants"):
        out += ["", "[constants]"]
        for n, k in t["constants"].items():
            out.append("%s = %s" % (_key(n), _inline(k, "const")))
    return "\n".join(out) + "\n"


def emit_check(cfg, header=""):
    """defs/check.toml from the settings dict the importer builds."""
    out = [header] if header else []
    for sect in ("project", "gen", "checks", "banned", "allowlists", "docs_scan"):
        d = cfg.get(sect)
        if not d:
            continue
        plain = {k: v for k, v in d.items() if k != "extra"}
        if plain:
            out += ["", "[%s]" % sect]
            _scalars(plain, "", out)
        for e in d.get("extra", []):
            out += ["", "[[%s.extra]]" % sect]
            _scalars(e, "", out)
    for name, u in cfg.get("units", {}).items():
        out += ["", "[units.%s]" % _key(name)]
        _scalars(u, "", out)
    for c in cfg.get("claims", []):
        out += ["", "[[claims]]"]
        _scalars({k: v for k, v in c.items() if k != "binds"}, "", out)
        if c.get("binds"):
            out.append("binds = [")
            for b in c["binds"]:
                out.append("  %s," % _val("binds", b))
            out.append("]")
    return "\n".join(out).lstrip("\n") + "\n"
