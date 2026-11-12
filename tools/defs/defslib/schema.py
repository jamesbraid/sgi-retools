"""Strict schema for a unit file and for a revision overlay.

Hand-written so retools needs nothing beyond the standard library. Unknown
keys, wrong types, a missing grade or a bad grade value are all errors, each
reported with the path of the offending key.
"""
import re

from .model import ACCESS, GRADES, RE_CONST, RE_LABEL, RE_PREFIX, RE_REG, RE_UNIT, RE_WORD


class Rule:
    """check(value, path, errors) appends to errors."""

    def check(self, v, path, errs):
        raise NotImplementedError


class Str(Rule):
    def __init__(self, pattern=None, minlen=0):
        self.rx = re.compile(pattern) if pattern else None
        self.minlen = minlen

    def check(self, v, path, errs):
        if not isinstance(v, str):
            errs.append("%s: must be a string" % path)
        elif len(v) < self.minlen:
            errs.append("%s: must not be empty" % path)
        elif self.rx and not self.rx.match(v):
            errs.append("%s: %r does not match %s" % (path, v, self.rx.pattern))


class Int(Rule):
    def __init__(self, lo=0, choices=None):
        self.lo = lo
        self.choices = choices

    def check(self, v, path, errs):
        if isinstance(v, bool) or not isinstance(v, int):
            errs.append("%s: must be an integer" % path)
        elif v < self.lo:
            errs.append("%s: must be at least %d" % (path, self.lo))
        elif self.choices and v not in self.choices:
            errs.append("%s: must be one of %s" % (path, ", ".join(map(str, self.choices))))


class Choice(Rule):
    def __init__(self, *values):
        self.values = values

    def check(self, v, path, errs):
        if not isinstance(v, str) or v not in self.values:
            errs.append("%s: must be one of %s" % (path, ", ".join(self.values)))


class Arr(Rule):
    def __init__(self, item, minlen=0, maxlen=None):
        self.item, self.minlen, self.maxlen = item, minlen, maxlen

    def check(self, v, path, errs):
        if not isinstance(v, list):
            errs.append("%s: must be an array" % path)
            return
        if len(v) < self.minlen or (self.maxlen is not None and len(v) > self.maxlen):
            errs.append("%s: needs %d..%s entries" % (path, self.minlen, self.maxlen if self.maxlen is not None else "n"))
        for i, x in enumerate(v):
            self.item.check(x, "%s[%d]" % (path, i), errs)


class Bool(Rule):
    def check(self, v, path, errs):
        if not isinstance(v, bool):
            errs.append("%s: must be true or false" % path)


class Any(Rule):
    def __init__(self, *rules):
        self.rules = rules

    def check(self, v, path, errs):
        why = []
        for r in self.rules:
            e = []
            r.check(v, path, e)
            if not e:
                return
            why.append(e[0].split(": ", 1)[1])
        errs.append("%s: %s" % (path, "; or ".join(why)))


class Obj(Rule):
    def __init__(self, props, required=()):
        self.props, self.required = props, tuple(required)

    def check(self, v, path, errs):
        if not isinstance(v, dict):
            errs.append("%s: must be a table" % path)
            return
        for k in self.required:
            if k not in v:
                errs.append("%s: missing required key %r" % (path, k))
        for k, x in v.items():
            if k not in self.props:
                errs.append("%s: unknown key %r" % (path, k))
            else:
                self.props[k].check(x, "%s.%s" % (path, k), errs)


class Map(Rule):
    """A table whose keys are names matching `key` and whose values follow `val`."""

    def __init__(self, key, val, what="name"):
        self.key, self.val, self.what = re.compile(key), val, what

    def check(self, v, path, errs):
        if not isinstance(v, dict):
            errs.append("%s: must be a table" % path)
            return
        for k, x in v.items():
            if not self.key.match(k):
                errs.append("%s: %s %r is not valid" % (path, self.what, k))
            self.val.check(x, "%s.%s" % (path, k), errs)


GRADE = Choice(*GRADES)
UINT = Int(0)
TEXT = Str()
SOURCE = Str(minlen=1)

ENUM_VALUE = Obj({"value": UINT, "grade": GRADE, "from": SOURCE, "doc": TEXT}, required=("value", "grade"))
ENUM_VALUES = Map(RE_LABEL.pattern, ENUM_VALUE, "enum label")
FIELD = Obj({
    "bits": Arr(UINT, 2, 2), "grade": GRADE, "from": SOURCE, "doc": TEXT, "notes": TEXT,
    "enum": Str(RE_LABEL.pattern), "enums": ENUM_VALUES,
}, required=("bits", "grade"))
FIELDS = Map(RE_REG.pattern, FIELD, "field name")
TEST = Obj({
    "value": UINT, "kind": Choice("vector", "example"),
    "expect": Map(RE_REG.pattern, Any(UINT, Str(r"^@[\w.]+$")), "field name"),
}, required=("value", "expect"))
TESTS = Arr(TEST)
REGISTER = Obj({
    "offset": UINT, "access": Choice(*ACCESS), "width": Int(0, (8, 16, 32, 64)),
    "count": Int(1), "stride": Int(1), "space": Str(RE_REG.pattern),
    "reset": Any(UINT, Choice("unknown")),
    "grade": GRADE, "from": SOURCE, "doc": TEXT, "notes": TEXT, "fields": FIELDS, "tests": TESTS,
}, required=("offset", "access", "width", "grade"))
WORD = Obj({
    "width": Int(0, (8, 16, 32, 64)), "grade": GRADE, "from": SOURCE, "doc": TEXT, "notes": TEXT,
    "type_name": TEXT, "fields": FIELDS, "tests": TESTS,
}, required=("width", "grade"))
CONSTANT = Obj({
    "value": UINT, "grade": GRADE, "from": SOURCE, "doc": TEXT, "count": Int(2), "stride": Int(1),
    "macro": Str(r"^[A-Za-z_][A-Za-z0-9_]*$"),
}, required=("value", "grade"))
C_OPTIONS = Obj({
    "offset_macro": Choice("suffix", "bare"), "const_prefix": Str(RE_PREFIX.pattern),
    "legacy_header": Str(minlen=1), "legacy_guard": Str(r"^[A-Za-z_][A-Za-z0-9_]*$"),
    "aliases": Map(r"^[A-Za-z_][A-Za-z0-9_]*$", Str(minlen=1), "macro name"),
})
SPACE = Obj({"unit": Choice("byte", "reg"), "doc": TEXT})

UNIT = Obj({
    "unit": Str(RE_UNIT.pattern), "prefix": Str(RE_PREFIX.pattern), "block": Str(RE_PREFIX.pattern),
    "title": TEXT, "doc": TEXT, "from": SOURCE, "public_from": Arr(Str(minlen=1)),
    "c": C_OPTIONS,
    "spaces": Map(RE_REG.pattern, SPACE, "space name"),
    "enums": Map(RE_LABEL.pattern, Obj({"doc": TEXT, "values": ENUM_VALUES}, required=("values",)), "enum name"),
    "registers": Map(RE_REG.pattern, REGISTER, "register name"),
    "words": Map(RE_WORD.pattern, WORD, "word name"),
    "constants": Map(RE_CONST.pattern, CONSTANT, "constant name"),
}, required=("unit", "prefix"))

# A revision overlay: defs/<unit>.<rev>.toml. `import` defaults to <unit>.
PATCH_PROPS = Obj({
    "grade": GRADE, "from": SOURCE, "doc": TEXT, "notes": TEXT, "title": TEXT,
    "offset": UINT, "access": Choice(*ACCESS), "width": Int(0, (8, 16, 32, 64)), "count": Int(1),
    "stride": Int(1), "space": Str(RE_REG.pattern), "reset": Any(UINT, Choice("unknown")),
    "bits": Arr(UINT, 2, 2), "value": UINT, "enum": Str(RE_LABEL.pattern), "type_name": TEXT,
})
OVERLAY = Obj({
    "import": Str(RE_UNIT.pattern),
    "override": Obj({
        "unit": Str(RE_UNIT.pattern), "prefix": Str(RE_PREFIX.pattern), "block": Str(RE_PREFIX.pattern),
        "title": TEXT, "doc": TEXT, "from": SOURCE, "public_from": Arr(Str(minlen=1)), "c": C_OPTIONS,
    }),
    "patch": Map(r"^(registers|words|constants|enums)\.[\w]+(\.fields\.[\w]+)?(\.values\.[\w]+)?$", PATCH_PROPS, "patch path"),
    "add": Obj({
        "spaces": UNIT.props["spaces"], "enums": UNIT.props["enums"], "registers": UNIT.props["registers"],
        "words": UNIT.props["words"], "constants": UNIT.props["constants"],
    }),
    "remove": Arr(Str(minlen=1)),
})

# defs/check.toml
CHECK = Obj({
    "project": Obj({"name": Str(minlen=1), "plugin": Str(minlen=1), "regenerate": TEXT}, required=("name",)),
    "gen": Obj({"profile": Choice("public", "internal"), "forwarding": Choice("on", "off"),
                "rust_crate": Str(r"^[a-z][a-z0-9_-]*$")}),
    "checks": Obj({"address_bits": Int(1), "max_reg_offset": UINT}),
    "banned": Obj({
        "skip": Arr(Str()), "allow_includes": Arr(Str()),
        "extra": Arr(Obj({"label": Str(minlen=1), "regex": Str(minlen=1)}, required=("label", "regex"))),
    }),
    "allowlists": Obj({"source_names": Str(), "copy": Str(), "leak": Str()}),
    "docs_scan": Obj({"paths": Arr(Str()), "rules": Arr(Str())}),
    "units": Map(RE_UNIT.pattern, Obj({
        "group": Str(minlen=1), "notes_corpus": Arr(Str(minlen=1)), "no_addresses": Bool(),
        "size_limit_macro": Str(), "address_field_prefix": Str(), "plugin_form": Choice("regs", "legacy"),
        "prose_offsets": Bool(),
    }), "unit name"),
    "claims": Arr(Obj({
        "group": Str(minlen=1), "label": Str(minlen=1), "doc": Str(minlen=1), "regex": Str(minlen=1),
        "binds": Arr(Arr(Any(Str(), Int(-10 ** 9), Arr(Str())))),
    }, required=("group", "label", "doc", "regex"))),
})


def validate(rule, doc, where):
    errs = []
    rule.check(doc, where, errs)
    return errs
