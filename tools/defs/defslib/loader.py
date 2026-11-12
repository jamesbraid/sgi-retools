"""Load a repo's defs/ directory into validated, normalised units.

    defs/<unit>.toml          one hardware block, word family or table
    defs/<unit>.<rev>.toml    optional revision overlay on <unit>
    defs/check.toml           the repo's check settings

Every problem is collected in Repo.errors with the file it came from, so one
run reports them all. Needs Python 3.11 for tomllib.
"""
import copy
import os
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.exit('error: Python 3.11 or newer is required (tomllib)')

from . import schema
from .model import RE_UNIT, block_of, normalize

DEFS_DIR = "defs"
CHECK_FILE = "check.toml"


class Unit:
    def __init__(self, name, path, raw, layers):
        self.name = name
        self.path = path            # repo-relative source file that names this unit
        self.raw = raw              # merged source dict
        self.layers = layers        # every source file that contributed
        self.model = normalize(raw)

    @property
    def helpers_path(self):
        return "%s/%s_helpers.h" % (DEFS_DIR, self.name)


class Repo:
    def __init__(self, root):
        self.root = root
        self.settings = {}
        self.units = {}
        self.errors = []

    def err(self, where, msg):
        self.errors.append("%s: %s" % (where, msg))

    @property
    def project(self):
        return self.settings["project"]["name"]

    @property
    def profile(self):
        return self.settings.get("gen", {}).get("profile", "public")


def defs_dir(root):
    return os.path.join(root, DEFS_DIR)


def has_defs(root):
    return os.path.isdir(defs_dir(root))


def read_toml(repo, rel):
    try:
        with open(os.path.join(repo.root, rel), "rb") as f:
            return tomllib.load(f)
    except OSError as e:
        repo.err(rel, "cannot read: %s" % e)
    except tomllib.TOMLDecodeError as e:
        repo.err(rel, "TOML error: %s" % e)
    return None


def _walk(node, parts, where):
    for p in parts:
        if not isinstance(node, dict) or p not in node:
            raise KeyError("%s: no such item %s" % (where, ".".join(parts)))
        node = node[p]
    return node


def apply_overlay(base, ov, where, rev):
    """Return the merged source dict, or raise KeyError/ValueError naming the problem."""
    u = copy.deepcopy(base)
    # A revision does not take over the base's old header path or old names.
    if "c" in u:
        for k in ("legacy_header", "legacy_guard", "aliases"):
            u["c"].pop(k, None)
    for k, v in ov.get("override", {}).items():
        u[k] = v
    if "unit" not in ov.get("override", {}):
        u["unit"] = "%s_%s" % (base["unit"], rev)
    if "prefix" not in ov.get("override", {}):
        u["prefix"] = "%s_%s" % (base["prefix"], rev.upper())
    for path in ov.get("remove", []):
        parts = path.split(".")
        parent = _walk(u, parts[:-1], where)
        if parts[-1] not in parent:
            raise KeyError("%s: remove: no such item %s" % (where, path))
        del parent[parts[-1]]
    for path, props in ov.get("patch", {}).items():
        node = _walk(u, path.split("."), where)
        node.update(props)
    for sect, nodes in ov.get("add", {}).items():
        dest = u.setdefault(sect, {})
        for n, v in nodes.items():
            if n in dest:
                raise ValueError("%s: add.%s.%s already exists in the base; use patch" % (where, sect, n))
            dest[n] = v
    return u


def load_settings(repo):
    rel = "%s/%s" % (DEFS_DIR, CHECK_FILE)
    if not os.path.isfile(os.path.join(repo.root, rel)):
        repo.settings = {"project": {"name": os.path.basename(os.path.abspath(repo.root))}}
        return
    d = read_toml(repo, rel)
    if d is None:
        repo.settings = {"project": {"name": os.path.basename(os.path.abspath(repo.root))}}
        return
    for e in schema.validate(schema.CHECK, d, rel):
        repo.err(rel, e)
    d.setdefault("project", {}).setdefault("name", os.path.basename(os.path.abspath(repo.root)))
    repo.settings = d


def load_repo(root):
    repo = Repo(os.path.abspath(root))
    load_settings(repo)
    d = defs_dir(repo.root)
    files = sorted(f for f in os.listdir(d) if f.endswith(".toml") and f != CHECK_FILE)
    bases, overlays = {}, []
    for f in files:
        rel = "%s/%s" % (DEFS_DIR, f)
        parts = f[:-5].split(".")
        if len(parts) > 2 or not all(RE_UNIT.match(p) for p in parts):
            repo.err(rel, "file name must be <unit>.toml or <unit>.<rev>.toml, lower_snake")
            continue
        doc = read_toml(repo, rel)
        if doc is None:
            continue
        if len(parts) == 1:
            errs = schema.validate(schema.UNIT, doc, rel)
            for e in errs:
                repo.err(rel, e)
            if errs:
                continue
            if doc["unit"] != parts[0]:
                repo.err(rel, "unit = %r does not match the file name" % doc["unit"])
                continue
            bases[parts[0]] = (rel, doc)
        else:
            errs = schema.validate(schema.OVERLAY, doc, rel)
            for e in errs:
                repo.err(rel, e)
            if not errs:
                overlays.append((rel, parts[0], parts[1], doc))
    for name, (rel, doc) in bases.items():
        repo.units[name] = Unit(name, rel, doc, [rel])
    for rel, base_name, rev, ov in overlays:
        src = ov.get("import", base_name)
        if src not in bases:
            repo.err(rel, "imports unit %r, which has no defs/%s.toml" % (src, src))
            continue
        try:
            merged = apply_overlay(bases[src][1], ov, rel, rev)
        except (KeyError, ValueError) as e:
            repo.err(rel, str(e).strip("'\""))
            continue
        errs = schema.validate(schema.UNIT, merged, rel + " (merged)")
        for e in errs:
            repo.err(rel, e)
        if errs:
            continue
        name = merged["unit"]
        if name in repo.units:
            repo.err(rel, "unit %r is already defined by %s" % (name, repo.units[name].path))
            continue
        repo.units[name] = Unit(name, rel, merged, [bases[src][0], rel])
    for name in repo.settings.get("units", {}):
        if name not in repo.units:
            repo.err("%s/%s" % (DEFS_DIR, CHECK_FILE), "[units.%s] names no unit" % name)
    resolve_refs(repo)
    return repo


def resolve_refs(repo):
    """Replace "@register" test expectations with that register's offset.
    "@name" looks in the unit, "@BLOCK.name" in any unit with that block."""
    by_block = {}
    for u in repo.units.values():
        for n, r in u.model["registers"].items():
            by_block["%s.%s" % (block_of(u.model), n)] = r["offset"]
    for u in repo.units.values():
        m = u.model
        for sect in ("registers", "words"):
            for name, x in m[sect].items():
                for t in x["tests"]:
                    for fn, v in list(t["expect"].items()):
                        if not isinstance(v, str):
                            continue
                        ref = v[1:]
                        if ref in m["registers"]:
                            t["expect"][fn] = m["registers"][ref]["offset"]
                        elif ref in by_block:
                            t["expect"][fn] = by_block[ref]
                        else:
                            repo.err(u.path, "%s test 0x%x: %s refers to unknown register %s" % (name, t["value"], fn, v))
                            t["expect"][fn] = -1
