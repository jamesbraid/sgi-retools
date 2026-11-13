"""Load a repo's register maps into validated, normalised units.

    devices/<unit>/registers.toml          one hardware block, word family or table
    devices/<unit>/registers.<rev>.toml    optional revision overlay on <unit>
    devices/<unit>/registers-extra.toml    a second unit kept beside it (its own `unit` name)
    formats/<name>/format.toml             a software data structure, same shape
    tools/config/defs-check.toml           the repo's check settings

A repository that has not moved still has the old shape, which is read as before:

    defs/<unit>.toml, defs/<unit>.<rev>.toml, defs/check.toml

tools/_layout.py decides which one a repository is on. Every problem is collected in
Repo.errors with the file it came from, so one run reports them all. Needs Python 3.11
for tomllib.
"""
import copy
import os
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.exit('error: Python 3.11 or newer is required (tomllib)')

from _layout import Layout  # noqa: E402  (tools/ is on sys.path: see __init__)

from . import schema  # noqa: E402
from .model import RE_UNIT, block_of, normalize  # noqa: E402


class Unit:
    def __init__(self, name, path, raw, layers, dirname=None, stem=None, helpers_path=None):
        self.name = name
        self.path = path            # repo-relative source file that names this unit
        self.raw = raw              # merged source dict
        self.layers = layers        # every source file that contributed
        self.model = normalize(raw)
        self.dir = dirname          # repo-relative directory of the source (None in the old layout)
        self.stem = stem            # source file name without .toml
        self.helpers_path = helpers_path or "defs/%s_helpers.h" % name


class Repo:
    def __init__(self, root):
        self.root = root
        self.layout = Layout(root)
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


def has_defs(root):
    """Whether the repo at root has register maps in either layout."""
    return Layout(root).has_defs()


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
    rel = repo.layout.defs_check_file
    default = {"project": {"name": os.path.basename(os.path.abspath(repo.root))}}
    if not os.path.isfile(os.path.join(repo.root, rel)):
        repo.settings = default
        return
    d = read_toml(repo, rel)
    if d is None:
        repo.settings = default
        return
    for e in schema.validate(schema.CHECK, d, rel):
        repo.err(rel, e)
    d.setdefault("project", {}).setdefault("name", os.path.basename(os.path.abspath(repo.root)))
    repo.settings = d


class Entry:
    """One register-map file found on disk, before it is read."""

    def __init__(self, rel, kind, base=None, rev=None, dirname=None, stem=None, expect=None):
        self.rel = rel
        self.kind = kind            # "base", "extra" or "overlay"
        self.base = base            # overlay: the unit name it patches by default
        self.rev = rev
        self.dir = dirname
        self.stem = stem
        self.expect = expect        # base: the unit name its file position demands (None: any)


def old_entries(repo):
    """defs/<unit>.toml and defs/<unit>.<rev>.toml."""
    out = []
    for src in repo.layout.old_sources():
        f = os.path.basename(src.rel)
        parts = f[:-5].split(".")
        if len(parts) > 2 or not all(RE_UNIT.match(p) for p in parts):
            repo.err(src.rel, "file name must be <unit>.toml or <unit>.<rev>.toml, lower_snake")
        elif len(parts) == 1:
            out.append(Entry(src.rel, "base", expect=parts[0], stem=parts[0]))
        else:
            out.append(Entry(src.rel, "overlay", base=parts[0], rev=parts[1], stem=f[:-5]))
    return out


def new_entries(repo):
    """devices/<unit>/registers*.toml and formats/<name>/format*.toml. A directory holds one base unit,
    named like the directory (hyphens read as underscores), overlays on it and one extra unit."""
    out = []
    for src in repo.layout.register_sources():
        name = os.path.basename(src.dir).replace("-", "_")
        if not RE_UNIT.match(name):
            repo.err(src.dir, "directory name must be lower_snake (hyphens allowed) to hold a register map")
            continue
        if src.kind == "base":
            out.append(Entry(src.rel, "base", expect=name, dirname=src.dir, stem=src.stem))
        elif src.kind == "extra":
            out.append(Entry(src.rel, "extra", dirname=src.dir, stem=src.stem))
        else:
            out.append(Entry(src.rel, "overlay", base=name, rev=src.rev, dirname=src.dir, stem=src.stem))
    return out


def load_repo(root):
    repo = Repo(os.path.abspath(root))
    load_settings(repo)
    entries = new_entries(repo) if repo.layout.defs_mode == "new" else old_entries(repo)
    bases, overlays = {}, []
    meta = {}
    for e in entries:
        rel = e.rel
        doc = read_toml(repo, rel)
        if doc is None:
            continue
        if e.kind == "overlay":
            errs = schema.validate(schema.OVERLAY, doc, rel)
            for er in errs:
                repo.err(rel, er)
            if not errs:
                overlays.append((rel, e.base, e.rev, doc, e))
            continue
        errs = schema.validate(schema.UNIT, doc, rel)
        for er in errs:
            repo.err(rel, er)
        if errs:
            continue
        if e.expect is not None and doc["unit"] != e.expect:
            repo.err(rel, "unit = %r does not match the %s name" % (doc["unit"], "file" if e.dir is None else "directory"))
            continue
        if doc["unit"] in bases:
            repo.err(rel, "unit %r is already defined by %s" % (doc["unit"], bases[doc["unit"]][0]))
            continue
        bases[doc["unit"]] = (rel, doc)
        meta[doc["unit"]] = e
    for name, (rel, doc) in bases.items():
        e = meta[name]
        repo.units[name] = Unit(name, rel, doc, [rel], e.dir, e.stem)
    for rel, base_name, rev, ov, e in overlays:
        src = ov.get("import", base_name)
        if src not in bases:
            repo.err(rel, "imports unit %r, which has no %s" % (src, "defs/%s.toml" % src if e.dir is None else "register map in this layout"))
            continue
        try:
            merged = apply_overlay(bases[src][1], ov, rel, rev)
        except (KeyError, ValueError) as err:
            repo.err(rel, str(err).strip("'\""))
            continue
        errs = schema.validate(schema.UNIT, merged, rel + " (merged)")
        for er in errs:
            repo.err(rel, er)
        if errs:
            continue
        name = merged["unit"]
        if name in repo.units:
            repo.err(rel, "unit %r is already defined by %s" % (name, repo.units[name].path))
            continue
        repo.units[name] = Unit(name, rel, merged, [bases[src][0], rel], e.dir, e.stem)
    for u in repo.units.values():
        u.helpers_path = repo.layout.helpers_file(u)
    for name in repo.settings.get("units", {}):
        if name not in repo.units:
            repo.err(repo.layout.defs_check_file, "[units.%s] names no unit" % name)
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
