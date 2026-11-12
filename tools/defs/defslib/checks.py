"""The checks over a loaded repo: layout, leaks, prose, notes, plugins, freshness.

The leak and prose rules are the ones check-publish-safe.py applies to the old
decode headers. They are shared with it (publish_check.py), fed from the model
and from the public-profile rendering of the generated files instead of from
header text.

Exit semantics for callers: run() returns 0 clean, 1 a check failed, 2 a setup
problem (a source file does not load, a prose document or plugin is missing).
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import publish_check as pc  # noqa: E402
from defs_common import Report  # noqa: E402

from . import gen, loader, modelcheck  # noqa: E402
from .genutil import GenError  # noqa: E402
from .model import block_of, decode, enum_values, fwidth, mask  # noqa: E402

LEGACY_LINE = 0


class Setup(Exception):
    """A problem with the setup, not with the definitions (exit 2)."""


# ---------------------------------------------------------------------------
# Model views in the shapes the shared checks and plugins already use
# ---------------------------------------------------------------------------
def eval_c(expr, names):
    """Value of a C integer expression over known macro names, else None."""
    if not re.fullmatch(r"[\w\s()|&^~<>+*-]*", expr):
        return None
    py = re.sub(r"\b(0x[0-9a-fA-F]+|\d+)[uUlL]*\b", r"\1", expr)

    def sub(m):
        return str(names[m.group(0)]) if m.group(0) in names else m.group(0)
    py = re.sub(r"\b[A-Za-z_]\w*\b", sub, py)
    if re.search(r"[A-Za-z_]", py):
        return None
    try:
        return int(eval(py, {"__builtins__": {}}, {}))  # noqa: S307 - digits and operators only, checked above
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError):
        return None


def legacy_annotations(m):
    """The unit as the old comment grammar (REG, WORD, FIELD, ENUM, TESTVEC lines), for plugins that
    read header text. Only plugins see this; it is not part of any output."""
    blk = block_of(m)
    out = ["/* the old annotation grammar, regenerated from the model for repo plugins */"]
    for n, w in m["words"].items():
        out.append("/* WORD: %s %d */" % (n, w["width"]))
    for n, r in m["registers"].items():
        out.append("/* REG: %s.%s 0x%03x %s%d%s%s reset=%s %s */" % (
            blk, n, r["offset"], r["access"], r["width"], " count=%d" % r["count"] if r["count"] > 1 else "",
            " space=%s" % r["space"] if r["space"] else "",
            hex(r["reset"]) if isinstance(r["reset"], int) else "unknown", r["grade"]))
    for sect, owner_of in (("registers", lambda n: "%s.%s" % (blk, n)), ("words", lambda n: n)):
        for n, x in m[sect].items():
            for fn, f in x["fields"].items():
                key = "%s.%s" % (owner_of(n), fn)
                out.append("/* FIELD: %s %d:%d %s */" % (key, f["bits"][0], f["bits"][1], f["grade"]))
                for lab, ev in enum_values(m, f).items():
                    out.append("/* ENUM: %s %d %s %s */" % (key, ev["value"], lab, ev["grade"]))
    tests = []
    for sect, owner_of in (("registers", lambda n: "%s.%s" % (blk, n)), ("words", lambda n: n)):
        for n, x in m[sect].items():
            for t in x["tests"]:
                kind = "TESTVEC" if t["kind"] == "vector" else "EXAMPLE (unverified)"
                vals = decode(x["fields"], t["value"])
                tests.append(" * %s: 0x%x as %s => %s" % (kind, t["value"], owner_of(n),
                                                          ", ".join("%s=%d" % (k, vals[k]) for k in t["expect"] if k in vals)))
    if tests:
        out.append("/*\n" + "\n *\n".join(tests) + "\n */")
    return "\n".join(out) + "\n"


def macro_values(unit, c_names):
    """Generated macros plus every alias that evaluates."""
    names = dict(c_names)
    pending = dict(unit.model["c"]["aliases"])
    for _ in range(len(pending) + 1):
        progressed = False
        for old, expr in list(pending.items()):
            v = eval_c(expr, names)
            if v is not None:
                names[old] = v
                del pending[old]
                progressed = True
        if not pending or not progressed:
            break
    return names


def views(unit, c_names):
    """(regs, fields, widths, enums, defs, vecs_regs_form, vecs_legacy) for one unit."""
    m = unit.model
    blk = block_of(m)
    regs, fields, widths, enums = {}, {}, {}, {}
    vecs, legacy = [], {}
    for n, r in m["registers"].items():
        key = "%s.%s" % (blk, n)
        regs[key] = dict(off=r["offset"], acc=r["access"], width=r["width"], count=r["count"],
                         reset="unknown" if r["reset"] == "unknown" else hex(r["reset"]), grade=r["grade"],
                         line=LEGACY_LINE, space=r["space"])
    for sect, owner_of in (("registers", lambda n: "%s.%s" % (blk, n)), ("words", lambda n: n)):
        for n, x in m[sect].items():
            owner = owner_of(n)
            for fn, f in x["fields"].items():
                key = "%s.%s" % (owner, fn)
                fields[key] = (f["bits"][0], f["bits"][1], f["grade"], LEGACY_LINE, owner)
                widths[key] = x["width"]
                for lab, ev in enum_values(m, f).items():
                    enums[(key, lab)] = ev["value"]
            for t in x["tests"]:
                vals = decode(x["fields"], t["value"])
                vals = {k: vals[k] for k in t["expect"] if k in vals}
                kind = "TESTVEC" if t["kind"] == "vector" else "EXAMPLE (unverified)"
                vecs.append((kind, t["value"], owner, vals, LEGACY_LINE))
                if t["kind"] == "vector":
                    legacy[(t["value"], owner)] = vals
    return regs, fields, widths, enums, macro_values(unit, c_names), vecs, legacy


# ---------------------------------------------------------------------------
# The check run
# ---------------------------------------------------------------------------
class Run:
    def __init__(self, repo, verbose=False):
        self.repo = repo
        self.verbose = verbose
        self.rep = Report()
        self.files, self.render_errors = {}, []
        self.c_names = {}

    @property
    def settings(self):
        return self.repo.settings

    def unit_setting(self, unit, key, default=None):
        return self.settings.get("units", {}).get(unit, {}).get(key, default)

    def group_of(self, unit):
        return self.unit_setting(unit, "group", unit)


def synth_config(repo, files, extra_headers):
    """The cfg shape publish_check.Ctx and banned_rules expect."""
    s = repo.settings
    cfg = {k: s[k] for k in ("checks", "banned", "allowlists", "docs_scan", "claims") if k in s}
    cfg["project"] = s.get("project", {})
    own = {os.path.basename(rel) for rel in files if rel.endswith(".h")}
    own |= {os.path.basename(h) for h in extra_headers}
    cfg["headers"] = [{"file": n} for n in sorted(own)]
    return cfg


def load_plugin(repo):
    rel = repo.settings.get("project", {}).get("plugin")
    if not rel:
        return None
    full = os.path.join(repo.root, rel)
    if not os.path.isfile(full):
        raise Setup("plugin %s does not exist" % rel)
    spec = importlib.util.spec_from_file_location("defs_plugin", full)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.dirname(full))
    spec.loader.exec_module(mod)
    return mod


def check_leaks(ctx, texts, project):
    """Banned content over the public-profile rendering of every generated file.
    Generated Rust must not name the project at all, as the old Rust check required."""
    named = re.compile(r"(?i)\b%s\b" % re.escape(project))
    for rel, text in sorted(texts.items()):
        pc.check_banned(ctx, rel, text)
        if rel.startswith("gen/rust/"):
            for n, line in enumerate(text.splitlines(), 1):
                if named.search(line):
                    ctx.rep.fail("%s:%d" % (rel, n), "banned content (project name in generated Rust) %r in: %s"
                                 % (project, line.strip()))


def prose_literals(run, ctx, unit, allregs):
    """A register offset must not be spelled out in prose: write the name."""
    m = unit.model
    offs = set()
    for r in allregs.values():
        if r["off"] >= 0x100:
            offs.add(r["off"])
            if r["count"] <= 64:
                offs.update(range(r["off"], r["off"] + r["count"]))
    pieces = [("title", m.get("title", "")), ("doc", m.get("doc", ""))]
    for sect in ("registers", "words", "constants"):
        for n, x in m[sect].items():
            pieces.append(("%s.%s doc" % (sect, n), x.get("doc", "")))
            for fn, f in x.get("fields", {}).items():
                pieces.append(("%s.%s.%s doc" % (sect, n, fn), f.get("doc", "")))
    for n, e in m["enums"].items():
        pieces.append(("enum.%s doc" % n, e.get("doc", "")))
    for where, text in pieces:
        for line in text.splitlines():
            for mm in pc.HEXLIT_RE.finditer(line):
                tok = mm.group(0)
                v = int(tok, 16)
                reason = None
                if v in offs:
                    reason = "a register offset"
                elif len(tok) - 2 == 4 and 0x1000 <= v <= ctx.max_reg_addr and (v + 1) & v:
                    reason = "a 4-digit value in the register address space"
                if reason:
                    run.rep.fail("%s %s" % (unit.path, where), "%s (%s) in prose; write the register name, not the number: %s"
                                 % (tok, reason, line.strip()))


def notes_corpus(run, ctx, unit):
    docs = run.unit_setting(unit.name, "notes_corpus")
    if not docs:
        return
    hexes = pc.corpus_hex(ctx, docs)
    for sect in ("registers", "words"):
        for n, x in unit.model[sect].items():
            for t in x["tests"]:
                if t["kind"] == "vector" and t["value"] not in hexes:
                    run.rep.fail("%s %s test 0x%x" % (unit.path, n, t["value"]),
                                 "vector value 0x%x is not recorded in the notes; make it an example" % t["value"])


def no_addresses(run, unit, c_text, fields):
    """For descriptors that must carry no address value. Scans the generated header
    and the unit's hand-written helpers, then the vectors. Returns the address fields."""
    for rel, text in (("gen/c/%s.h" % unit.name, c_text), (unit.helpers_path, helpers_text(run, unit))):
        if text:
            _no_addresses_in(run, unit, rel, text)
    _vector_rules(run, unit)
    pfx = run.unit_setting(unit.name, "address_field_prefix", "addr")
    return [k for k in fields if k.split(".")[-1].startswith(pfx)]


def helpers_text(run, unit):
    path = os.path.join(run.repo.root, unit.helpers_path)
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8") as f:
        return f.read()


def _no_addresses_in(run, unit, rel, c_text):
    rep = run.rep
    limit = run.unit_setting(unit.name, "size_limit_macro")
    for n, line in enumerate(c_text.splitlines(), 1):
        where = "%s:%d" % (rel, n)
        m = pc.DEC_BIG_RE.search(line)
        if m:
            rep.fail(where, "decimal literal %s could be an address: %s" % (m.group(0), line.strip()))
        dm = re.match(r"^#define\s+(\w+)\s+(.*)$", line)
        name = dm.group(1) if dm else None
        for hm in pc.HEXLIT_RE.finditer(line):
            tok = hm.group(0)
            v = int(tok, 16)
            if len(tok) - 2 < 5:
                continue
            if name and name.endswith("_MASK") and pc.is_mask(v):
                continue
            if limit and name == limit:
                continue
            rep.fail(where, "hex literal %s (5+ digits) could be an address; only a contiguous MASK%s may be this wide: %s"
                     % (tok, " or " + limit if limit else "", line.strip()))
        if name and "ADDR" in name and not re.search(r"_(SHIFT|MASK|BITS|INPLACE)$", name):
            rep.fail(where, "address macro %s is not a SHIFT, MASK, BITS or INPLACE (values are omitted): %s" % (name, line.strip()))


def _vector_rules(run, unit):
    """No vector may set bits in, or name, an address field."""
    rep = run.rep
    pfx = run.unit_setting(unit.name, "address_field_prefix", "addr")
    m = unit.model
    for sect in ("registers", "words"):
        for n, x in m[sect].items():
            for t in x["tests"]:
                for fn, f in x["fields"].items():
                    if not fn.startswith(pfx):
                        continue
                    if (t["value"] >> f["bits"][1]) & mask(fwidth(f)):
                        rep.fail("%s %s test 0x%x" % (unit.path, n, t["value"]),
                                 "0x%x sets bits in address field %s; vectors carry no address" % (t["value"], fn))
                    if fn in t["expect"]:
                        rep.fail("%s %s test 0x%x" % (unit.path, n, t["value"]), "vector names address field %s" % fn)


def run_checks(repo, verbose=False, fresh=True, only=None):
    """Run every check; return (exit_status, Run)."""
    run = Run(repo, verbose)
    rep = run.rep
    if repo.errors:
        raise Setup("\n".join(repo.errors))
    units = [u for u in repo.units.values() if not only or u.name in only]
    for name in only or ():
        if name not in repo.units:
            raise Setup("%s is not a unit (%s)" % (name, ", ".join(sorted(repo.units))))

    # 1. layout
    for u in units:
        for p in modelcheck.check_unit(u.model, repo.settings):
            rep.fail(u.path, p)
    for p in modelcheck.check_overlap([u.model for u in repo.units.values()]):
        rep.fail("registers", p)

    # 2. render: the committed profile for staleness, the public one for the leak check
    files, errs = gen.render(repo)
    if errs:
        for e in errs:
            rep.fail("generate", e)
        return 1, run
    pub = files if repo.profile == "public" else gen.render(repo, "public")[0]
    run.files = files

    # 3. context shared with the old checks
    legacy_paths = [u.model["c"]["legacy_header"] for u in repo.units.values() if u.model["c"].get("legacy_header")]
    helper_paths = [u.helpers_path for u in repo.units.values() if os.path.isfile(os.path.join(repo.root, u.helpers_path))]
    cfg = synth_config(repo, files, legacy_paths + helper_paths)
    ctx = pc.Ctx(cfg, repo.root, rep, verbose)
    ctx.allow_names = pc.load_allow(ctx, "source_names") | pc.load_allow(ctx, "copy")
    ctx.allow_terms = pc.load_allow(ctx, "leak")
    ctx.rules = pc.banned_rules(ctx)

    # 4. leaks: every public rendering, plus the hand-written helper files
    selected = {rel: text for rel, text in pub.items()
                if not only or any(rel.endswith("/%s.%s" % (n, e)) for n in only for e in ("h", "rs", "py", "json", "xml", "md"))
                or rel in legacy_paths}
    check_leaks(ctx, selected, repo.project)
    for rel in helper_paths:
        if not only or os.path.basename(rel)[:-len("_helpers.h")] in only:
            pc.check_banned(ctx, rel, ctx.read(rel))

    # 5. per-unit views, shared across the prose, vector and plugin checks
    all_views, allregs = {}, {}
    for u in repo.units.values():
        c_text, c_names = _c_names(u, repo)
        all_views[u.name] = (c_text,) + views(u, c_names)
        allregs.update(all_views[u.name][1])
    ctx.allregs = allregs
    plugin = load_plugin(repo)

    hdrs = {}
    for u in repo.units.values():
        c_text, regs, fields, widths, enums, defs, vecs, legacy = all_views[u.name]
        file = u.model["c"].get("legacy_header") or "gen/c/%s.h" % u.name
        hcfg = {"file": file, "block": block_of(u.model) if u.model["registers"] else None,
                "group": run.group_of(u.name), "form": run.unit_setting(u.name, "plugin_form", "regs"),
                "prefix": u.model["prefix"], "no_addresses": run.unit_setting(u.name, "no_addresses", False),
                "notes_corpus": run.unit_setting(u.name, "notes_corpus"),
                "size_limit_macro": run.unit_setting(u.name, "size_limit_macro"),
                "address_field_prefix": run.unit_setting(u.name, "address_field_prefix", "addr")}
        h = pc.Hdr(hcfg, c_text + ("\n" + helpers_text(run, u) if helpers_text(run, u) else "") + "\n" + legacy_annotations(u.model), u in units)
        h.regs, h.fields, h.widths, h.enums, h.defs = regs, fields, widths, enums, defs
        h.vecs = legacy if hcfg["form"] == "legacy" else vecs
        h.unit = u
        hdrs[file] = h
    ctx.hdrs = hdrs

    for u in units:
        c_text = all_views[u.name][0]
        if u.model["registers"] and run.unit_setting(u.name, "prose_offsets", True):
            prose_literals(run, ctx, u, allregs)
        notes_corpus(run, ctx, u)
        h = hdrs[u.model["c"].get("legacy_header") or "gen/c/%s.h" % u.name]
        if run.unit_setting(u.name, "no_addresses"):
            h.addr_fields = no_addresses(run, u, c_text, all_views[u.name][2])
        if plugin and hasattr(plugin, "check_header"):
            plugin.check_header(ctx, h)
        if verbose:
            print("%s: %d registers, %d fields, %d enum values, %d vectors, %d macros"
                  % (u.name, len(h.regs), len(h.fields), len(h.enums), len(h.vecs), len(h.defs)))

    # 6. prose claims, once per group that has a selected unit
    groups = {}
    for h in hdrs.values():
        groups.setdefault(h.group, []).append(h)
    claims = list(repo.settings.get("claims", []))
    if plugin and hasattr(plugin, "CLAIMS"):
        claims += list(plugin.CLAIMS)
    for c in claims:
        if c.get("group", c.get("header")) not in groups:
            raise Setup('claim "%s" names unknown group %r' % (c.get("label"), c.get("group")))
    for gname, members in groups.items():
        if not any(m.selected for m in members):
            continue
        merged = dict(fields={}, regs={}, enums={}, defs={})
        for m in members:
            merged["fields"].update(m.fields)
            merged["regs"].update(m.regs)
            merged["enums"].update(m.enums)
            merged["defs"].update(m.defs)
        label = "/".join(m.unit.path for m in members)
        gclaims = [c for c in claims if c.get("group", c.get("header")) == gname]
        if gclaims:
            pc.check_claims(ctx, label, gclaims, merged["fields"], merged["regs"], merged["enums"], merged["defs"])
        if plugin and hasattr(plugin, "check_group"):
            plugin.check_group(ctx, gname, members)

    if not only:
        pc.check_docs_scan(ctx)
    if plugin and hasattr(plugin, "check_final"):
        plugin.check_final(ctx)

    # 7. the committed tree matches the sources
    if fresh and not only:
        for p in gen.stale(repo, files):
            rep.fail("generated", p)
    return (1 if rep.fails else 0), run


def _c_names(unit, repo):
    from . import gen_c
    from .model import publish_profile
    m = unit.model if repo.profile == "internal" else publish_profile(unit.model)
    helpers = gen_c.helpers_rel(unit.name) if os.path.isfile(os.path.join(repo.root, unit.helpers_path)) else None
    return gen_c.gen_c(m, unit.path, helpers)


def run(root, verbose=False, fresh=True, only=None):
    """Load and check the repo at root; return the exit status."""
    repo = loader.load_repo(root)
    try:
        status, r = run_checks(repo, verbose, fresh, only)
    except Setup as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    except GenError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if r.rep.fails:
        print("%d failure(s)" % len(r.rep.fails))
    else:
        print("ok: %d unit(s) consistent, publish-safe, and the generated tree is %s"
              % (len(repo.units), "fresh" if fresh and not only else "not checked for freshness"))
    return status
