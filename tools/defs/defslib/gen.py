"""Render and write the generated tree, and tell when the committed one is stale.

    generated/c/<unit>.h        generated/rust/{Cargo.toml,src/}   generated/python/<unit>.py
    generated/json/<unit>.json  generated/xml/<unit>.xml           devices/<dir>/registers.md
    generated/rust-regs/<unit>.rs  generated/c-regfields/<unit>.h   the export profiles (gen_export.py)
    <legacy header path>        forwarding headers, one per unit that names one

A repository still on the old layout gets the old names: gen/c, gen/rust, gen/py, gen/json,
gen/genxml and gen/docs/<unit>.md (tools/_layout.py maps both). Output is deterministic, so
staleness is a byte comparison.
"""
import os
import re

from . import gen_c, gen_docs, gen_export, gen_genxml, gen_json, gen_py, gen_rust
from .genutil import GenError
from .model import publish_profile

MARK = "generated from "
# The register table written beside a source in the current layout: registers.md, registers.<rev>.md,
# registers-extra.md, format.md. Anything else in those directories is hand-written.
DOC_RE = re.compile(r"^(registers|format)(-extra|\.[a-z][a-z0-9_]*)?\.md$")


def owned(lay, rel):
    """True when defs-gen owns the file: it sits in one of the directories the generator fills and has the
    extension it writes there, so a file it no longer produces (the output of a removed unit, a JSON file
    that cannot carry a banner) is safe to remove. Anything else in generated/ (a README, cargo's target/,
    a stray file) is not its to delete."""
    for kind, ext in (("c", ".h"), ("py", ".py"), ("json", ".json"), ("xml", ".xml")):
        if os.path.dirname(rel) == lay.gen_dir(kind) and rel.endswith(ext):
            return True
    rust = lay.gen_dir("rust")
    return rel == rust + "/Cargo.toml" or (os.path.dirname(rel) == rust + "/src" and rel.endswith(".rs"))


def render(repo, profile=None):
    """Return ({relative path: text}, [errors]) for the whole repo.

    profile is "public" or "internal"; default is the repo's setting."""
    profile = profile or repo.profile
    lay = repo.layout
    new_layout = lay.defs_mode == "new"
    files, errors = {}, []
    forwarding = repo.settings.get("gen", {}).get("forwarding", "on") == "on"
    models = {}
    for name, unit in sorted(repo.units.items()):
        m = unit.model if profile == "internal" else publish_profile(unit.model)
        models[name] = m
        src = unit.path
        try:
            c_rel = lay.gen_file("c", name)
            helpers = None
            if os.path.isfile(os.path.join(repo.root, unit.helpers_path)):
                helpers = gen_c.helpers_rel(name, unit.helpers_path, c_rel)
            files[c_rel] = gen_c.gen_c(m, src, helpers)[0]
            files["%s/src/%s.rs" % (lay.gen_dir("rust"), name)] = gen_rust.gen_rust(m, src)
            files[lay.gen_file("py", name)] = gen_py.gen_py(m, src)
            files[lay.gen_file("json", name)] = gen_json.gen_json(m, src, profile)
            files[lay.gen_file("xml", name)] = gen_genxml.gen_genxml(m, src)
            files[lay.doc_file(unit)] = gen_docs.gen_docs(m, src, profile, banner_first=new_layout)
            legacy = m["c"].get("legacy_header")
            if legacy and forwarding:
                if legacy in files:
                    raise GenError("%s: legacy header %s is also another unit's" % (name, legacy))
                files[legacy] = gen_c.gen_forwarding(m, src, gen_c.rel_include(legacy, c_rel))
        except GenError as e:
            errors.append(str(e))
    if repo.units:
        label = "devices/ and formats/" if new_layout else "defs/"
        files["%s/Cargo.toml" % lay.gen_dir("rust")] = gen_rust.gen_cargo(repo.settings.get("gen", {}).get("rust_crate"), label)
        files["%s/src/lib.rs" % lay.gen_dir("rust")] = gen_rust.gen_lib(list(repo.units), label)
    exported, errs = gen_export.render_export(repo, models, gen_export.source_commit(repo.root))
    files.update(exported)
    errors += errs
    return files, errors


def existing(root):
    """Every generated file on disk, relative to root: the generated tree, and in the current layout
    the register tables that sit beside their sources."""
    from _layout import Layout
    lay = Layout(root)
    found = []
    base = os.path.join(root, lay.gen_root())
    for d, _dirs, names in os.walk(base):
        for n in names:
            found.append(os.path.relpath(os.path.join(d, n), root))
    if lay.defs_mode == "new":
        for top in ("devices", "formats"):
            tdir = os.path.join(root, top)
            if not os.path.isdir(tdir):
                continue
            for sub in sorted(os.listdir(tdir)):
                d = os.path.join(tdir, sub)
                if os.path.isdir(d):
                    found += ["%s/%s/%s" % (top, sub, n) for n in sorted(os.listdir(d)) if DOC_RE.match(n)]
    return sorted(found)


def in_scope(rel, scope):
    return scope is None or rel.startswith(scope.rstrip("/") + "/")


def stale(repo, files, scope=None):
    """Problems: files missing, differing, or present with no source. `scope` limits the check to one
    directory of the generated tree. The commit in an export banner is not compared: it changes with every
    commit, and the content it labels does not."""
    probs = []
    for rel, text in sorted(files.items()):
        if not in_scope(rel, scope):
            continue
        path = os.path.join(repo.root, rel)
        try:
            with open(path, encoding="utf-8") as f:
                have = f.read()
        except OSError:
            probs.append("%s: missing; run defs-gen" % rel)
            continue
        if gen_export.mask_commit(have) != gen_export.mask_commit(text):
            probs.append("%s: stale against its source; run defs-gen" % rel)
    for rel in existing(repo.root):
        if rel not in files and in_scope(rel, scope):
            probs.append("%s: no unit generates this file; run defs-gen to remove it" % rel)
    return probs


def write(repo, files, scope=None):
    """Write every file, and remove leftovers: any file of a directory the generator owns (see owned), and
    any other file in the generated tree that carries the generator banner. Returns
    (written, removed, kept_unrecognised)."""
    written, removed, kept = [], [], []
    for rel, text in sorted(files.items()):
        if not in_scope(rel, scope):
            continue
        path = os.path.join(repo.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, encoding="utf-8") as f:
                same = gen_export.mask_commit(f.read()) == gen_export.mask_commit(text)
        except OSError:
            same = False
        if not same:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            written.append(rel)
    for rel in existing(repo.root):
        if rel in files or not in_scope(rel, scope):
            continue
        path = os.path.join(repo.root, rel)
        try:
            with open(path, encoding="utf-8") as f:
                head = f.read(400)
        except (OSError, UnicodeDecodeError):
            head = ""
        if owned(repo.layout, rel) or (MARK in head and "defs-gen" in head) or "@generated by defs-gen" in head:
            os.remove(path)
            removed.append(rel)
        else:
            kept.append(rel)
    return written, removed, kept
