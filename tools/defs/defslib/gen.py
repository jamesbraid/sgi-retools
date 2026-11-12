"""Render and write the generated tree, and tell when the committed one is stale.

    gen/c/<unit>.h            gen/rust/{Cargo.toml,src/}   gen/py/<unit>.py
    gen/json/<unit>.json      gen/genxml/<unit>.xml        gen/docs/<unit>.md
    <legacy header path>      forwarding headers, one per unit that names one

Output is deterministic, so staleness is a byte comparison.
"""
import os

from . import gen_c, gen_docs, gen_genxml, gen_json, gen_py, gen_rust
from .genutil import GenError
from .model import publish_profile

GEN_DIR = "gen"
MARK = "generated from "


def render(repo, profile=None):
    """Return ({relative path: text}, [errors]) for the whole repo.

    profile is "public" or "internal"; default is the repo's setting."""
    profile = profile or repo.profile
    files, errors = {}, []
    forwarding = repo.settings.get("gen", {}).get("forwarding", "on") == "on"
    for name, unit in sorted(repo.units.items()):
        m = unit.model if profile == "internal" else publish_profile(unit.model)
        src = unit.path
        try:
            helpers = gen_c.helpers_rel(name) if os.path.isfile(os.path.join(repo.root, unit.helpers_path)) else None
            files["gen/c/%s.h" % name] = gen_c.gen_c(m, src, helpers)[0]
            files["gen/rust/src/%s.rs" % name] = gen_rust.gen_rust(m, src)
            files["gen/py/%s.py" % name] = gen_py.gen_py(m, src)
            files["gen/json/%s.json" % name] = gen_json.gen_json(m, src, profile)
            files["gen/genxml/%s.xml" % name] = gen_genxml.gen_genxml(m, src)
            files["gen/docs/%s.md" % name] = gen_docs.gen_docs(m, src, profile)
            legacy = m["c"].get("legacy_header")
            if legacy and forwarding:
                if legacy in files:
                    raise GenError("%s: legacy header %s is also another unit's" % (name, legacy))
                files[legacy] = gen_c.gen_forwarding(m, src, gen_c.rel_include(legacy, "gen/c/%s.h" % name))
        except GenError as e:
            errors.append(str(e))
    if repo.units:
        files["gen/rust/Cargo.toml"] = gen_rust.gen_cargo(repo.project, "defs/")
        files["gen/rust/src/lib.rs"] = gen_rust.gen_lib(list(repo.units), "defs/")
    return files, errors


def existing(root):
    """Every file under gen/, relative to root."""
    found = []
    base = os.path.join(root, GEN_DIR)
    for d, _dirs, names in os.walk(base):
        for n in names:
            found.append(os.path.relpath(os.path.join(d, n), root))
    return sorted(found)


def stale(repo, files):
    """Problems: files missing, differing, or present with no source."""
    probs = []
    for rel, text in sorted(files.items()):
        path = os.path.join(repo.root, rel)
        try:
            with open(path, encoding="utf-8") as f:
                have = f.read()
        except OSError:
            probs.append("%s: missing; run defs-gen" % rel)
            continue
        if have != text:
            probs.append("%s: stale against its source; run defs-gen" % rel)
    for rel in existing(repo.root):
        if rel not in files:
            probs.append("%s: no unit generates this file; run defs-gen to remove it" % rel)
    return probs


def write(repo, files):
    """Write every file, and remove leftovers under gen/ that carry the generator banner.
    Returns (written, removed, kept_unrecognised)."""
    written, removed, kept = [], [], []
    for rel, text in sorted(files.items()):
        path = os.path.join(repo.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, encoding="utf-8") as f:
                same = f.read() == text
        except OSError:
            same = False
        if not same:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            written.append(rel)
    for rel in existing(repo.root):
        if rel in files:
            continue
        path = os.path.join(repo.root, rel)
        try:
            with open(path, encoding="utf-8") as f:
                head = f.read(400)
        except (OSError, UnicodeDecodeError):
            head = ""
        if MARK in head and "defs-gen" in head:
            os.remove(path)
            removed.append(rel)
        else:
            kept.append(rel)
    return written, removed, kept
