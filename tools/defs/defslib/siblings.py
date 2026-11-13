"""One register, one repository: find registers that two sibling repositories both define.

The sibling repositories are the ones named in the inventory-siblings pin file
(tools/config/inventory-siblings.json, old layout scripts/inventory-siblings.json). Two of
them describe the same chip when each has a unit of that name, and then each register
should live in one of them. A register is the same register when the unit name, the address
space and the offset agree; the names given to it may differ, which is the usual way a
duplicate hides.

A sibling is looked for, in order, at the path given on the command line, at the path the
inventory config's `siblings` map gives (relative to this repository), at ../NAME and at
.cache/siblings/NAME. What is read is the checkout's working tree. A sibling that is not
there is a note, never a failure: the check can only compare what it can see.
"""
import json
import os

from _layout import Layout

from . import loader


def pinned_names(layout):
    """Sibling names from the pin file, or [] when the repository has none."""
    rel = layout.sibling_pins
    path = layout.path(rel)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return sorted(json.load(f))
    except (OSError, ValueError):
        return []


def configured_paths(layout):
    """The inventory config's `siblings` map ({name: path from this repository}), or {}."""
    path = layout.path(layout.inventory_config)
    try:
        with open(path, encoding="utf-8") as f:
            return dict(json.load(f).get("siblings", {}))
    except (OSError, ValueError, AttributeError, TypeError):
        return {}


def locate(layout, name, given):
    """Absolute path of the checkout of sibling `name`, or None."""
    cands = []
    if name in given:
        cands.append(os.path.abspath(given[name]))
    cfg = configured_paths(layout).get(name)
    if cfg:
        cands.append(os.path.normpath(os.path.join(layout.root, cfg)))
    cands.append(os.path.normpath(os.path.join(layout.root, "..", name)))
    cands.append(os.path.join(layout.root, ".cache", "siblings", name))
    for c in cands:
        if os.path.isdir(c) and Layout(c).has_defs():
            return c
    return None


def register_keys(repo):
    """{(unit, space, offset): (register name, source file)} for a loaded repo."""
    keys = {}
    for uname, unit in sorted(repo.units.items()):
        for rname, reg in unit.model["registers"].items():
            keys.setdefault((uname, reg.get("space") or "", reg["offset"]), (rname, unit.path))
    return keys


def check(repo, given=None):
    """Compare the repo's registers with every present sibling's. Returns (failures, notes): a failure
    for each register defined in both, a note for each sibling that could not be compared."""
    given = given or {}
    fails, notes = [], []
    names = set(pinned_names(repo.layout)) | set(given)
    names.discard(os.path.basename(repo.root))
    if not names:
        return fails, notes
    mine = register_keys(repo)
    for name in sorted(names):
        path = locate(repo.layout, name, given)
        if path is None:
            notes.append("sibling %s is not present locally (looked at ../%s and .cache/siblings/%s): "
                         "its registers were not compared" % (name, name, name))
            continue
        other = loader.load_repo(path)
        if other.errors:
            notes.append("sibling %s at %s does not load (%d error(s), first: %s): its registers were not compared"
                         % (name, path, len(other.errors), other.errors[0]))
            continue
        theirs = register_keys(other)
        for key in sorted(set(mine) & set(theirs), key=lambda k: (k[0], k[1], k[2])):
            unit, space, off = key
            fails.append("register at offset 0x%x of unit %s%s is defined here as %s (%s) and in sibling %s as %s (%s)"
                         % (off, unit, " space %s" % space if space else "", mine[key][0], mine[key][1],
                            name, theirs[key][0], theirs[key][1]))
    return fails, notes
