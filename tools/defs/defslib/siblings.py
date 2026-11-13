"""One register, one repository: find registers that two sibling repositories both define.

The sibling repositories are the ones named in the inventory-siblings pin file
(tools/config/inventory-siblings.json, old layout scripts/inventory-siblings.json). Two of
them describe the same chip when each has a unit of that name, and then each register
should live in one of them. A register is the same register when the unit name, the address
space and the offset agree; the names given to it may differ, which is the usual way a
duplicate hides.

A sibling is looked for, in order, at the path given with --sibling NAME=PATH (inside tools/re-run
the same option mounts a path outside the workspace, and the check finds it through
$ORIGAMI_RE_SIBLINGS), at the path the inventory config's `siblings` map gives (relative to this
repository), at .cache/siblings/NAME and at ../NAME. The default is a clone in
.cache/siblings/NAME, which tools/setup-clone.sh makes and which is inside the workspace, so it is
visible to a containerised run. What is read is the checkout's working tree. A sibling that is not
there, or lacks the commit its pin names, is a note, never a failure: the check can only compare
what it can see.
"""
import json
import os
import subprocess

from _layout import Layout, env_siblings

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


def candidates(layout, name, given):
    """Every place `locate` looks for sibling `name`, in order."""
    cands = []
    for src in (given, env_siblings()):
        if name in src:
            cands.append(os.path.abspath(src[name]))
    cfg = configured_paths(layout).get(name)
    if cfg:
        cands.append(os.path.normpath(os.path.join(layout.root, cfg)))
    cands.append(os.path.join(layout.root, ".cache", "siblings", name))
    cands.append(os.path.normpath(os.path.join(layout.root, "..", name)))
    return list(dict.fromkeys(cands))


def locate(layout, name, given):
    """Absolute path of the checkout of sibling `name`, or None."""
    for c in candidates(layout, name, given):
        if os.path.isdir(c) and Layout(c).has_defs():
            return c
    return None


def pinned_commit(layout, name):
    """The commit the pin file records for sibling `name`, or None."""
    try:
        with open(layout.path(layout.sibling_pins), encoding="utf-8") as f:
            sha = json.load(f).get(name)
    except (OSError, ValueError, AttributeError):
        return None
    return sha if isinstance(sha, str) and sha else None


def lacks_commit(path, sha):
    """True when `path` is a git checkout that does not have commit `sha`. A directory that is not a
    checkout (an export, a fixture) cannot be asked."""
    if not sha or not os.path.exists(os.path.join(path, ".git")):
        return False
    r = subprocess.run(["git", "-c", "safe.directory=*", "-C", path, "cat-file", "-e", sha + "^{commit}"],
                       capture_output=True)
    return r.returncode != 0


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
    given = {**env_siblings(), **(given or {})}
    fails, notes = [], []
    names = set(pinned_names(repo.layout)) | set(given)
    names.discard(os.path.basename(repo.root))
    if not names:
        return fails, notes
    mine = register_keys(repo)
    for name in sorted(names):
        path = locate(repo.layout, name, given)
        pin = pinned_commit(repo.layout, name)
        if path is None:
            tried = candidates(repo.layout, name, given)
            bare = next((c for c in tried if os.path.isdir(c)), None)
            if bare:
                notes.append("sibling %s at %s has no register maps (devices/, formats/ or defs/), so there is "
                             "nothing to compare; its working tree may predate the layout move"
                             % (name, bare))
                continue
            notes.append("sibling %s is not present locally%s (looked at %s): its registers were not compared. "
                         "Clone it into .cache/siblings/%s (tools/setup-clone.sh does this), or pass "
                         "--sibling %s=PATH (tools/re-run mounts a PATH outside the workspace)"
                         % (name, " at its pinned commit %s" % pin[:12] if pin else "", ", ".join(tried), name, name))
            continue
        if lacks_commit(path, pin):
            notes.append("sibling %s at %s does not have its pinned commit %s: comparing its working tree "
                         "instead; fetch it (git -C %s fetch origin) to compare the pinned state"
                         % (name, path, pin[:12], path))
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
