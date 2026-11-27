"""What every generated file says about itself: the generator version, a hash of the input TOML and the licence.

The hash is the sha256 of the unit's source files read in layer order (a base then its overlay), so for a
one-file unit it equals `sha256sum registers.toml`. A file generated before its commit cannot name that
commit; the hash names the input instead, and `defs-gen --check` still catches a stale tree.
"""
import hashlib
import os
import re

from .genutil import GENERATOR_VERSION


def digest(root, rels):
    h = hashlib.sha256()
    for rel in rels:
        with open(os.path.join(root, rel), "rb") as f:
            h.update(f.read())
    return h.hexdigest()


DEFAULT_LICENSE = "BSD-3-Clause"


class Stamper:
    def __init__(self, repo):
        self.repo = repo
        self.license = repo.settings.get("project", {}).get("license", DEFAULT_LICENSE)
        seen = []
        for _n, u in sorted(repo.units.items()):
            seen += [r for r in u.layers if r not in seen]
        self.all = digest(repo.root, sorted(seen))
        self.unit = {n: digest(repo.root, u.layers) for n, u in repo.units.items()}

    def lines(self, unit=None):
        out = []
        if self.license:
            out.append("SPDX-License-Identifier: %s" % self.license)
        out += ["defs-gen %s" % GENERATOR_VERSION, "input sha256 %s" % (self.unit[unit] if unit else self.all)]
        return out

    def apply(self, rel, text, unit=None):
        """Insert the stamp lines after the banner (two lines down in XML, after the declaration)."""
        lines = self.lines(unit)
        ext = os.path.splitext(rel)[1]
        if ext == ".json":
            body = "".join(' "%s": "%s",\n' % (k, v) for k, v in
                           (("license", self.license), ("generator", "defs-gen " + GENERATOR_VERSION),
                            ("input_sha256", lines[-1].rsplit(" ", 1)[1])) if v)
            return text.replace("{\n", "{\n" + body, 1)
        if ext == ".py":
            wrap = "%s"
        elif ext == ".rs":
            wrap = "// %s"
        elif ext == ".toml":
            wrap = "# %s"
        elif ext in (".md", ".xml"):
            wrap = "<!-- %s -->"
        else:
            wrap = "/* %s */"
        at = 2 if ext == ".xml" else 1
        if wrap == "/* %s */":      # after the whole first comment, which a long banner wraps
            at = next(i for i, ln in enumerate(text.split("\n"), 1) if "*/" in ln)
        parts = text.split("\n", at)
        return "\n".join(parts[:at] + [wrap % ln for ln in lines] + parts[at:])


STAMP_RE = re.compile(r"input sha256 ([0-9a-f]{64})")
