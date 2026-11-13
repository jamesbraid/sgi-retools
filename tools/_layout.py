"""Where a workspace keeps its files: the current layout, and the old one while repositories move.

Every tool that names a workspace path asks this module, so the fallback to the old layout lives in
one place and goes when the last repository has moved.

    current                              old
    devices/<unit>/registers*.toml       defs/<unit>*.toml
    formats/<name>/format.toml           (none)
    generated/{c,rust,python,json,xml}   gen/{c,rust,py,json,genxml}
    devices/<unit>/registers.md          gen/docs/<unit>.md
    tools/config/inventory-config.json   scripts/inventory-config.json
    tools/config/inventory-root.sha256   scripts/inventory-root.sha256
    tools/config/inventory-siblings.json scripts/inventory-siblings.json
    tools/config/binaries_manifest.json  binaries_manifest.json
    tools/config/defs-check.toml         defs/check.toml
    evidence/inventory/                  docs/inventory/
    evidence/coverage.md                 docs/coverage.md
    evidence/routines/                   docs/routines/
    evidence/instruction-readings-*.md   docs/instruction-readings-*.md

Reading takes the current path when it exists and the old one otherwise. A path that does not exist
yet (an output a tool is about to create) is the current one, unless the workspace is plainly on the
old layout. The hardware definitions are decided once for the whole repository by `defs_mode`, so one
run never mixes the two trees.

A tool's own data and sibling scripts stay relative to its __file__; only workspace paths come here.
"""
import glob
import os
import re

CONFIG_DIR = 'tools/config'
OLD_CONFIG_DIR = 'scripts'

# Directories that exist only in a workspace that has moved.
NEW_MARKERS = ('tools/config', 'evidence', 'devices', 'formats', 'generated', 'platforms', 'software')
OLD_MARKERS = ('defs', 'gen', 'docs', 'scripts')

# <stem>[-extra | .<rev>].toml inside devices/<unit>/ (stem registers) or formats/<name>/ (stem format)
SOURCE_RE = re.compile(r'^(?P<stem>registers|format)(?:(?P<extra>-extra)|\.(?P<rev>[a-z][a-z0-9_]*))?\.toml$')

# generated/ subdirectory names by output kind, for each layout
GEN_DIRS = {
    'new': {'c': 'c', 'rust': 'rust', 'py': 'python', 'json': 'json', 'xml': 'xml'},
    'old': {'c': 'c', 'rust': 'rust', 'py': 'py', 'json': 'json', 'xml': 'genxml'},
}
GEN_ROOT = {'new': 'generated', 'old': 'gen'}


class Source:
    """One register-map file: its path, the directory it sits in (None in the old layout) and what it is.

    kind is "base" (a unit of its own), "overlay" (a revision patch on a base) or "extra" (a unit of its
    own, kept beside the base). stem is the file name without .toml."""

    def __init__(self, rel, dirname, kind, rev=None, stem=None):
        self.rel = rel
        self.dir = dirname
        self.kind = kind
        self.rev = rev
        self.stem = stem or os.path.basename(rel)[:-len('.toml')]

    def __repr__(self):
        return 'Source(%r, %s)' % (self.rel, self.kind)


class Layout:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self._defs_mode = None

    # ------------------------------------------------------------------ plumbing
    def exists(self, rel):
        return os.path.exists(os.path.join(self.root, rel))

    def path(self, rel):
        return os.path.join(self.root, rel)

    @property
    def on_current_layout(self):
        """True when some directory of the current layout already exists."""
        return any(self.exists(d) for d in NEW_MARKERS)

    @property
    def moved(self):
        """True when the workspace shows the current layout, False when it shows only the old one.
        A workspace with neither (a new one) counts as moved: new files go where they belong."""
        if self.on_current_layout:
            return True
        return not any(self.exists(d) for d in OLD_MARKERS)

    def pick(self, new, old):
        """The path to read: the current one if it exists, else the old one if that does, else the path
        a new file belongs at (current, unless the workspace is on the old layout)."""
        if self.exists(new):
            return new
        if self.exists(old):
            return old
        return new if self.moved else old

    # ------------------------------------------------------------ tool configuration
    def config(self, name, old=None):
        """tools/config/NAME, else scripts/NAME (else NAME at the top, for `old`='' )."""
        old_rel = '%s/%s' % (OLD_CONFIG_DIR, name) if old is None else (old or name)
        return self.pick('%s/%s' % (CONFIG_DIR, name), old_rel)

    @property
    def inventory_config(self):
        return self.config('inventory-config.json')

    @property
    def root_manifest(self):
        return self.config('inventory-root.sha256')

    @property
    def sibling_pins(self):
        return self.config('inventory-siblings.json')

    @property
    def binaries_manifest(self):
        return self.config('binaries_manifest.json', old='binaries_manifest.json')

    @property
    def scope_file(self):
        return self.config('scope.json')

    @property
    def defs_check_file(self):
        return self.pick('%s/defs-check.toml' % CONFIG_DIR, 'defs/check.toml')

    @property
    def legacy_dropped_file(self):
        return self.pick('%s/defs-legacy-dropped.txt' % CONFIG_DIR, 'defs/legacy-dropped.txt')

    # ------------------------------------------------------------------ evidence
    @property
    def inventory_dir(self):
        return self.pick('evidence/inventory', 'docs/inventory')

    @property
    def coverage_file(self):
        return self.pick('evidence/coverage.md', 'docs/coverage.md')

    @property
    def routines_dir(self):
        return self.pick('evidence/routines', 'docs/routines')

    @property
    def audits_file(self):
        return self.inventory_dir + '/audits.tsv'

    @property
    def functions_table(self):
        return self.inventory_dir + '/functions.tsv'

    @property
    def readings_dir(self):
        """The directory that holds the instruction-reading pages. Where pages already exist that is
        decided by them (the current directory wins); otherwise by the layout."""
        for d in ('evidence', 'docs'):
            if glob.glob(self.path(d + '/instruction-readings-*.md')):
                return d
        return 'evidence' if self.moved else 'docs'

    def census_dir(self, name):
        """Where a chip's census tables live: devices/<name>/census, else chips/<name>/census."""
        return self.pick('devices/%s/census' % name, 'chips/%s/census' % name)

    # ------------------------------------------------------- hardware definitions
    def register_sources(self):
        """Every register-map file of the current layout, sorted, as Source objects."""
        out = []
        for top, stem in (('devices', 'registers'), ('formats', 'format')):
            for d in sorted(glob.glob(self.path(top + '/*/'))):
                name = os.path.basename(os.path.dirname(d))
                for f in sorted(os.listdir(d)):
                    m = SOURCE_RE.match(f)
                    if not m or m.group('stem') != stem:
                        continue
                    kind = 'extra' if m.group('extra') else 'overlay' if m.group('rev') else 'base'
                    out.append(Source('%s/%s/%s' % (top, name, f), '%s/%s' % (top, name), kind, m.group('rev'),
                                      f[:-len('.toml')]))
        return out

    def old_sources(self):
        """The old layout's defs/*.toml (check.toml is the settings file, not a source)."""
        d = self.path('defs')
        if not os.path.isdir(d):
            return []
        return [Source('defs/%s' % f, None, 'base') for f in sorted(os.listdir(d))
                if f.endswith('.toml') and f != 'check.toml']

    @property
    def defs_mode(self):
        """"new" when register maps sit under devices/ or formats/, "old" when only defs/ has them,
        None when the repository has none. The current layout wins when both exist."""
        if self._defs_mode is None:
            if self.register_sources():
                self._defs_mode = 'new'
            elif os.path.isdir(self.path('defs')):
                self._defs_mode = 'old'
            else:
                self._defs_mode = ''
        return self._defs_mode or None

    def has_defs(self):
        return self.defs_mode is not None

    def gen_root(self):
        return GEN_ROOT[self.defs_mode or 'new']

    def gen_dir(self, kind):
        """Repo-relative directory of one output kind: c, rust, py, json or xml."""
        mode = self.defs_mode or 'new'
        return '%s/%s' % (GEN_ROOT[mode], GEN_DIRS[mode][kind])

    def gen_file(self, kind, unit):
        ext = {'c': 'h', 'py': 'py', 'json': 'json', 'xml': 'xml'}[kind]
        return '%s/%s.%s' % (self.gen_dir(kind), unit, ext)

    def doc_file(self, unit):
        """The generated register table of a Unit (see defslib.loader): next to its source in the current
        layout, gen/docs/<unit>.md in the old one."""
        if self.defs_mode == 'new' and unit.dir:
            return '%s/%s.md' % (unit.dir, unit.stem)
        return 'gen/docs/%s.md' % unit.name

    def helpers_file(self, unit):
        """Hand-written C helpers of a Unit: devices/<unit>/helpers.h (registers becomes helpers in the
        file name for overlays and extras), defs/<unit>_helpers.h in the old layout."""
        if self.defs_mode == 'new' and unit.dir:
            return '%s/%s.h' % (unit.dir, re.sub(r'^(registers|format)', 'helpers', unit.stem))
        return 'defs/%s_helpers.h' % unit.name

    def generated_roots(self):
        """Every directory that may hold generated register tables, for finding leftovers."""
        return [self.gen_root()]


def of(root=None):
    """The Layout of the workspace at root (default: the workspace the tools find)."""
    if root is None:
        from _workspace import find_workspace
        root = find_workspace()
    return Layout(root)
