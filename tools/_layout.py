"""Where a workspace keeps its files.

Every tool that names a workspace path asks this module. Only the hardware definitions still have
an old shape (defs/<unit>*.toml, gen/...), for a repository that has not adopted devices/ and
formats/: `defs_mode` decides it once for the whole repository, so one run never mixes the two trees.

    devices/<unit>/registers*.toml       old: defs/<unit>*.toml
    formats/<name>/format.toml           (none)
    generated/{c,rust,python,json,xml}   old: gen/{c,rust,py,json,genxml}
    devices/<unit>/registers.md          old: gen/docs/<unit>.md
    tools/config/                        inventory-config.json, inventory-root.sha256, inventory-siblings.json,
                                         binaries_manifest.json, defs-check.toml (old: defs/check.toml)
    generated/inventory/, generated/version-diffs/, generated/personality-diffs/, generated/userland-symbols/
    COVERAGE.md
    references/<list>.md
    <subject>/readings/<binary>.md
    software/<component>/                the component directories callers still name by their old top-level
                                         names (ucode/, kona_kernel/, mgras_kernel/, libglcore/, ddx/, irisgl/,
                                         diags/); `software()` maps them
    tools/ghidra/

A tool's own data and sibling scripts stay relative to its __file__; only workspace paths come here.
"""
import glob
import os
import re

CONFIG_DIR = 'tools/config'

# Directories that exist only in a workspace that has moved to subject filing.
NEW_MARKERS = ('tools/config', 'devices', 'formats', 'generated', 'platforms', 'software', 'COVERAGE.md')

# <stem>[-extra | .<rev>].toml inside devices/<unit>/ (stem registers) or formats/<name>/ (stem format)
SOURCE_RE = re.compile(r'^(?P<stem>registers|format)(?:(?P<extra>-extra)|\.(?P<rev>[a-z][a-z0-9_]*))?\.toml$')

# generated/ subdirectory names by output kind, for each layout
GENERATED_PAGE = re.compile(r'^(registers|format)(-extra|\.[a-z][a-z0-9_]*)?\.md$')

GEN_DIRS = {
    'new': {'c': 'c', 'rust': 'rust', 'py': 'python', 'json': 'json', 'xml': 'xml'},
    'old': {'c': 'c', 'rust': 'rust', 'py': 'py', 'json': 'json', 'xml': 'genxml'},
}
GEN_ROOT = {'new': 'generated', 'old': 'gen'}

# Old top-level component name -> the software/ component that took its files.
SOFTWARE_OLD = {'ucode': 'ucode', 'kona_kernel': 'kernel', 'mgras_kernel': 'kernel', 'libglcore': 'opengl',
                'ddx': 'xsgi', 'irisgl': 'irisgl', 'diags': 'diags'}


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

    # ------------------------------------------------------------ tool configuration
    def config(self, name):
        return '%s/%s' % (CONFIG_DIR, name)

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
        return self.config('binaries_manifest.json')

    @property
    def scope_file(self):
        return self.config('scope.json')

    @property
    def defs_check_file(self):
        return 'defs/check.toml' if self.defs_mode == 'old' else '%s/defs-check.toml' % CONFIG_DIR

    @property
    def legacy_dropped_file(self):
        return 'defs/legacy-dropped.txt' if self.defs_mode == 'old' else '%s/defs-legacy-dropped.txt' % CONFIG_DIR

    # ------------------------------------------------------------ software components
    def software(self, rel):
        """A path written with an old top-level component name (ucode/KONA/arm1.u, kona_kernel/disasm,
        libglcore/asm/...) as it is under software/<component>/."""
        head, sep, rest = rel.partition('/')
        comp = SOFTWARE_OLD.get(head)
        if comp is None:
            return rel
        return 'software/' + comp + sep + rest

    def page(self, name, component):
        """A documentation page or data file that sits with its component."""
        return 'software/%s/%s' % (component, name)

    def header(self, name):
        """A hand-written header: devices/<unit>/NAME."""
        for p in sorted(glob.glob(self.path('devices/*/' + name))):
            return os.path.relpath(p, self.root)
        return 'devices/%s/%s' % (name.split('.')[0].lower(), name)

    @property
    def ge_header(self):
        """The geometry-engine header of the Kona repository."""
        return self.header('GE.h')

    def ghidra(self, rel):
        """A path inside the Ghidra tree."""
        return 'tools/ghidra/' + rel

    def doc_pages(self):
        """Every prose page of the workspace: the component and device pages and the readings."""
        pages = []
        for pat in ('software/*/*.md', 'devices/*/*.md', 'formats/*/*.md', 'questions/*.md',
                    'references/*.md', 'COVERAGE.md'):
            pages.extend(glob.glob(self.path(pat)))
        pages.extend(self.path(p) for p in self.reading_pages())
        # registers.md, registers.<rev>.md, registers-extra.md and format.md are generated from the
        # register maps, as gen/docs/ was; they were never among docs/*.md
        return sorted(p for p in pages if not GENERATED_PAGE.match(os.path.basename(p)))

    # ------------------------------------------------------------------ evidence
    @property
    def inventory_dir(self):
        return 'generated/inventory'

    @property
    def coverage_file(self):
        return 'COVERAGE.md'

    @property
    def version_diffs_dir(self):
        return 'generated/version-diffs'

    @property
    def personality_diffs_dir(self):
        return 'generated/personality-diffs'

    @property
    def userland_symbols_dir(self):
        return 'generated/userland-symbols'

    def reference(self, name):
        """A list of what the repository holds and cites (irix-files.md, binaries.md, hinv-codes.tsv)."""
        return 'references/' + name

    @property
    def audits_file(self):
        return self.inventory_dir + '/audits.tsv'

    @property
    def functions_table(self):
        return self.inventory_dir + '/functions.tsv'

    def reading_pages(self):
        """Repository-relative paths of every page of per-routine readings: <subject>/readings/<binary>.md."""
        found = []
        for top in ('devices', 'platforms', 'formats', 'software'):
            for dirpath, dirs, files in os.walk(self.path(top)):
                if os.path.basename(dirpath) == 'readings':
                    found += [os.path.relpath(os.path.join(dirpath, f), self.root) for f in files if f.endswith('.md')]
        return sorted(found)

    def census_dir(self, name):
        """Where a chip's census tables live: devices/<name>/census, else chips/<name>/census (a repository
        that still has the old register-map shape)."""
        new = 'devices/%s/census' % name
        old = 'chips/%s/census' % name
        return old if not self.exists(new) and self.exists(old) else new

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


def sw(rel):
    """Layout.software for the workspace the tools find: sw('ucode/KONA/arm1.u')."""
    return of().software(rel)


SIBLINGS_ENV = 'RETOOLS_SIBLINGS'


def env_siblings():
    """{name: path} from $RETOOLS_SIBLINGS, a comma-separated list of NAME=PATH. tools/re-run sets it
    for each `--sibling NAME=PATH` it was given, with PATH as seen inside the container."""
    out = {}
    for item in os.environ.get(SIBLINGS_ENV, '').split(','):
        name, eq, path = item.partition('=')
        if eq and name and path:
            out[name] = path
    return out


def header(name):
    """Layout.header for the workspace the tools find."""
    return of().header(name)


def ge_header():
    """Layout.ge_header for the workspace the tools find."""
    return of().ge_header


if __name__ == '__main__':
    # `_layout.py sw PATH...` prints each old-layout path as this workspace has it, for shell scripts.
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == 'sw':
        for a in sys.argv[2:]:
            print(sw(a))
    else:
        sys.exit('usage: _layout.py sw PATH...')
