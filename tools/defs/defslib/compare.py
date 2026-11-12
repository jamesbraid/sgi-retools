"""Compare an old header with its replacement, macro by macro, with the C compiler.

Every macro the old header defines must exist in the new one with the same
value (integer macros are evaluated by compiling and running a program; the rest
are compared as text, function-like macros by parameters and body). A macro the
migration deliberately drops is listed in a dropped file and counted, not
silently ignored. The new header is normally the forwarding header, which pulls
in the generated header and defines the old names that differ, so passing means
the forwarding header is a drop-in for the old one.
"""
import os
import re
import shutil
import subprocess
import tempfile

DEFINE_LINE = re.compile(r"^#define (\w+)(\([^)]*\))? ?(.*)$")


class Outcome:
    def __init__(self, label):
        self.label = label
        self.old = self.paired = self.equal = self.dropped = self.new_only = 0
        self.different = []     # (name, old, new)
        self.broken = []        # headers that do not compile, with the first error
        self.missing = []
        self.unused_drops = []

    @property
    def ok(self):
        return not self.different and not self.missing and not self.broken

    def summary(self):
        return ("%s: %d old macros, %d paired, %d equal, %d different, %d missing, %d dropped on purpose, %d only in the new header"
                % (self.label, self.old, self.paired, self.equal, len(self.different), len(self.missing), self.dropped, self.new_only))


def _cc():
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        raise RuntimeError("no C compiler (cc) found")
    return cc


def _env():
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    return env


def macro_table(path, includes=()):
    """name -> (params or None, body) for what the header defines (system macros removed)."""
    cc = _cc()
    argv = [cc, "-dM", "-E", "-x", "c"] + ["-I%s" % i for i in includes]
    r = subprocess.run(argv + [path], capture_output=True, text=True, env=_env())
    if r.returncode:
        raise RuntimeError("%s does not preprocess: %s" % (path, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "?"))
    with tempfile.TemporaryDirectory() as td:
        base = os.path.join(td, "base.h")
        with open(base, "w") as f:
            f.write("#include <stdint.h>\n")
        b = subprocess.run(argv + [base], capture_output=True, text=True, env=_env())
    baseline = set()
    for ln in b.stdout.splitlines():
        m = DEFINE_LINE.match(ln)
        if m:
            baseline.add(m.group(1))
    out = {}
    for ln in r.stdout.splitlines():
        m = DEFINE_LINE.match(ln)
        if not m or m.group(1) in baseline:
            continue
        out[m.group(1)] = (m.group(2), re.sub(r"\s+", " ", m.group(3)).strip())
    return out


def evaluate(path, names, includes=(), workdir=None):
    """Value of each object-like macro that is an integer expression; others are left out."""
    cc = _cc()
    names = sorted(names)
    td = workdir or tempfile.mkdtemp()
    try:
        src, exe = os.path.join(td, "e.c"), os.path.join(td, "e")
        for _ in range(12):
            with open(src, "w") as f:
                f.write('#include <stdio.h>\n#include "%s"\n' % os.path.abspath(path))
                # an enumerator must be an integer constant expression: strings, floats and the like are refused
                for i, n in enumerate(names):
                    f.write("enum { E_%d = (%s) };\n" % (i, n))
                f.write("int main(void) {\n")
                for i, n in enumerate(names):
                    f.write('  printf("%s=%%llu\\n", (unsigned long long)E_%d);\n' % (n, i))
                f.write("  return 0;\n}\n")
            r = subprocess.run([cc, "-std=gnu99", "-w", "-o", exe, src] + ["-I%s" % i for i in includes],
                               capture_output=True, text=True, env=_env())
            if r.returncode == 0:
                out = subprocess.run([exe], capture_output=True, text=True).stdout
                return {l.split("=", 1)[0]: int(l.split("=", 1)[1]) for l in out.splitlines() if "=" in l}
            bad = {int(x) - 3 for x in re.findall(r"e\.c:(\d+):\d+: error", r.stderr)}
            bad = {i for i in bad if 0 <= i < len(names)}
            if not bad:
                return {}
            names = [n for i, n in enumerate(names) if i not in bad]
        return {}
    finally:
        if not workdir:
            shutil.rmtree(td, ignore_errors=True)


def compile_error(path, includes=()):
    """First compiler error from the header on its own, or None."""
    r = subprocess.run([_cc(), "-fsyntax-only", "-std=gnu99", "-w", "-x", "c"] + ["-I%s" % i for i in includes] + [path],
                       capture_output=True, text=True, env=_env())
    if r.returncode == 0:
        return None
    errs = [l for l in r.stderr.splitlines() if "error" in l]
    return (errs[0] if errs else r.stderr.strip().splitlines()[-1]).strip()


def load_dropped(path):
    names = {}
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    n, _, why = line.rstrip("\n").partition("\t")
                    names[n.strip()] = why.strip()
    return names


def compare_headers(old_path, new_path, label, dropped=None, includes=()):
    dropped = dropped or {}
    out = Outcome(label)
    for which, path in (("old", old_path), ("new", new_path)):
        err = compile_error(path, includes)
        if err:
            out.broken.append("%s header does not compile: %s" % (which, err))
    if out.broken:
        return out
    old, new = macro_table(old_path, includes), macro_table(new_path, includes)
    guard = {n for n, (p, b) in old.items() if p is None and b == ""}
    old = {n: v for n, v in old.items() if n not in guard}
    new = {n: v for n, v in new.items() if not (v[0] is None and v[1] == "")}      # include guards
    out.old = len(old)
    out.new_only = len([n for n in new if n not in old])
    with tempfile.TemporaryDirectory() as td:
        for sub in ("o", "n"):
            os.makedirs(os.path.join(td, sub))
        oldv = evaluate(old_path, [n for n, (p, b) in old.items() if p is None], includes, os.path.join(td, "o"))
        newv = evaluate(new_path, [n for n, (p, b) in new.items() if p is None], includes, os.path.join(td, "n"))
    for name, (params, body) in sorted(old.items()):
        if name in dropped:
            out.dropped += 1
            if name in new:
                out.unused_drops.append(name)
            continue
        if name not in new:
            out.missing.append(name)
            continue
        out.paired += 1
        nparams, nbody = new[name]
        if params is not None or nparams is not None:
            if (params, body) == (nparams, nbody):
                out.equal += 1
            else:
                out.different.append((name, "%s %s" % (params or "", body), "%s %s" % (nparams or "", nbody)))
        elif name in oldv and name in newv:
            if oldv[name] == newv[name]:
                out.equal += 1
            else:
                out.different.append((name, "0x%x" % oldv[name], "0x%x" % newv[name]))
        elif body == nbody:
            out.equal += 1
        else:
            out.different.append((name, body, nbody))
    return out
