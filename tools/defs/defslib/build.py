"""Build the committed outputs: the proof that they compile, import and agree with the vectors.

  C           every gen/c header and forwarding header compiles with -Wall -Wextra -Werror,
              and a generated program decodes every vector with the header's own macros
  Python      every gen/py module runs its self-test
  genxml      the vendored upstream pack generator accepts every export; what it
              writes compiles, and every vector unpacks and repacks through it
  Rust        the crate builds with warnings denied and its tests pass (rustc is optional)
"""
import os
import shutil
import subprocess
import sys
import tempfile

from . import gen_c, gen_genxml
from .model import publish_profile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(HERE, "vendor", "genxml", "gen_pack.py")
PRELUDE = os.path.join(HERE, "genxml_prelude.h")


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def _tail(r):
    return ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-6:]


def verify(repo, notes=None):
    """Return a list of failure strings; `notes` collects skipped steps."""
    notes = notes if notes is not None else []
    fails = []
    cc = shutil.which("cc") or shutil.which("gcc")
    rustc = shutil.which("rustc")
    root = repo.root
    models = {n: (u.model if repo.profile == "internal" else publish_profile(u.model)) for n, u in repo.units.items()}
    with tempfile.TemporaryDirectory() as td:
        for name, m in sorted(models.items()):
            hdr = os.path.join(root, "gen", "c", "%s.h" % name)
            if not os.path.isfile(hdr):
                fails.append("gen/c/%s.h: missing" % name)
                continue
            if cc:
                r = _run([cc, "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-std=c99", "-x", "c", hdr])
                if r.returncode:
                    fails.append("gen/c/%s.h: C compile failed: %s" % (name, " | ".join(_tail(r))))
                    continue
                src = os.path.join(td, "t_%s.c" % name)
                with open(src, "w", encoding="utf-8") as f:
                    f.write(gen_c.gen_c_test(m, hdr))
                exe = os.path.join(td, "t_%s" % name)
                r = _run([cc, "-std=c99", "-Wall", "-Werror", "-o", exe, src])
                if r.returncode:
                    fails.append("gen/c/%s.h: self-test compile failed: %s" % (name, " | ".join(_tail(r))))
                elif _run([exe]).returncode:
                    fails.append("gen/c/%s.h: a vector disagrees with the generated macros" % name)
                legacy = m["c"].get("legacy_header")
                if legacy and os.path.isfile(os.path.join(root, legacy)):
                    r = _run([cc, "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-std=c99", "-x", "c", os.path.join(root, legacy)])
                    if r.returncode:
                        fails.append("%s: forwarding header does not compile: %s" % (legacy, " | ".join(_tail(r))))
            py = os.path.join(root, "gen", "py", "%s.py" % name)
            if os.path.isfile(py):
                r = _run([sys.executable, "-I", py])
                if r.returncode:
                    fails.append("gen/py/%s.py: self-test failed: %s" % (name, " | ".join(_tail(r))))
            xml = os.path.join(root, "gen", "genxml", "%s.xml" % name)
            if os.path.isfile(xml):
                r = _run([sys.executable, "-I", VENDOR, xml, PRELUDE])
                if r.returncode:
                    fails.append("gen/genxml/%s.xml: upstream pack generator refused it: %s" % (name, " | ".join(_tail(r))))
                elif cc:
                    packed = os.path.join(td, "%s_pack.h" % name)
                    with open(packed, "w", encoding="utf-8") as f:
                        f.write(r.stdout)
                    src = os.path.join(td, "x_%s.c" % name)
                    with open(src, "w", encoding="utf-8") as f:
                        f.write(gen_genxml.genxml_selftest_c(m, packed))
                    exe = os.path.join(td, "x_%s" % name)
                    c = _run([cc, "-std=gnu11", "-Wno-unused-function", "-o", exe, src])
                    if c.returncode:
                        fails.append("gen/genxml/%s.xml: upstream output does not compile: %s" % (name, " | ".join(_tail(c))))
                    else:
                        t = _run([exe])
                        if t.returncode:
                            fails.append("gen/genxml/%s.xml: a vector does not roundtrip through the upstream pack code: %s"
                                         % (name, " | ".join(_tail(t))))
        if not cc:
            notes.append("no C compiler: skipped the C and genxml builds")
        crate = os.path.join(root, "gen", "rust", "src", "lib.rs")
        if not os.path.isfile(crate):
            if models:
                fails.append("gen/rust/src/lib.rs: missing")
        elif not rustc:
            notes.append("no rustc: skipped the Rust build (run it in the rust container)")
        else:
            exe = os.path.join(td, "rust_tests")
            r = _run([rustc, "--edition", "2021", "--test", "-D", "warnings", "-o", exe, crate])
            if r.returncode:
                fails.append("gen/rust: build failed: %s" % " | ".join(_tail(r)))
            else:
                r = _run([exe])
                if r.returncode:
                    fails.append("gen/rust: tests failed: %s" % " | ".join(_tail(r)))
    return fails


