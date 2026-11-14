"""Build the committed outputs: the proof that they compile, import and agree with the vectors.

  C           every generated C header and forwarding header compiles with -Wall -Wextra -Werror,
              and a generated program decodes every vector with the header's own macros
  Python      every generated Python module runs its self-test
  genxml      the vendored upstream pack generator accepts every export; what it
              writes compiles, and every vector unpacks and repacks through it
  Rust        the crate builds with warnings denied and its tests pass (rustc is optional)
  export      each file of the export profiles (gen_export.py) compiles: the Rust constants as a library
              with warnings denied, the C macros against a small stand-in for the REG and FIELD macros,
              with a static assertion per register offset and array stride

The paths are the repository's own: generated/{c,python,xml,rust} in the current layout,
gen/{c,py,genxml,rust} in the old one.
"""
import os
import shutil
import subprocess
import sys
import tempfile

from . import gen_c, gen_export, gen_genxml
from .model import publish_profile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(HERE, "vendor", "genxml", "gen_pack.py")
PRELUDE = os.path.join(HERE, "genxml_prelude.h")


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def _tail(r):
    return ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-6:]


# Stand-in for the REG and FIELD macros the C export expects from its includer, with the same meaning
# as the registerfields.h macros: A_ is the byte offset, R_ the index in units of the register size.
C_SHIM = """#include <stdint.h>
#define MAKE_64BIT_MASK(shift, length) (((~0ULL) >> (64 - (length))) << (shift))
#define REG8(reg, addr) enum { A_##reg = (addr), R_##reg = (addr) };
#define REG16(reg, addr) enum { A_##reg = (addr), R_##reg = (addr) / 2 };
#define REG32(reg, addr) enum { A_##reg = (addr), R_##reg = (addr) / 4 };
#define REG64(reg, addr) enum { A_##reg = (addr), R_##reg = (addr) / 8 };
#define FIELD(reg, field, shift, length) \\
    enum { R_##reg##_##field##_SHIFT = (shift), R_##reg##_##field##_LENGTH = (length), \\
           R_##reg##_##field##_MASK = MAKE_64BIT_MASK(shift, length) };
"""


def verify_export(repo, models, td, cc, rustc, notes):
    fails = []
    cfg = repo.settings.get("gen", {}).get("export", {})
    profiles, units = cfg.get("profiles", []), cfg.get("units", {})
    root, gen_root = repo.root, repo.layout.gen_root()
    shim = os.path.join(td, "export_shim.h")
    with open(shim, "w", encoding="utf-8") as f:
        f.write(C_SHIM)
    for name in sorted(units):
        m = models.get(name)
        if m is None:
            continue
        base = units[name].get("base", 0)
        if gen_export.RUST_DIR in profiles and rustc:
            rel = "%s/%s/%s.rs" % (gen_root, gen_export.RUST_DIR, name)
            r = _run([rustc, "--edition", "2021", "--crate-type", "lib", "-D", "warnings", "--emit", "metadata",
                      "-o", os.path.join(td, "export_%s.rmeta" % name), os.path.join(root, rel)])
            if r.returncode:
                fails.append("%s: build failed: %s" % (rel, " | ".join(_tail(r))))
        if gen_export.C_DIR in profiles and cc:
            rel = "%s/%s/%s.h" % (gen_root, gen_export.C_DIR, name)
            src = os.path.join(td, "export_%s.c" % name)
            lines = ['#include "export_shim.h"', '#include "%s"' % os.path.join(root, rel)]
            for n, r in m["registers"].items():
                lines.append("_Static_assert(A_%s == 0x%x, \"%s\");" % (n.upper(), r["offset"] - base, n))
                if r["count"] > 1:
                    lines.append("_Static_assert(%s_STRIDE == 0x%x, \"%s\");" % (n.upper(), r["stride"], n))
            with open(src, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            r = _run([cc, "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-std=gnu11", "-I", td, "-x", "c", src])
            if r.returncode:
                fails.append("%s: C compile failed: %s" % (rel, " | ".join(_tail(r))))
    if units and gen_export.RUST_DIR in profiles and not rustc:
        notes.append("no rustc: skipped the Rust export build (run it in the rust container)")
    return fails


def verify(repo, notes=None):
    """Return a list of failure strings; `notes` collects skipped steps."""
    notes = notes if notes is not None else []
    fails = []
    cc = shutil.which("cc") or shutil.which("gcc")
    rustc = shutil.which("rustc")
    root = repo.root
    lay = repo.layout
    models = {n: (u.model if repo.profile == "internal" else publish_profile(u.model)) for n, u in repo.units.items()}
    with tempfile.TemporaryDirectory() as td:
        for name, m in sorted(models.items()):
            c_rel = lay.gen_file("c", name)
            hdr = os.path.join(root, c_rel)
            if not os.path.isfile(hdr):
                fails.append("%s: missing" % c_rel)
                continue
            if cc:
                r = _run([cc, "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-std=c99", "-x", "c", hdr])
                if r.returncode:
                    fails.append("%s: C compile failed: %s" % (c_rel, " | ".join(_tail(r))))
                    continue
                src = os.path.join(td, "t_%s.c" % name)
                with open(src, "w", encoding="utf-8") as f:
                    f.write(gen_c.gen_c_test(m, hdr))
                exe = os.path.join(td, "t_%s" % name)
                r = _run([cc, "-std=c99", "-Wall", "-Werror", "-o", exe, src])
                if r.returncode:
                    fails.append("%s: self-test compile failed: %s" % (c_rel, " | ".join(_tail(r))))
                elif _run([exe]).returncode:
                    fails.append("%s: a vector disagrees with the generated macros" % c_rel)
                legacy = m["c"].get("legacy_header")
                if legacy and os.path.isfile(os.path.join(root, legacy)):
                    r = _run([cc, "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-std=c99", "-x", "c", os.path.join(root, legacy)])
                    if r.returncode:
                        fails.append("%s: forwarding header does not compile: %s" % (legacy, " | ".join(_tail(r))))
            py_rel = lay.gen_file("py", name)
            py = os.path.join(root, py_rel)
            if os.path.isfile(py):
                r = _run([sys.executable, "-I", py])
                if r.returncode:
                    fails.append("%s: self-test failed: %s" % (py_rel, " | ".join(_tail(r))))
            xml_rel = lay.gen_file("xml", name)
            xml = os.path.join(root, xml_rel)
            if os.path.isfile(xml):
                r = _run([sys.executable, "-I", VENDOR, xml, PRELUDE])
                if r.returncode:
                    fails.append("%s: upstream pack generator refused it: %s" % (xml_rel, " | ".join(_tail(r))))
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
                        fails.append("%s: upstream output does not compile: %s" % (xml_rel, " | ".join(_tail(c))))
                    else:
                        t = _run([exe])
                        if t.returncode:
                            fails.append("%s: a vector does not roundtrip through the upstream pack code: %s"
                                         % (xml_rel, " | ".join(_tail(t))))
        if not cc:
            notes.append("no C compiler: skipped the C and genxml builds")
        crate_rel = "%s/src/lib.rs" % lay.gen_dir("rust")
        crate = os.path.join(root, crate_rel)
        if not os.path.isfile(crate):
            if models:
                fails.append("%s: missing" % crate_rel)
        elif not rustc:
            notes.append("no rustc: skipped the Rust build (run it in the rust container)")
        else:
            exe = os.path.join(td, "rust_tests")
            r = _run([rustc, "--edition", "2021", "--test", "-D", "warnings", "-o", exe, crate])
            if r.returncode:
                fails.append("%s: build failed: %s" % (lay.gen_dir("rust"), " | ".join(_tail(r))))
            else:
                r = _run([exe])
                if r.returncode:
                    fails.append("%s: tests failed: %s" % (lay.gen_dir("rust"), " | ".join(_tail(r))))
        fails += verify_export(repo, models, td, cc, rustc, notes)
    return fails


