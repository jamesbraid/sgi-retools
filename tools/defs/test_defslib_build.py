#!/usr/bin/env python3
"""Tests for the build step of defs-check: compile, import, upstream pack, Rust."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import build, loader  # noqa: E402
from testkit import HERE, RepoTest, which  # noqa: E402

CHECK = os.path.join(HERE, "defs-check")
GEN = os.path.join(HERE, "defs-gen")
CC = which("cc", "gcc")


class BuildTest(RepoTest):
    def setUp(self):
        super().setUp()
        r = subprocess.run([sys.executable, GEN, "--root", self.root], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def verify(self):
        notes = []
        return build.verify(loader.load_repo(self.root), notes), notes

    @unittest.skipUnless(CC, "no C compiler")
    def test_fixture_builds(self):
        fails, notes = self.verify()
        self.assertEqual(fails, [])

    @unittest.skipUnless(CC, "no C compiler")
    def test_forwarding_header_is_compiled(self):
        self.edit("defs/uart.toml", 'public_from =', 'c = { legacy_header = "UART_DECODE.h", aliases = { UART_DIV_SHIFT = "UART_CTL_DIVISOR_SHIFT" } }\npublic_from =')
        subprocess.run([sys.executable, GEN, "--root", self.root], check=True, capture_output=True)
        self.assertEqual(self.verify()[0], [])
        self.write("UART_DECODE.h", '#include "gen/c/uart.h"\n#define BAD (UART_NOPE + 1)\nint x = BAD;\n')
        fails, _ = self.verify()
        self.assertTrue([f for f in fails if "forwarding header does not compile" in f], fails)

    @unittest.skipUnless(CC, "no C compiler")
    def test_a_broken_header_fails_the_c_build(self):
        with open(self.path("gen/c/uart.h"), "a", encoding="utf-8") as f:
            f.write("\nint broken = ;\n")
        fails, _ = self.verify()
        self.assertTrue([f for f in fails if "C compile failed" in f], fails)

    def test_a_wrong_python_module_fails(self):
        self.write("gen/py/uart.py", self.read("gen/py/uart.py").replace("(8, 1)", "(8, 2)"))
        fails, _ = self.verify()
        self.assertTrue([f for f in fails if "gen/py/uart.py: self-test failed" in f], fails)

    def test_upstream_generator_refusing_the_xml_fails(self):
        self.write("gen/genxml/uart.xml", "<genxml><struct name='X' size='4'><field name='a' start='0' size='1' type='bogus'/></struct></genxml>")
        fails, _ = self.verify()
        self.assertTrue([f for f in fails if "gen/genxml/uart.xml" in f], fails)

    @unittest.skipUnless(CC, "no C compiler")
    def test_defs_check_build_flag(self):
        r = subprocess.run([sys.executable, CHECK, "--root", self.root, "--build"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("build: ok", r.stdout)
        with open(self.path("gen/c/uart_rev2.h"), "a", encoding="utf-8") as f:
            f.write("\nint broken = ;\n")
        r = subprocess.run([sys.executable, CHECK, "--root", self.root, "--build", "--no-fresh"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("build: 1 failure(s)", r.stdout)

    def test_missing_rustc_is_a_note_not_a_failure(self):
        fails, notes = self.verify()
        if not which("rustc"):
            self.assertEqual(fails, [])
            self.assertTrue([n for n in notes if "rustc" in n], notes)


if __name__ == "__main__":
    unittest.main()
