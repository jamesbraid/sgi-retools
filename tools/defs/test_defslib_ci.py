#!/usr/bin/env python3
"""Tests for ci-check: the TOML path when defs/ exists, the old path otherwise."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from testkit import HERE, CurrentRepoTest, OldRepoTest, RepoTest, which  # noqa: E402

CI = os.path.join(HERE, "ci-check")
GEN = os.path.join(HERE, "defs-gen")
CC = which("cc", "gcc")


def ci(cwd):
    return subprocess.run([sys.executable, CI], capture_output=True, text=True, cwd=cwd)


@unittest.skipUnless(CC, "no C compiler")
class TomlPathTest(RepoTest):
    def setUp(self):
        super().setUp()
        subprocess.run([sys.executable, GEN, "--root", self.root], check=True, capture_output=True)

    def test_clean_repo_passes(self):
        r = ci(self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("hardware definitions ok", r.stdout)
        self.assertIn("build: ok", r.stdout)

    def test_stale_output_fails(self):
        self.edit("defs/uart.toml", 'title = "made-up UART (fixture for the defs tools)"', 'title = "renamed"')
        r = ci(self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("gen/c/uart.h: stale", r.stdout)
        self.assertIn("FAIL definitions: exit 1", r.stderr)

    def test_broken_source_fails(self):
        self.edit("defs/uart.toml", "width = 8\n", "width = 9\n")
        r = ci(self.root)
        self.assertEqual(r.returncode, 1)

    def test_old_defs_toml_beside_defs_is_noted_not_used(self):
        self.write("defs.toml", "[project]\nname = \"x\"\n")
        r = ci(self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("defs.toml is not used", r.stderr)


@unittest.skipUnless(CC, "no C compiler")
class CurrentLayoutTest(CurrentRepoTest):
    def setUp(self):
        super().setUp()
        subprocess.run([sys.executable, GEN, "--root", self.root], check=True, capture_output=True)

    def test_clean_repo_passes(self):
        r = ci(self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("hardware definitions ok", r.stdout)
        self.assertIn("build: ok", r.stdout)

    def test_stale_output_fails(self):
        self.edit("devices/uart/registers.toml", 'title = "made-up UART (fixture for the defs tools)"', 'title = "renamed"')
        r = ci(self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("generated/c/uart.h: stale", r.stdout)

    def test_old_defs_toml_beside_the_maps_is_noted_not_used(self):
        self.write("defs.toml", "[project]\nname = \"x\"\n")
        r = ci(self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("defs.toml is not used", r.stderr)
        self.assertIn("tools/config/defs-check.toml", r.stderr)


class OldPathTest(OldRepoTest):
    def test_nothing_to_check(self):
        os.remove(self.path("defs.toml"))
        r = ci(self.root)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "no decode headers"))

    def test_old_config_takes_the_old_path(self):
        r = ci(self.root)         # the old fixture has no generated Rust, which only the old path asks for
        self.assertEqual(r.returncode, 1)
        self.assertIn("generated Rust", r.stderr)
        self.assertNotIn("hardware definitions", r.stdout)


if __name__ == "__main__":
    unittest.main()
