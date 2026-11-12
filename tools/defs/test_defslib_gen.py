#!/usr/bin/env python3
"""Tests for rendering, writing and staleness of the generated tree."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen, loader  # noqa: E402
from testkit import HERE, RepoTest  # noqa: E402

GEN = os.path.join(HERE, "defs-gen")


def run(*args):
    return subprocess.run([sys.executable, GEN, *args], capture_output=True, text=True)


class GenTest(RepoTest):
    def render(self, profile=None):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        files, errors = gen.render(repo, profile)
        self.assertEqual(errors, [])
        return repo, files

    def test_every_output_kind_per_unit(self):
        _, files = self.render()
        for unit in ("uart", "uart_rev2"):
            for rel in ("gen/c/%s.h", "gen/rust/src/%s.rs", "gen/py/%s.py", "gen/json/%s.json",
                        "gen/genxml/%s.xml", "gen/docs/%s.md"):
                self.assertIn(rel % unit, files)
        self.assertIn("gen/rust/Cargo.toml", files)
        self.assertIn("pub mod uart_rev2;", files["gen/rust/src/lib.rs"])

    def test_overlay_unit_is_rendered_from_the_merged_source(self):
        _, files = self.render()
        self.assertIn("UART_REV2_IRQ_MASK_OFFSET", files["gen/c/uart_rev2.h"])
        self.assertNotIn("IRQ_MASK", files["gen/c/uart.h"])
        self.assertIn("defs/uart.rev2.toml", files["gen/c/uart_rev2.h"].splitlines()[0])

    def test_output_is_deterministic(self):
        self.assertEqual(self.render()[1], self.render()[1])

    def test_profile_controls_sources(self):
        self.edit("defs/uart.toml", 'from = "fixture notes (status page)"', 'from = "driver readings"')
        self.assertNotIn("driver readings", self.render("public")[1]["gen/docs/uart.md"])
        self.assertIn("driver readings", self.render("internal")[1]["gen/docs/uart.md"])

    def test_repo_setting_chooses_the_profile(self):
        self.edit("defs/uart.toml", 'from = "fixture notes (status page)"', 'from = "driver readings"')
        self.edit("defs/check.toml", "[project]", '[gen]\nprofile = "internal"\n\n[project]')
        self.assertIn("driver readings", self.render()[1]["gen/docs/uart.md"])

    def test_crate_name_default_and_setting(self):
        self.assertIn('name = "hwdefs"', self.render()[1]["gen/rust/Cargo.toml"])
        self.edit("defs/check.toml", "[project]", '[gen]\nrust_crate = "uart-regs"\n\n[project]')
        self.assertIn('name = "uart-regs"', self.render()[1]["gen/rust/Cargo.toml"])

    def test_helpers_file_is_included_when_present(self):
        self.write("defs/uart_helpers.h", "#define UART_GET(w, f) (((w) >> UART_##f##_SHIFT) & UART_##f##_MASK)\n")
        self.assertIn("../../defs/uart_helpers.h", self.render()[1]["gen/c/uart.h"])
        self.assertNotIn("uart_helpers", self.render()[1]["gen/c/uart_rev2.h"])

    def test_forwarding_header_at_the_legacy_path(self):
        self.edit("defs/uart.toml", 'public_from =', 'c = { legacy_header = "include/UART_DECODE.h", aliases = { OLD_NAME = "UART_FIFO_DEPTH" } }\npublic_from =')
        _, files = self.render()
        fwd = files["include/UART_DECODE.h"]
        self.assertIn('#include "../gen/c/uart.h"', fwd)
        self.assertIn("#define OLD_NAME", fwd)
        self.edit("defs/check.toml", "[project]", '[gen]\nforwarding = "off"\n\n[project]')
        self.assertNotIn("include/UART_DECODE.h", self.render()[1])

    def test_write_then_check_is_fresh(self):
        r = run("--root", self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(self.path("gen/c/uart.h")))
        r = run("--root", self.root, "--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("fresh", r.stdout)

    def test_second_write_changes_nothing(self):
        run("--root", self.root)
        before = {rel: os.stat(self.path(rel)).st_mtime_ns for rel in gen.existing(self.root)}
        r = run("--root", self.root)
        self.assertIn("0 written", r.stdout)
        self.assertEqual(before, {rel: os.stat(self.path(rel)).st_mtime_ns for rel in gen.existing(self.root)})

    def test_source_edit_makes_the_output_stale(self):
        run("--root", self.root)
        self.edit("defs/uart.toml", "divisor = { bits = [31, 16]", "divisor = { bits = [30, 16]")
        r = run("--root", self.root, "--check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("gen/c/uart.h: stale", r.stdout)

    def test_missing_and_orphan_files_fail(self):
        run("--root", self.root)
        os.remove(self.path("gen/py/uart.py"))
        self.write("gen/c/old_unit.h", "x\n")
        r = run("--root", self.root, "--check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("gen/py/uart.py: missing", r.stdout)
        self.assertIn("gen/c/old_unit.h: no unit generates this file", r.stdout)

    def test_write_removes_orphans_it_made_and_keeps_others(self):
        run("--root", self.root)
        self.write("gen/c/old_unit.h", "/* generated from defs/old.toml by defs-gen - do not edit, change the source */\n")
        self.write("gen/notes.txt", "hand-written\n")
        r = run("--root", self.root)
        self.assertIn("removed gen/c/old_unit.h", r.stdout)
        self.assertFalse(os.path.exists(self.path("gen/c/old_unit.h")))
        self.assertTrue(os.path.exists(self.path("gen/notes.txt")))
        self.assertIn("left alone", r.stderr)

    def test_bad_source_is_a_setup_error(self):
        self.edit("defs/uart.toml", "width = 8\n", "width = 9\n")
        r = run("--root", self.root)
        self.assertEqual(r.returncode, 2)
        self.assertIn("must be one of 8, 16, 32, 64", r.stderr)

    def test_macro_collision_is_a_setup_error(self):
        self.edit("defs/uart.toml", "[constants]", '[constants]\nCTL_OFFSET = { value = 1, grade = "unknown" }')
        self.edit("defs/uart.toml", 'public_from =', 'c = { const_prefix = "UART" }\npublic_from =')
        r = run("--root", self.root)
        self.assertEqual(r.returncode, 2)
        self.assertIn("defined twice", r.stderr)

    def test_no_defs_directory(self):
        r = run("--root", self.tmp)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
