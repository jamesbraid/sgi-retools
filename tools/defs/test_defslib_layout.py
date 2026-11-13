#!/usr/bin/env python3
"""Tests for the register-map layout: devices/ and formats/ read and written like defs/ and gen/,
and the old layout still read as before."""
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen, loader  # noqa: E402
from defslib.model import publish_profile  # noqa: E402
from testkit import HERE, UNITS_FIXTURE, CurrentRepoTest, RepoTest, which  # noqa: E402

GEN = os.path.join(HERE, "defs-gen")
CHECK = os.path.join(HERE, "defs-check")
CC = which("cc", "gcc")


def tool(script, root, *args):
    return subprocess.run([sys.executable, script, "--root", root, *args], capture_output=True, text=True)


class LoadTest(CurrentRepoTest):
    def test_units_come_from_devices_and_formats(self):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        self.assertEqual(sorted(repo.units), ["frame", "uart", "uart_extra", "uart_rev2"])
        self.assertEqual(repo.units["uart"].path, "devices/uart/registers.toml")
        self.assertEqual(repo.units["uart_rev2"].path, "devices/uart/registers.rev2.toml")
        self.assertEqual(repo.units["uart_rev2"].dir, "devices/uart")
        self.assertEqual(repo.units["frame"].path, "formats/frame/format.toml")
        self.assertIn("irq_mask", repo.units["uart_rev2"].model["registers"])
        self.assertEqual(repo.layout.defs_mode, "new")

    def test_settings_come_from_tools_config(self):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.project, "mini")
        self.assertIn("uart", repo.settings["units"])

    def test_base_unit_must_match_its_directory(self):
        self.edit("devices/uart/registers.toml", 'unit = "uart"', 'unit = "serial"')
        repo = loader.load_repo(self.root)
        self.assertTrue(any("does not match the directory name" in e for e in repo.errors), repo.errors)

    def test_extra_unit_may_have_its_own_name(self):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.units["uart_extra"].path, "devices/uart/registers-extra.toml")

    def test_overlay_without_a_base_is_an_error(self):
        os.remove(self.path("devices/uart/registers.toml"))
        repo = loader.load_repo(self.root)
        self.assertTrue(any("imports unit 'uart'" in e for e in repo.errors), repo.errors)

    def test_other_files_in_a_unit_directory_are_not_sources(self):
        self.write("devices/uart/notes.toml", "this is not a register map = [")
        self.write("devices/uart/format.toml", "also not")
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])

    def test_current_layout_wins_over_defs(self):
        shutil.copytree(os.path.join(UNITS_FIXTURE, "defs"), self.path("defs"))
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.units["uart"].path, "devices/uart/registers.toml")

    def test_helpers_sit_beside_the_source(self):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.units["uart"].helpers_path, "devices/uart/helpers.h")
        self.assertEqual(repo.units["uart_rev2"].helpers_path, "devices/uart/helpers.rev2.h")
        self.assertEqual(repo.units["uart_extra"].helpers_path, "devices/uart/helpers-extra.h")


class GenerateTest(CurrentRepoTest):
    def render(self):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        files, errors = gen.render(repo)
        self.assertEqual(errors, [])
        return files

    def test_paths(self):
        files = self.render()
        for rel in ("generated/c/uart.h", "generated/rust/src/uart.rs", "generated/rust/Cargo.toml",
                    "generated/rust/src/lib.rs", "generated/python/uart.py", "generated/json/uart.json",
                    "generated/xml/uart.xml", "devices/uart/registers.md", "devices/uart/registers.rev2.md",
                    "devices/uart/registers-extra.md", "formats/frame/format.md", "generated/c/frame.h"):
            self.assertIn(rel, files)
        self.assertFalse([r for r in files if r.startswith("gen/")])

    def test_register_table_says_generated_on_its_first_line(self):
        first = self.render()["devices/uart/registers.md"].splitlines()[0]
        self.assertTrue(first.startswith("<!-- generated from devices/uart/registers.toml by defs-gen"), first)

    def test_generated_text_names_the_current_sources(self):
        files = self.render()
        self.assertTrue(files["generated/c/uart.h"].startswith("/* generated from devices/uart/registers.toml by defs-gen"))
        self.assertIn("devices/ and formats/", files["generated/rust/src/lib.rs"])

    def test_write_prunes_outputs_of_removed_units_but_not_hand_written_files(self):
        tool(GEN, self.root)
        self.write("generated/json/gone.json", "{}\n")
        self.write("generated/xml/gone.xml", "<x/>\n")
        self.write("generated/README.md", "hand-written\n")
        self.write("devices/uart/notes.md", "hand-written\n")
        r = tool(GEN, self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("removed generated/json/gone.json", r.stdout)
        self.assertFalse(os.path.exists(self.path("generated/json/gone.json")))
        self.assertFalse(os.path.exists(self.path("generated/xml/gone.xml")))
        self.assertTrue(os.path.exists(self.path("generated/README.md")))
        self.assertTrue(os.path.exists(self.path("devices/uart/notes.md")))
        self.assertTrue(os.path.exists(self.path("generated/json/uart.json")))

    def test_same_outputs_as_the_old_layout(self):
        old = RepoTest("run")
        old.setUp()
        self.addCleanup(old.tearDown)
        old_files = gen.render(loader.load_repo(old.root))[0]
        new_files = self.render()
        for old_rel, new_rel in (("gen/c/uart.h", "generated/c/uart.h"), ("gen/rust/src/uart.rs", "generated/rust/src/uart.rs"),
                                 ("gen/py/uart.py", "generated/python/uart.py"), ("gen/json/uart.json", "generated/json/uart.json"),
                                 ("gen/genxml/uart.xml", "generated/xml/uart.xml"),
                                 ("gen/c/uart_rev2.h", "generated/c/uart_rev2.h")):
            a = old_files[old_rel].replace("defs/uart.toml", "SRC").replace("defs/uart.rev2.toml", "SRC")
            b = new_files[new_rel].replace("devices/uart/registers.toml", "SRC").replace("devices/uart/registers.rev2.toml", "SRC")
            self.assertEqual(a, b, new_rel)
        self.assertEqual(sorted(r for r in old_files if r.startswith("gen/docs/")), ["gen/docs/uart.md", "gen/docs/uart_rev2.md"])

    def test_public_profile_still_drops_internal_text(self):
        repo = loader.load_repo(self.root)
        m = repo.units["uart"].model
        self.assertEqual(publish_profile(m)["unit"], "uart")


@unittest.skipUnless(CC, "no C compiler")
class ToolsTest(CurrentRepoTest):
    def gen_all(self):
        r = tool(GEN, self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_defs_gen_writes_then_check_is_clean_and_builds(self):
        self.gen_all()
        self.assertTrue(os.path.isfile(self.path("generated/c/uart.h")))
        self.assertTrue(os.path.isfile(self.path("devices/uart/registers.md")))
        self.assertFalse(os.path.exists(self.path("gen")))
        r = tool(CHECK, self.root, "--build")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("build: ok", r.stdout)
        r = tool(GEN, self.root, "--check")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_stale_source_is_reported_with_the_current_path(self):
        self.gen_all()
        self.edit("devices/uart/registers.toml", 'title = "made-up UART (fixture for the defs tools)"', 'title = "renamed"')
        r = tool(CHECK, self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("generated/c/uart.h: stale", r.stdout)
        self.assertIn("devices/uart/registers.md: stale", r.stdout)

    def test_hand_written_pages_are_left_alone_and_leftover_tables_go(self):
        self.gen_all()
        self.write("devices/uart/README.md", self.read("devices/uart/README.md") + "\nUsed by: nothing yet.\n")
        shutil.copy(self.path("devices/uart/registers.md"), self.path("devices/uart/registers.old.md"))
        r = tool(GEN, self.root, "--check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("registers.old.md: no unit generates this file", r.stdout)
        tool(GEN, self.root)
        self.assertFalse(os.path.exists(self.path("devices/uart/registers.old.md")))
        self.assertTrue(os.path.isfile(self.path("devices/uart/README.md")))

    def test_hand_written_helpers_are_included_and_scanned(self):
        self.write("devices/uart/helpers.h", "/* hand-written */\n#define UART_CTL_DIV(v) (((v) >> 16) & 0xffff)\n")
        self.gen_all()
        self.assertIn('#include "../../devices/uart/helpers.h"', self.read("generated/c/uart.h"))
        r = tool(CHECK, self.root, "--build")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_unit_flag_narrows_the_check(self):
        self.gen_all()
        r = tool(CHECK, self.root, "--unit", "frame")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_check_against_the_fixed_claims_text_still_runs(self):
        self.gen_all()
        self.edit("devices/uart/README.md", "bits 31:16", "bits 31:17")
        r = tool(CHECK, self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("control register fields", r.stdout)


class FallbackTest(RepoTest):
    """The old layout behaves as it did: defs/ in, gen/ out."""

    def test_old_layout_round_trip(self):
        r = tool(GEN, self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.isfile(self.path("gen/c/uart.h")))
        self.assertTrue(os.path.isfile(self.path("gen/docs/uart.md")))
        self.assertFalse(os.path.exists(self.path("generated")))
        self.assertTrue(self.read("gen/docs/uart.md").startswith("# "))
        if CC:
            r = tool(CHECK, self.root, "--build")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_old_layout_is_reported_as_old(self):
        self.assertEqual(loader.load_repo(self.root).layout.defs_mode, "old")


if __name__ == "__main__":
    unittest.main()
