#!/usr/bin/env python3
"""Tests for the sibling check: a register defined in two sibling repositories fails, and a sibling
that is not present is only a note."""
import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import loader, siblings  # noqa: E402
from testkit import HERE, UNITS_FIXTURE, CurrentRepoTest  # noqa: E402

GEN = os.path.join(HERE, "defs-gen")
CHECK = os.path.join(HERE, "defs-check")


def tool(script, root, *args):
    return subprocess.run([sys.executable, script, "--root", root, *args], capture_output=True, text=True)


class SiblingTest(CurrentRepoTest):
    """A register defined in two sibling repositories fails; an absent sibling is only a note."""

    def setUp(self):
        super().setUp()
        self.sib = os.path.join(self.tmp, "other")
        shutil.copytree(self.FIXTURE, self.sib)
        self.pins = self.path("tools/config/inventory-siblings.json")
        with open(self.pins, "w", encoding="utf-8") as f:
            json.dump({"other": "0" * 40}, f)

    def run_siblings(self, given=None):
        repo = loader.load_repo(self.root)
        return siblings.check(repo, given or {})

    def test_same_unit_and_offset_in_two_repos_fails(self):
        fails, notes = self.run_siblings({"other": self.sib})
        self.assertEqual(notes, [])
        self.assertTrue(any("offset 0x10 of unit uart" in f and "sibling other" in f for f in fails), fails)

    def test_different_offset_or_unit_is_fine(self):
        for rel in ("devices/uart/registers.toml", "devices/uart/registers.rev2.toml", "devices/uart/registers-extra.toml"):
            p = os.path.join(self.sib, rel)
            with open(p, encoding="utf-8") as f:
                text = f.read()
            for old, new in (("offset = 0x10", "offset = 0x11"), ("offset = 0x14", "offset = 0x15"), ("offset = 0x120", "offset = 0x121"),
                             ("offset = 0x18", "offset = 0x19"), ("offset = 0x200", "offset = 0x201")):
                text = text.replace(old, new)
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
        self.assertEqual(self.run_siblings({"other": self.sib}), ([], []))

    def test_absent_sibling_is_a_note_not_a_failure(self):
        shutil.rmtree(self.sib)
        fails, notes = self.run_siblings()
        self.assertEqual(fails, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("sibling other is not present locally", notes[0])

    def test_sibling_found_next_to_the_repository_and_in_the_cache(self):
        os.makedirs(self.path(".cache/siblings"))
        shutil.move(self.sib, self.path(".cache/siblings/other"))
        fails, notes = self.run_siblings()
        self.assertTrue(fails and not notes)

    def test_sibling_on_the_old_layout_is_read(self):
        shutil.rmtree(self.sib)
        shutil.copytree(UNITS_FIXTURE, self.sib)
        fails, _ = self.run_siblings({"other": self.sib})
        self.assertTrue(any("sibling other" in f for f in fails), fails)

    def test_sibling_that_does_not_load_is_a_note(self):
        with open(os.path.join(self.sib, "devices/uart/registers.toml"), "w", encoding="utf-8") as f:
            f.write("unit = [")
        fails, notes = self.run_siblings({"other": self.sib})
        self.assertEqual(fails, [])
        self.assertIn("does not load", notes[0])

    def test_pins_in_the_old_place_are_read(self):
        shutil.move(self.pins, self.path("tools/config/old-pins"))
        os.makedirs(self.path("scripts"))
        shutil.move(self.path("tools/config/old-pins"), self.path("scripts/inventory-siblings.json"))
        fails, _ = self.run_siblings({"other": self.sib})
        self.assertTrue(fails)

    def test_the_check_runs_inside_defs_check(self):
        subprocess.run([sys.executable, GEN, "--root", self.root], check=True, capture_output=True)
        r = tool(CHECK, self.root, "--sibling", "other=%s" % self.sib)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAIL siblings:", r.stdout)
        r = tool(CHECK, self.root, "--sibling", "other=%s" % self.sib, "--skip-siblings")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        shutil.rmtree(self.sib)
        r = tool(CHECK, self.root)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("note: sibling other is not present locally", r.stderr)


if __name__ == "__main__":
    unittest.main()
