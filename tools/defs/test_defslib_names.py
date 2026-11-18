#!/usr/bin/env python3
"""Tests for name provenance: the name_source field, its check and the defs-names unchecked listing."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import loader, modelcheck  # noqa: E402
from testkit import HERE, RepoTest  # noqa: E402

NAMES = os.path.join(HERE, "defs-names")


class ProvenanceTest(RepoTest):
    def names(self, *args):
        return subprocess.run([sys.executable, NAMES, *args], capture_output=True, text=True)

    def test_everything_is_unchecked_by_default(self):
        r = self.names("unchecked", "--root", self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("uart\tctl\n", r.stdout)
        self.assertIn("uart\tctl.divisor\n", r.stdout)
        self.assertIn("uart\tFRAME.payload\n", r.stdout)

    def test_a_unit_or_register_can_claim_a_source(self):
        self.edit("defs/uart.toml", 'public_from = ["fixture notes"]', 'public_from = ["fixture notes"]\nname_source = "ours"')
        self.edit("defs/uart.toml", "[registers.status]\n", '[registers.status]\nname_source = "imported-unchecked"\n')
        out = self.names("unchecked", "--root", self.root).stdout
        self.assertEqual([ln for ln in out.splitlines() if ln.startswith("uart\t") and not ln.startswith("uart\tstatus")], [])

    def test_a_public_name_needs_a_citation(self):
        self.edit("defs/uart.toml", "[registers.status]\n", '[registers.status]\nname_source = "public"\n')
        def problems():
            return modelcheck.check_unit(loader.load_repo(self.root).units["uart"].model)
        self.assertTrue([p for p in problems() if "name_cite" in p])
        self.edit("defs/uart.toml", 'name_source = "public"', 'name_source = "public"\nname_cite = "a datasheet"')
        self.assertEqual(problems(), [])


if __name__ == "__main__":
    unittest.main()
