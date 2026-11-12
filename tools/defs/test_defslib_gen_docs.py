#!/usr/bin/env python3
"""Tests for the Markdown reference page generator."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen_docs, loader  # noqa: E402
from defslib.model import publish_profile  # noqa: E402
from testkit import RepoTest  # noqa: E402


class GenDocsTest(RepoTest):
    def unit(self, name="uart"):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        return repo.units[name].model

    def test_every_item_appears_with_grade_and_source(self):
        text = gen_docs.gen_docs(self.unit(), "defs/uart.toml")
        for needle in ("# made-up UART", "`ctl`", "`status`", "`data`", "`FRAME`", "`parity`", "`FIFO_DEPTH`",
                       "`divisor`", "`rx_ready`", "`payload`", "`even`", "Array of 16 registers"):
            self.assertIn(needle, text)
        divisor = [l for l in text.splitlines() if "`divisor`" in l][0]
        self.assertIn("established", divisor)
        self.assertIn("fixture notes (docs/uart.md)", divisor)
        self.assertIn("fixture notes (status page)", [l for l in text.splitlines() if "`rx_ready`" in l][0])
        even = [l for l in text.splitlines() if l.startswith("| `even`")][0]
        self.assertIn("inferred", even)

    def test_tables_are_well_formed(self):
        text = gen_docs.gen_docs(self.unit(), "defs/uart.toml")
        lines = text.splitlines()
        for i, l in enumerate(lines):
            if l.startswith("|---"):
                cols = l.count("|") - 1
                j = i - 1
                while j >= 0 and lines[j].startswith("|"):
                    self.assertEqual(len(re.findall(r"(?<!\\)\|", lines[j])) - 1, cols, lines[j])
                    j -= 1

    def test_pipe_in_prose_is_escaped(self):
        self.edit("defs/uart.toml", 'doc = "One frame: a start bit and eight payload bits."', 'doc = "A | B."')
        self.edit("defs/uart.toml", 'start = { bits = [0, 0], grade = "established" }', 'start = { bits = [0, 0], grade = "established", doc = "a|b" }')
        self.assertIn("a\\|b", gen_docs.gen_docs(self.unit(), "defs/uart.toml"))

    def test_register_index_space_and_vectors(self):
        self.edit("defs/uart.toml", 'access = "r"\nwidth = 32\ngrade', 'access = "r"\nwidth = 32\nspace = "hq"\ngrade')
        self.edit("defs/uart.toml", '[enums.parity]', '[spaces.hq]\nunit = "reg"\ndoc = "register indexes"\n\n[enums.parity]')
        text = gen_docs.gen_docs(self.unit(), "defs/uart.toml")
        self.assertIn("register index", text)
        self.assertIn("| `FRAME` | 0x6b | vector | start=1, payload=53 |", text)

    def test_notes_only_in_the_internal_profile(self):
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "Control register."\nnotes = "private reading"')
        m = self.unit()
        self.assertIn("private reading", gen_docs.gen_docs(m, "defs/uart.toml", "internal"))
        self.assertNotIn("private reading", gen_docs.gen_docs(publish_profile(m), "defs/uart.toml", "public"))

    def test_private_sources_only_in_the_internal_profile(self):
        self.edit("defs/uart.toml", 'from = "fixture notes (status page)"', 'from = "driver readings"')
        m = self.unit()
        self.assertIn("driver readings", gen_docs.gen_docs(m, "defs/uart.toml", "internal"))
        self.assertNotIn("driver readings", gen_docs.gen_docs(publish_profile(m), "defs/uart.toml", "public"))


if __name__ == "__main__":
    unittest.main()
