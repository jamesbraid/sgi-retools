#!/usr/bin/env python3
"""Tests for the stamp every generated file carries: licence, generator version and input hash."""
import hashlib
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen, loader  # noqa: E402
from testkit import RepoTest  # noqa: E402


class StampTest(RepoTest):
    def render(self, license=True):
        if license:
            self.edit("defs/check.toml", '[project]\nname = "mini"\n', '[project]\nname = "mini"\nlicense = "BSD-3-Clause"\n')
        repo = loader.load_repo(self.root)
        files, errors = gen.render(repo)
        self.assertEqual(errors, [])
        return files

    def test_every_file_carries_licence_version_and_input_hash(self):
        files = self.render()
        with open(self.path("defs/uart.toml"), "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        for rel, text in files.items():
            if os.path.basename(rel).startswith(("Cargo", "lib")) or not re.search(r"uart\.", rel):
                continue
            head = text[:600]
            self.assertIn("BSD-3-Clause", head, rel)
            self.assertIn("defs-gen 4", head, rel)
            self.assertIn(digest, head, rel)
        for rel in ("gen/rust/Cargo.toml", "gen/rust/src/lib.rs"):
            self.assertIn("SPDX-License-Identifier: BSD-3-Clause", files[rel])
        self.assertEqual(json.loads(files["gen/json/uart.json"])["license"], "BSD-3-Clause")

    def test_the_stamp_follows_a_wrapped_banner(self):
        from defslib import gen_c, stamp
        self.render()
        repo = loader.load_repo(self.root)
        text = gen_c.gen_c(repo.units["uart"].model, "defs/" + "long-name-" * 8 + "uart.toml")[0]
        head = stamp.Stamper(repo).apply("gen/c/uart.h", text, "uart").split("\n")
        end = next(i for i, ln in enumerate(head) if "*/" in ln)
        self.assertGreater(end, 0)
        self.assertTrue(head[end].endswith("the source */"), head[:5])
        self.assertTrue(head[end + 1].startswith("/* SPDX-License-Identifier"), head[:5])

    def test_the_hash_follows_the_input(self):
        before = self.render()["gen/c/uart.h"]
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "Control register, changed."')
        after = self.render(license=False)["gen/c/uart.h"]
        grab = lambda t: re.search(r"input sha256 ([0-9a-f]{64})", t).group(1)     # noqa: E731
        self.assertNotEqual(grab(before), grab(after))

    def test_no_licence_line_without_a_setting(self):
        self.assertNotIn("SPDX", self.render(license=False)["gen/c/uart.h"])


if __name__ == "__main__":
    unittest.main()
