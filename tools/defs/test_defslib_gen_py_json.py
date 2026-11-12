#!/usr/bin/env python3
"""Tests for the Python decode helpers and the flat JSON generators."""
import importlib.util
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen_json, gen_py, loader  # noqa: E402
from defslib.model import publish_profile  # noqa: E402
from testkit import RepoTest  # noqa: E402


class GenPyJsonTest(RepoTest):
    def unit(self, name="uart"):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        return repo.units[name].model

    def load_module(self):
        self.write("uart_defs.py", gen_py.gen_py(self.unit(), "defs/uart.toml"))
        spec = importlib.util.spec_from_file_location("uart_defs", self.path("uart_defs.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_python_module_imports_and_selftests(self):
        mod = self.load_module()
        self.assertEqual(mod.UNIT, "uart")
        self.assertEqual(mod.selftest(), 3)

    def test_decode_encode_describe(self):
        mod = self.load_module()
        self.assertEqual(mod.decode("ctl", 0x00040003), {"divisor": 4, "parity": 1, "enable": 1})
        self.assertEqual(mod.encode("ctl", enable=1, parity=1, divisor=4), 0x00040003)
        self.assertEqual(mod.describe("ctl", 0x00040003)["parity"], "odd")
        self.assertEqual(mod.describe("ctl", 0xff)["parity"], 7)
        with self.assertRaises(ValueError):
            mod.encode("ctl", parity=8)
        self.assertEqual(mod.REGISTERS["data"]["count"], 16)
        self.assertEqual(mod.CONSTANTS["FIFO_DEPTH"]["value"], 16)

    def test_selftest_catches_a_wrong_layout(self):
        mod = self.load_module()
        mod.FIELDS["FRAME"]["payload"] = (8, 2)
        with self.assertRaises(AssertionError):
            mod.selftest()

    def test_json_rows(self):
        d = json.loads(gen_json.gen_json(self.unit(), "defs/uart.toml"))
        self.assertEqual(d["schema"], "defs-flat/1")
        rows = {(r["kind"], r["name"]): r for r in d["rows"]}
        self.assertEqual(rows[("register", "ctl")]["offset"], 0x10)
        self.assertEqual(rows[("field", "ctl.divisor")]["hi"], 31)
        self.assertEqual(rows[("enum_value", "ctl.parity.odd")]["value"], 1)
        self.assertEqual(rows[("constant", "FIFO_DEPTH")]["grade"], "established")
        self.assertEqual(rows[("field", "ctl.enable")]["from"], "fixture notes (docs/uart.md)")
        self.assertEqual(rows[("register", "status")]["from"], "fixture notes (status page)")

    def test_json_public_profile_drops_private_sources(self):
        self.edit("defs/uart.toml", 'from = "fixture notes (status page)"', 'from = "driver readings"')
        public = json.loads(gen_json.gen_json(publish_profile(self.unit()), "defs/uart.toml", "public"))
        rows = {(r["kind"], r["name"]): r for r in public["rows"]}
        self.assertEqual(public["profile"], "public")
        self.assertEqual(rows[("register", "status")]["from"], "fixture notes (docs/uart.md)")
        internal = json.loads(gen_json.gen_json(self.unit(), "defs/uart.toml", "internal"))
        self.assertEqual({(r["kind"], r["name"]): r for r in internal["rows"]}[("register", "status")]["from"], "driver readings")


if __name__ == "__main__":
    unittest.main()
