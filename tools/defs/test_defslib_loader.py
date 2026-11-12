#!/usr/bin/env python3
"""Tests for the defs loader: file layout, strict schema, overlays, references."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import loader  # noqa: E402
from testkit import RepoTest  # noqa: E402


class LoaderTest(RepoTest):
    def load(self):
        return loader.load_repo(self.root)

    def errors_with(self, needle):
        repo = self.load()
        hits = [e for e in repo.errors if needle in e]
        self.assertTrue(hits, "no error mentioning %r in %r" % (needle, repo.errors))
        return repo

    def test_fixture_loads_clean(self):
        repo = self.load()
        self.assertEqual(repo.errors, [])
        self.assertEqual(sorted(repo.units), ["uart", "uart_rev2"])
        self.assertEqual(repo.project, "mini")

    def test_normalisation_fills_defaults_and_orders(self):
        m = self.load().units["uart"].model
        data = m["registers"]["data"]
        self.assertEqual((data["count"], data["stride"], data["reset"]), (16, 1, "unknown"))
        self.assertEqual(list(m["registers"]), ["ctl", "status", "data"])
        self.assertEqual(list(m["registers"]["ctl"]["fields"]), ["divisor", "parity", "enable"])
        self.assertEqual(m["registers"]["ctl"]["tests"][1]["kind"], "vector")

    def test_overlay_merges_patch_and_add(self):
        repo = self.load()
        o = repo.units["uart_rev2"].model
        self.assertEqual(o["prefix"], "UART_REV2")
        self.assertEqual(o["title"], "made-up UART, revision 2")
        self.assertEqual(o["registers"]["ctl"]["fields"]["divisor"]["grade"], "inferred")
        self.assertIn("irq_mask", o["registers"])
        base = repo.units["uart"].model
        self.assertEqual(base["registers"]["ctl"]["fields"]["divisor"]["grade"], "established")
        self.assertNotIn("irq_mask", base["registers"])
        self.assertEqual(repo.units["uart_rev2"].layers, ["defs/uart.toml", "defs/uart.rev2.toml"])

    def test_overlay_does_not_inherit_the_base_legacy_header(self):
        self.edit("defs/uart.toml", 'public_from =', 'c = { offset_macro = "bare", legacy_header = "UART_DECODE.h", aliases = { A = "B" } }\npublic_from =')
        o = self.load().units["uart_rev2"].model
        self.assertEqual(o["c"]["offset_macro"], "bare")
        self.assertNotIn("legacy_header", o["c"])
        self.assertEqual(o["c"]["aliases"], {})

    def test_overlay_can_name_its_unit(self):
        self.edit("defs/uart.rev2.toml", "[override]\n", '[override]\nunit = "uart2"\nprefix = "UART2"\n')
        self.assertIn("uart2", self.load().units)

    def test_overlay_add_of_existing_item_is_an_error(self):
        self.write("defs/uart.rev2.toml", '[add.registers.ctl]\noffset = 0\naccess = "r"\nwidth = 32\ngrade = "unknown"\n')
        self.errors_with("already exists")

    def test_overlay_patch_of_missing_item_is_an_error(self):
        self.write("defs/uart.rev2.toml", '[patch."registers.nope"]\ngrade = "unknown"\n')
        self.errors_with("no such item")

    def test_overlay_remove(self):
        self.write("defs/uart.rev2.toml", 'remove = ["registers.status"]\n')
        self.assertNotIn("status", self.load().units["uart_rev2"].model["registers"])

    def test_overlay_of_missing_unit(self):
        self.write("defs/ghost.r1.toml", '[override]\ntitle = "x"\n')
        self.errors_with("has no defs/ghost.toml")

    def test_item_without_grade_is_a_schema_error(self):
        self.edit("defs/uart.toml", 'enable = { bits = [0, 0], grade = "established" }', "enable = { bits = [0, 0] }")
        self.errors_with("missing required key 'grade'")

    def test_bad_grade_value(self):
        self.edit("defs/uart.toml", 'parity = { bits = [3, 1], grade = "inferred"', 'parity = { bits = [3, 1], grade = "guessed"')
        self.errors_with("must be one of established, inferred, unknown")

    def test_misspelt_key(self):
        self.edit("defs/uart.toml", "access = \"rw\"\nwidth = 32\nreset", "acces = \"rw\"\nwidth = 32\nreset")
        self.errors_with("unknown key 'acces'")

    def test_duplicate_key_is_a_parse_error(self):
        self.edit("defs/uart.toml", 'prefix = "UART"', 'prefix = "UART"\nprefix = "UART"')
        self.errors_with("TOML error")

    def test_constant_macro_name_must_be_an_identifier(self):
        self.edit("defs/uart.toml", "FIFO_DEPTH = { value = 16,", 'FIFO_DEPTH = { macro = "not valid", value = 16,')
        self.errors_with("does not match")

    def test_wrong_type(self):
        self.edit("defs/uart.toml", "width = 8\n", 'width = "8"\n')
        self.errors_with("must be an integer")

    def test_bad_width(self):
        self.edit("defs/uart.toml", "width = 8\n", "width = 12\n")
        self.errors_with("must be one of 8, 16, 32, 64")

    def test_unit_name_must_match_file(self):
        self.edit("defs/uart.toml", 'unit = "uart"', 'unit = "serial"')
        self.errors_with("does not match the file name")

    def test_bad_file_name(self):
        self.write("defs/Bad-Name.toml", 'unit = "x"\nprefix = "X"\n')
        self.errors_with("file name must be")

    def test_check_toml_unknown_key(self):
        self.edit("defs/check.toml", "[project]\n", "[project]\nplugn = \"x\"\n")
        self.errors_with("unknown key 'plugn'")

    def test_check_toml_names_missing_unit(self):
        self.edit("defs/check.toml", "[units.uart]", "[units.nope]")
        self.errors_with("[units.nope] names no unit")

    def test_register_reference_in_vector(self):
        self.edit("defs/uart.toml", "expect = { start = 1, payload = 0x35 }",
                  'expect = { start = 1, payload = "@status" }')
        # payload decodes 0x35, status sits at 0x14: reference resolves to the offset
        m = self.load().units["uart"].model
        self.assertEqual(m["words"]["FRAME"]["tests"][-1]["expect"]["payload"], 0x14)

    def test_unknown_register_reference(self):
        self.edit("defs/uart.toml", "payload = 0x35 }", 'payload = "@nope" }')
        self.errors_with("unknown register @nope")


if __name__ == "__main__":
    unittest.main()
