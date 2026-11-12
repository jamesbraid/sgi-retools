#!/usr/bin/env python3
"""Tests for the structural model checks, one mutation of the fixture each."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import loader, modelcheck  # noqa: E402
from testkit import RepoTest  # noqa: E402


class ModelCheckTest(RepoTest):
    def problems(self, unit="uart"):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        units = [u.model for u in repo.units.values()]
        probs = modelcheck.check_unit(repo.units[unit].model, repo.settings)
        probs += modelcheck.check_overlap(units)
        return probs

    def assert_problem(self, needle, unit="uart"):
        probs = self.problems(unit)
        self.assertTrue([p for p in probs if needle in p], "no problem mentioning %r in %r" % (needle, probs))

    def test_fixture_is_clean(self):
        self.assertEqual(self.problems(), [])

    def test_field_overlap(self):
        self.edit("defs/uart.toml", "enable = { bits = [0, 0]", "enable = { bits = [1, 0]")
        self.assert_problem("overlaps field")

    def test_field_wider_than_register(self):
        self.edit("defs/uart.toml", "rx_ready = { bits = [0, 0]", "rx_ready = { bits = [32, 0]")
        self.assert_problem("do not fit 32-bit register")

    def test_enum_value_wider_than_field(self):
        self.edit("defs/uart.toml", 'even = { value = 2,', 'even = { value = 9,')
        self.assert_problem("does not fit 3 bits")

    def test_duplicate_enum_value(self):
        self.edit("defs/uart.toml", 'odd = { value = 1,', 'odd = { value = 0,')
        self.assert_problem("duplicate values")

    def test_unknown_shared_enum(self):
        self.edit("defs/uart.toml", 'enum = "parity"', 'enum = "nope"')
        self.assert_problem("unknown shared enum")

    def test_vector_disagrees_with_layout(self):
        self.edit("defs/uart.toml", "expect = { enable = 1, parity = 1, divisor = 4 }",
                  "expect = { enable = 1, parity = 1, divisor = 5 }")
        self.assert_problem("field divisor decodes to 4")

    def test_vector_names_unknown_field(self):
        self.edit("defs/uart.toml", "expect = { start = 0, payload = 8 }", "expect = { start = 0, nope = 8 }")
        self.assert_problem("unknown field 'nope'")

    def test_vector_wider_than_word(self):
        self.edit("defs/uart.toml", "value = 0x6b", "value = 0x1ffffffff")
        self.assert_problem("wider than 32 bits")

    def test_register_overlap_within_unit(self):
        self.edit("defs/uart.toml", "offset = 0x14", "offset = 0x12")
        self.assert_problem("overlaps")

    def test_register_array_overlaps_by_stride(self):
        self.edit("defs/uart.toml", "offset = 0x120\naccess = \"rw\"\nwidth = 8\ncount = 16",
                  "offset = 0x0e\naccess = \"rw\"\nwidth = 8\ncount = 8\nstride = 4")
        self.assert_problem("overlaps")

    def test_strided_array_that_interleaves_is_fine(self):
        self.edit("defs/uart.toml", "offset = 0x120\naccess = \"rw\"\nwidth = 8\ncount = 16",
                  "offset = 0x20\naccess = \"rw\"\nwidth = 8\ncount = 8\nstride = 4")
        self.assertEqual(self.problems(), [])

    def test_named_space_is_shared_across_units(self):
        spaced = '\n[spaces.mmio]\n'
        self.edit("defs/uart.toml", 'access = "rw"\nwidth = 32\nreset = 0', 'access = "rw"\nwidth = 32\nspace = "mmio"\nreset = 0')
        self.edit("defs/uart.toml", '[enums.parity]', spaced + '\n[enums.parity]')
        self.write("defs/other.toml", 'unit = "other"\nprefix = "OTHER"\nfrom = "x"\n[spaces.mmio]\n'
                   '[registers.clash]\noffset = 0x12\naccess = "r"\nwidth = 32\nspace = "mmio"\ngrade = "unknown"\n')
        self.assert_problem("overlaps", "other")

    def test_default_space_is_per_unit(self):
        self.write("defs/other.toml", 'unit = "other"\nprefix = "OTHER"\nfrom = "x"\n'
                   '[registers.same]\noffset = 0x10\naccess = "r"\nwidth = 32\ngrade = "unknown"\n')
        self.assertEqual(self.problems("other"), [])

    def test_undeclared_space(self):
        self.edit("defs/uart.toml", 'access = "r"\nwidth = 32\ngrade', 'access = "r"\nwidth = 32\nspace = "nope"\ngrade')
        self.assert_problem("not declared in spaces")

    def test_register_index_space_counts_in_registers(self):
        self.write("defs/idx.toml", 'unit = "idx"\nprefix = "IDX"\nfrom = "x"\n[spaces.hq]\nunit = "reg"\n'
                   '[registers.a]\noffset = 0\naccess = "w"\nwidth = 32\ncount = 4\nspace = "hq"\ngrade = "unknown"\n'
                   '[registers.b]\noffset = 3\naccess = "w"\nwidth = 32\nspace = "hq"\ngrade = "unknown"\n')
        self.assert_problem("overlaps", "idx")

    def test_offset_beyond_address_bits(self):
        self.edit("defs/uart.toml", "offset = 0x120", "offset = 0x20000")
        self.assert_problem("outside the register space")

    def test_address_bits_setting_widens_the_space(self):
        self.edit("defs/uart.toml", "offset = 0x120", "offset = 0x20000")
        self.edit("defs/check.toml", "[project]", "[checks]\naddress_bits = 32\nmax_reg_offset = 0xffffffff\n\n[project]")
        self.assertEqual(self.problems(), [])

    def test_missing_from_is_found(self):
        self.edit("defs/uart.toml", 'from = "fixture notes (docs/uart.md)"\n', "")
        self.assert_problem("no `from`")

    def test_reset_wider_than_register(self):
        self.edit("defs/uart.toml", "reset = 0\n", "reset = 0x1ffffffff\n")
        self.assert_problem("reset does not fit")

    def test_stride_smaller_than_register(self):
        self.edit("defs/uart.toml", "access = \"r\"\nwidth = 32\ngrade", "access = \"r\"\nwidth = 32\ncount = 2\nstride = 2\ngrade")
        self.assert_problem("stride smaller")

    def test_register_and_word_share_a_name(self):
        self.edit("defs/uart.toml", "[words.FRAME]", '[words.CTL]\nwidth = 32\ngrade = "unknown"\n\n[words.FRAME]')
        self.assert_problem("share a name")


if __name__ == "__main__":
    unittest.main()
