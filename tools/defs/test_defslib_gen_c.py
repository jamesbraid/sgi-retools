#!/usr/bin/env python3
"""Tests for the C generator, its self-test program and the forwarding header."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen_c, loader  # noqa: E402
from defslib.genutil import GenError  # noqa: E402
from testkit import RepoTest, which  # noqa: E402

CC = which("cc", "gcc")


class GenCTest(RepoTest):
    def unit(self, name="uart"):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        return repo.units[name].model

    def test_names_follow_one_rule(self):
        text, names = gen_c.gen_c(self.unit(), "defs/uart.toml")
        self.assertEqual(names["UART_CTL_OFFSET"], 0x10)
        self.assertEqual(names["UART_CTL_DIVISOR_SHIFT"], 16)
        self.assertEqual(names["UART_CTL_DIVISOR_MASK"], 0xffff)
        self.assertEqual(names["UART_CTL_DIVISOR_INPLACE"], 0xffff0000)
        self.assertEqual(names["UART_DATA_COUNT"], 16)
        self.assertEqual(names["UART_FRAME_PAYLOAD_SHIFT"], 1)
        self.assertEqual(names["UART_FRAME_WIDTH"], 32)
        self.assertEqual(names["UART_PARITY_EVEN"], 2)
        self.assertEqual(names["UART_FIFO_DEPTH"], 16)
        self.assertIn("#define UART_CTL_OFFSET", text)
        self.assertTrue(text.startswith("/* generated from defs/uart.toml by defs-gen"))

    def test_bare_offset_macro_and_const_prefix(self):
        self.edit("defs/uart.toml", 'public_from =', 'c = { offset_macro = "bare", const_prefix = "UARTC" }\npublic_from =')
        _, names = gen_c.gen_c(self.unit(), "defs/uart.toml")
        self.assertIn("UART_CTL", names)
        self.assertNotIn("UART_CTL_OFFSET", names)
        self.assertIn("UARTC_FIFO_DEPTH", names)

    def test_constant_macro_key_names_the_macro_in_full(self):
        self.edit("defs/uart.toml", "[constants]", '[constants]\nELSEWHERE = { value = 7, grade = "unknown", macro = "OTHER_LIMIT" }\n'
                  'FAMILY = { value = 0x100, count = 4, stride = 8, grade = "unknown", macro = "OTHER_FAMILY" }')
        text, names = gen_c.gen_c(self.unit(), "defs/uart.toml")
        self.assertEqual(names["OTHER_LIMIT"], 7)
        self.assertEqual(names["OTHER_FAMILY_COUNT"], 4)
        self.assertNotIn("UART_ELSEWHERE", names)
        self.assertIn("#define OTHER_FAMILY(i)", text)

    def test_block_names_registers_and_prefix_names_words(self):
        self.edit("defs/uart.toml", 'prefix = "UART"', 'prefix = "UART"\nblock = "SERIAL"')
        _, names = gen_c.gen_c(self.unit(), "defs/uart.toml")
        self.assertIn("SERIAL_CTL_OFFSET", names)
        self.assertIn("UART_FRAME_PAYLOAD_MASK", names)

    def test_inline_enum_values_use_the_field_macro(self):
        self.edit("defs/uart.toml", 'parity = { bits = [3, 1], grade = "inferred", enum = "parity" }',
                  'parity = { bits = [3, 1], grade = "inferred", enums = { none = { value = 0, grade = "established" } } }')
        _, names = gen_c.gen_c(self.unit(), "defs/uart.toml")
        self.assertEqual(names["UART_CTL_PARITY_NONE"], 0)

    def test_colliding_macro_is_refused(self):
        self.edit("defs/uart.toml", "[constants]", '[constants]\nCTL_OFFSET = { value = 1, grade = "unknown" }')
        self.edit("defs/uart.toml", 'public_from =', 'c = { const_prefix = "UART" }\npublic_from =')
        with self.assertRaises(GenError):
            gen_c.gen_c(self.unit(), "defs/uart.toml")

    def test_public_profile_leaves_out_private_sources(self):
        from defslib.model import publish_profile
        m = self.unit()
        text, _ = gen_c.gen_c(publish_profile(m), "defs/uart.toml")
        self.assertIn("fixture notes", text)          # public_from prefix keeps it
        self.edit("defs/uart.toml", 'from = "fixture notes (docs/uart.md)"', 'from = "driver readings"')
        text, _ = gen_c.gen_c(publish_profile(self.unit()), "defs/uart.toml")
        self.assertNotIn("driver readings", text)
        text, _ = gen_c.gen_c(self.unit(), "defs/uart.toml")
        self.assertIn("driver readings", text)

    def test_helpers_are_included_last(self):
        text, _ = gen_c.gen_c(self.unit(), "defs/uart.toml", helpers_include=gen_c.helpers_rel("uart"))
        self.assertIn('#include "../../defs/uart_helpers.h"', text)
        self.assertLess(text.index("UART_FIFO_DEPTH"), text.index("uart_helpers.h"))

    def test_forwarding_header_defines_aliases(self):
        self.edit("defs/uart.toml", 'public_from =', 'c = { legacy_header = "UART_DECODE.h", legacy_guard = "UART_DECODE_H", aliases = { UART_CTL_DIV_SHIFT = "UART_CTL_DIVISOR_SHIFT" } }\npublic_from =')
        m = self.unit()
        text = gen_c.gen_forwarding(m, "defs/uart.toml", "gen/c/uart.h")
        self.assertIn("#ifndef UART_DECODE_H", text)
        self.assertIn('#include "gen/c/uart.h"', text)
        self.assertIn("#define UART_CTL_DIV_SHIFT", text)
        self.assertEqual(gen_c.rel_include("include/old.h", "gen/c/uart.h"), "../gen/c/uart.h")

    @unittest.skipUnless(CC, "no C compiler")
    def test_header_compiles_and_self_test_passes(self):
        m = self.unit()
        text, _ = gen_c.gen_c(m, "defs/uart.toml")
        self.write("uart.h", text)
        self.write("t.c", gen_c.gen_c_test(m, "uart.h"))
        exe = self.path("t")
        r = subprocess.run([CC, "-std=c99", "-Wall", "-Wextra", "-Werror", "-o", exe, self.path("t.c")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([exe], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("7 C field checks, 0 failed", r.stdout)

    @unittest.skipUnless(CC, "no C compiler")
    def test_self_test_fails_when_a_mask_is_wrong(self):
        m = self.unit()
        text, _ = gen_c.gen_c(m, "defs/uart.toml")
        self.write("uart.h", text.replace("0xffu", "0xfu"))
        self.write("t.c", gen_c.gen_c_test(m, "uart.h"))
        exe = self.path("t")
        subprocess.run([CC, "-w", "-o", exe, self.path("t.c")], check=True)
        r = subprocess.run([exe], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
