#!/usr/bin/env python3
"""Tests for the Rust crate generator."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen_rust, loader  # noqa: E402
from testkit import RepoTest, which  # noqa: E402

RUSTC = which("rustc")


class GenRustTest(RepoTest):
    def unit(self, name="uart"):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        return repo.units[name].model

    def test_module_shape(self):
        text = gen_rust.gen_rust(self.unit(), "defs/uart.toml")
        self.assertIn("pub mod ctl {", text)
        self.assertIn("pub const OFFSET: u64 = 0x10;", text)
        self.assertIn("pub const COUNT: u32 = 16;", text)
        self.assertIn("pub mod divisor { // bits 31:16, established", text)
        self.assertIn("pub use super::super::enums::parity::Value;", text)
        self.assertIn("pub const FIFO_DEPTH: u32 = 0x10; // established", text)
        self.assertIn("assert_eq!(frame::payload::get(0x6b), 53);", text)

    def test_examples_do_not_become_tests(self):
        text = gen_rust.gen_rust(self.unit(), "defs/uart.toml")
        self.assertNotIn("0xff)", text.split("mod tests")[1])

    def test_sixty_four_bit_word_uses_u64(self):
        self.edit("defs/uart.toml", "[words.FRAME]\nwidth = 32", "[words.FRAME]\nwidth = 64")
        self.edit("defs/uart.toml", "payload = { bits = [8, 1]", "payload = { bits = [40, 1]")
        self.edit("defs/uart.toml", "value = 0x6b\nexpect = { start = 1, payload = 0x35 }", "value = 0x6b\nexpect = { start = 1, payload = 0x35 }")
        text = gen_rust.gen_rust(self.unit(), "defs/uart.toml")
        self.assertIn("pub const MASK: u64 = 0xffffffffff;", text)

    def test_digit_led_constant_and_keyword_names(self):
        self.edit("defs/uart.toml", "[constants]", '[constants]\n3D_MODE = { value = 3, grade = "unknown" }')
        self.edit("defs/uart.toml", 'none = { value = 0,', 'self = { value = 0,')
        text = gen_rust.gen_rust(self.unit(), "defs/uart.toml")
        self.assertIn("pub const N3D_MODE: u32 = 0x3;", text)
        self.assertIn("Self_,", text)

    def test_crate_files(self):
        self.assertEqual(gen_rust.crate_name("My_Repo"), "my_repo-defs")
        self.assertIn('name = "mini-defs"', gen_rust.gen_cargo("mini", "defs/"))
        lib = gen_rust.gen_lib(["b", "a"], "defs/")
        self.assertIn("pub mod a;\npub mod b;\n", lib)

    @unittest.skipUnless(RUSTC, "no rustc on this host; run in the rust container")
    def test_crate_compiles_and_its_tests_pass(self):
        os.makedirs(self.path("crate/src"))
        self.write("crate/src/uart.rs", gen_rust.gen_rust(self.unit(), "defs/uart.toml"))
        self.write("crate/src/lib.rs", gen_rust.gen_lib(["uart"], "defs/"))
        exe = self.path("crate/t")
        r = subprocess.run([RUSTC, "--edition", "2021", "--test", "-D", "warnings", "-o", exe, self.path("crate/src/lib.rs")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([exe], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("3 passed", r.stdout)


if __name__ == "__main__":
    unittest.main()
