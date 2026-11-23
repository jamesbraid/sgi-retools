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
CLIPPY = which("clippy-driver")
RUSTFMT = which("rustfmt")


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

    def test_shared_enum_reexport_allows_unused_imports(self):
        text = gen_rust.gen_rust(self.unit(), "defs/uart.toml")
        self.assertIn("    #[allow(unused_imports)]\n        pub use super::super::enums::parity::Value;", text)

    def test_register_named_like_its_field_allows_module_inception(self):
        self.edit("defs/uart.toml", "enable = { bits = [0, 0]", "ctl = { bits = [0, 0]")
        self.edit("defs/uart.toml", "expect = { enable = 1, parity = 1", "expect = { ctl = 1, parity = 1")
        self.edit("defs/uart.toml", "expect = { enable = 1, parity = 7", "expect = { ctl = 1, parity = 7")
        text = gen_rust.gen_rust(self.unit(), "defs/uart.toml")
        self.assertIn("#[allow(clippy::module_inception)]\npub mod ctl {", text)
        self.assertEqual(text.count("module_inception"), 1)

    def test_files_are_marked_generated_and_unformatted(self):
        for text in (gen_rust.gen_rust(self.unit(), "defs/uart.toml"), gen_rust.gen_lib(["uart"], "defs/")):
            self.assertTrue(text.startswith("// @generated from defs/"), text[:60])
            self.assertIn("\n#![cfg_attr(rustfmt, rustfmt_skip)]\n", text)

    @unittest.skipUnless(RUSTFMT, "no rustfmt on this host; run in the rust container")
    def test_rustfmt_leaves_the_crate_alone(self):
        self.build()
        r = subprocess.run([RUSTFMT, "--check", "--edition", "2021", self.path("crate/src/lib.rs")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_doc_markdown_is_allowed_for_register_docs(self):
        self.assertIn("\n#![allow(clippy::doc_markdown)]\n", gen_rust.gen_rust(self.unit(), "defs/uart.toml"))

    @unittest.skipUnless(CLIPPY, "no clippy-driver on this host; run in the rust container")
    def test_clippy_doc_markdown_accepts_prose_docs_that_name_registers(self):
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "Set timer_run and clear TIMER_MASK in the CtlReg; see ctl_status."')
        self.build(CLIPPY, flags=["-W", "clippy::doc_markdown"])

    def test_labels_that_reduce_to_one_variant_get_a_suffix(self):
        v = gen_rust.variants({"k9_6": {"value": 3}, "k96": {"value": 7}, "k8": {"value": 6}})
        self.assertEqual(v, {"k9_6": "K96", "k96": "K96_7", "k8": "K8"})

    def test_crate_files(self):
        self.assertEqual(gen_rust.crate_name(), "hwdefs")
        self.assertEqual(gen_rust.crate_name("My_Repo"), "my_repo")
        self.assertIn('name = "hwdefs"', gen_rust.gen_cargo(None, "defs/"))
        self.assertIn('name = "regs"', gen_rust.gen_cargo("regs", "defs/"))
        lib = gen_rust.gen_lib(["b", "a"], "defs/")
        self.assertIn("pub mod a;\npub mod b;\n", lib)
        self.assertIn("\n#![no_std]\n", lib)

    def build(self, *tools, flags=()):
        """Write the crate and run each tool (rustc or clippy-driver) over it with -D warnings."""
        os.makedirs(self.path("crate/src"))
        self.write("crate/src/uart.rs", gen_rust.gen_rust(self.unit(), "defs/uart.toml"))
        self.write("crate/src/lib.rs", gen_rust.gen_lib(["uart"], "defs/").replace("pub mod", "mod"))   # private, as a consumer may include it
        exe = self.path("crate/t")
        for tool in tools:
            r = subprocess.run([tool, "--edition", "2021", "--test", *flags, "-D", "warnings", "-o", exe, self.path("crate/src/lib.rs")],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        return exe

    @unittest.skipUnless(RUSTC, "no rustc on this host; run in the rust container")
    def test_crate_compiles_and_its_tests_pass(self):
        r = subprocess.run([self.build(RUSTC)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("3 passed", r.stdout)

    @unittest.skipUnless(CLIPPY, "no clippy-driver on this host; run in the rust container")
    def test_crate_is_clippy_clean_with_a_register_named_like_its_field(self):
        self.edit("defs/uart.toml", "enable = { bits = [0, 0]", "ctl = { bits = [0, 0]")
        self.edit("defs/uart.toml", "expect = { enable = 1, parity = 1", "expect = { ctl = 1, parity = 1")
        self.edit("defs/uart.toml", "expect = { enable = 1, parity = 7", "expect = { ctl = 1, parity = 7")
        self.build(CLIPPY)


if __name__ == "__main__":
    unittest.main()
