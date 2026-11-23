#!/usr/bin/env python3
"""Tests for the QEMU header and for defs-names dups."""
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import build, gen, gen_qemu, loader  # noqa: E402
from testkit import HERE, RepoTest, which  # noqa: E402

NAMES = os.path.join(HERE, "defs-names")
CC = which("cc", "gcc")
SETTINGS = '\n[gen.qemu]\nboard = "TEST"\n\n[gen.qemu.units.uart]\nname = "UART0"\n'


class QemuTest(RepoTest):
    def enable(self):
        self.edit("defs/check.toml", '[project]\nname = "mini"\n', '[project]\nname = "mini"\nlicense = "BSD-3-Clause"\n')
        self.write("defs/check.toml", self.read("defs/check.toml") + SETTINGS)

    def render(self):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        files, errors = gen.render(repo)
        self.assertEqual(errors, [])
        return files

    def test_nothing_is_written_unless_the_settings_ask(self):
        self.assertFalse([f for f in self.render() if "qemu" in f])

    def test_comments_wrap_at_80_columns(self):
        self.enable()
        self.edit("defs/check.toml", 'name = "UART0"', 'name = "UART0_WITH_A_LONG_UNIT_NAME_FOR_WRAPPING"')
        self.edit("defs/uart.toml", 'title = "made-up UART (fixture for the defs tools)"', 'title = "%s"' % ("a long title " * 12))
        text = self.render()["gen/qemu/uart.h"]
        self.assertEqual([ln for ln in text.splitlines() if len(ln) > 80 and not ln.startswith("/* input sha256")], [])
        self.assertRegex(text, r"/\* established \*/\nFIELD\(TEST_UART0_WITH_A_LONG_UNIT_NAME_FOR_WRAPPING_CTL, DIVISOR, 16, 16\)\n")

    def test_header_shape(self):
        self.enable()
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn('#include "hw/core/registerfields.h"', text)
        self.assertIn("REG32(TEST_UART0_CTL, 0x10) /* established */", text)
        self.assertIn("FIELD(TEST_UART0_CTL, DIVISOR, 16, 16) /* established */", text)
        self.assertIn("REG8(TEST_UART0_DATA, 0x120) /* inferred */\n#define TEST_UART0_DATA_COUNT 16\n#define TEST_UART0_DATA_STRIDE 0x1", text)
        self.assertIn("#define TEST_UART0_FRAME_WIDTH 32 /* established; word */\nFIELD(TEST_UART0_FRAME, PAYLOAD, 1, 8)", text)
        self.assertIn("#define TEST_UART0_FIFO_DEPTH 0x10u /* ", text)
        self.assertRegex(text, r"#ifndef HW_SGI_GPU_TEST_UART0_REGS_H\n#define HW_SGI_GPU_TEST_UART0_REGS_H\n")
        self.assertNotIn("Control register", text)       # no prose

    def test_a_register_indexed_space_is_written_in_bytes(self):
        self.enable()
        self.edit("defs/uart.toml", "[registers.status]\n", '[spaces.idx]\nunit = "reg"\n\n[registers.status]\nspace = "idx"\n')
        self.edit("defs/uart.toml", "offset = 0x14\n", "offset = 0x5\n")
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn("REG32(TEST_UART0_STATUS, 0x14)", text)

    def test_a_name_defined_twice_is_refused(self):
        self.enable()
        reg = '[registers.%s]\noffset = %s\naccess = "r"\nwidth = 32\ngrade = "inferred"\n\n[registers.%s.fields]\n%s = { bits = [0, 0], grade = "inferred" }\n\n'
        self.edit("defs/uart.toml", "[registers.status]\n", reg % ("a", "0x30", "a", "b_c") + reg % ("a_b", "0x34", "a_b", "c") + "[registers.status]\n")
        _files, errors = gen.render(loader.load_repo(self.root))
        self.assertTrue(any("R_TEST_UART0_A_B_C_SHIFT is defined twice" in e for e in errors), errors)

    def test_the_header_compiles_against_the_shim(self):
        if not CC:
            self.skipTest("no C compiler")
        self.enable()
        repo = loader.load_repo(self.root)
        files, _e = gen.render(repo)
        gen.write(repo, files)
        models = {n: u.model for n, u in repo.units.items()}
        td = os.path.join(self.tmp, "shim")
        os.makedirs(td)
        self.assertEqual(build.verify_qemu(repo, models, td, CC), [])

    def test_the_registerfields_include_passes_the_leak_check(self):
        self.enable()
        repo = loader.load_repo(self.root)
        gen.write(repo, gen.render(repo)[0])
        r = subprocess.run([sys.executable, os.path.join(HERE, "defs-check"), "--root", self.root, "--skip-siblings"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_stale_header_is_reported(self):
        self.enable()
        repo = loader.load_repo(self.root)
        files, _e = gen.render(repo)
        gen.write(repo, files)
        self.assertEqual(gen.stale(repo, files), [])
        self.edit("gen/qemu/uart.h", "0x10)", "0x11)")
        self.assertTrue([p for p in gen.stale(repo, files) if "gen/qemu/uart.h" in p])


class QemuNamesTest(RepoTest):
    def names(self, *args):
        return subprocess.run([sys.executable, NAMES, *args], capture_output=True, text=True)

    def test_the_source_shows_in_the_header_when_it_differs_from_the_unit(self):
        self.edit("defs/check.toml", '[project]\nname = "mini"\n', '[project]\nname = "mini"\n')
        self.write("defs/check.toml", self.read("defs/check.toml") + SETTINGS)
        self.edit("defs/uart.toml", "[registers.status]\n", '[registers.status]\nname_source = "public"\nname_cite = "a datasheet"\n')
        repo = loader.load_repo(self.root)
        text = gen.render(repo)[0]["gen/qemu/uart.h"]
        self.assertIn("name source: imported-unchecked", text.split("#ifndef")[0])
        self.assertIn("name source: public (a datasheet)", text)

    def test_dups_across_repositories(self):
        self.write("defs/check.toml", self.read("defs/check.toml") + SETTINGS)
        repo = loader.load_repo(self.root)
        files, _e = gen.render(repo)
        gen.write(repo, files)
        other = os.path.join(self.tmp, "other")
        os.makedirs(os.path.join(other, "gen", "qemu"))
        with open(os.path.join(other, "gen", "qemu", "x.h"), "w", encoding="utf-8") as f:
            f.write("REG32(TEST_UART0_CTL, 0x0)\n")
        r = self.names("dups", self.root, other)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("A_TEST_UART0_CTL", r.stdout)
        os.remove(os.path.join(other, "gen", "qemu", "x.h"))
        self.assertEqual(self.names("dups", self.root, other).returncode, 0)


class IdentifierTest(unittest.TestCase):
    def test_expansion_matches_registerfields(self):
        ids = gen_qemu.identifiers("REG32(A, 0x4)\nFIELD(A, B, 1, 2)\n#define A_COUNT 3\n")
        self.assertEqual(sorted(ids), sorted(["A_COUNT", "A_A", "R_A", "R_A_B_SHIFT", "R_A_B_LENGTH", "R_A_B_MASK"]))


if __name__ == "__main__":
    unittest.main()
