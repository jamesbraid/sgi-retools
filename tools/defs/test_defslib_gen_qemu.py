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
        self.write("defs/check.toml", self.read("defs/check.toml") + SETTINGS)
        self.edit("defs/uart.toml", 'unit = "uart"\n', 'unit = "uart"\nname_source = "ours"\n')

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

    def test_a_unit_may_override_the_board(self):
        self.enable()
        self.edit("defs/check.toml", 'name = "UART0"', 'name = "UART0"\nboard = "OTHER"')
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn("REG32(OTHER_UART0_CTL, 0x10)", text)
        self.assertNotIn("TEST_UART0", text)

    def test_without_a_board_the_unit_name_is_the_prefix(self):
        self.enable()
        self.edit("defs/check.toml", 'board = "TEST"\n', "")
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn("REG32(UART0_CTL, 0x10)", text)
        self.assertRegex(text, r"#ifndef HW_UART0_REGS_H\n#define HW_UART0_REGS_H\n")
        self.assertNotIn("TEST_", text)

    def test_header_shape(self):
        self.enable()
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn('#include "hw/core/registerfields.h"', text)
        self.assertIn("REG32(TEST_UART0_CTL, 0x10) /* established */", text)
        self.assertIn("FIELD(TEST_UART0_CTL, DIVISOR, 16, 16) /* established */", text)
        self.assertIn("#define TEST_UART0_CTL_RESET 0x0u /* established */\n", text)
        self.assertIn("FIELD(TEST_UART0_CTL, PARITY, 1, 3) /* inferred */\n#define TEST_UART0_CTL_PARITY_NONE 0 /* established */\n"
                      "#define TEST_UART0_CTL_PARITY_ODD 1 /* established */\n"
                      "#define TEST_UART0_CTL_PARITY_EVEN 2 /* inferred */\n", text)
        self.assertIn("REG8(TEST_UART0_DATA, 0x120) /* inferred */\n#define TEST_UART0_DATA_COUNT 16\n#define TEST_UART0_DATA_STRIDE 0x1", text)
        self.assertIn("#define TEST_UART0_FRAME_WIDTH 32 /* established; word */\nFIELD(TEST_UART0_FRAME, PAYLOAD, 1, 8)", text)
        self.assertIn("#define TEST_UART0_FIFO_DEPTH 0x10u /* ", text)
        self.assertRegex(text, r"#ifndef HW_TEST_UART0_REGS_H\n#define HW_TEST_UART0_REGS_H\n")
        self.assertNotIn("Control register", text)       # no prose

    def test_an_unknown_reset_is_left_out(self):
        self.enable()
        text = self.render()["gen/qemu/uart.h"]
        self.assertNotIn("TEST_UART0_STATUS_RESET", text)
        self.assertNotIn("TEST_UART0_DATA_RESET", text)

    def test_a_reset_has_its_own_grade_and_applies_per_element(self):
        self.enable()
        self.edit("defs/uart.toml", "reset = 0\n", 'reset = 0\nreset_grade = "inferred"\n')
        self.edit("defs/uart.toml", "grade = \"inferred\"\n\n[words.FRAME]", 'reset = 0x5a\ngrade = "inferred"\n\n[words.FRAME]')
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn("#define TEST_UART0_CTL_RESET 0x0u /* inferred */\n", text)
        self.assertIn("#define TEST_UART0_DATA_COUNT 16\n#define TEST_UART0_DATA_STRIDE 0x1\n#define TEST_UART0_DATA_RESET 0x5au /* inferred */\n", text)

    def test_masks_are_written_only_where_the_register_has_them(self):
        self.enable()
        self.edit("defs/uart.toml", 'reset = 0\n', "reset = 0\nro = 0xf0\nw1c = 0x100\ncor = 0x2\nrsvd = 0xff000000\n")
        text = self.render()["gen/qemu/uart.h"]
        for line in ("RO 0xf0u", "W1C 0x100u", "COR 0x2u", "RSVD 0xff000000u"):
            self.assertIn("#define TEST_UART0_CTL_%s /* established */\n" % line, text)
        self.assertEqual(len(re.findall(r"_(?:RO|W1C|COR|RSVD) ", text)), 4)

    def test_a_field_with_its_own_enum_values_carries_them(self):
        self.enable()
        self.edit("defs/uart.toml", "rx_ready = { bits = [0, 0], grade = \"established\" }",
                  'rx_ready = { bits = [0, 0], grade = "established", enums = { no = { value = 0, grade = "inferred" } } }')
        self.assertIn("#define TEST_UART0_STATUS_RX_READY_NO 0 /* inferred */\n", self.render()["gen/qemu/uart.h"])

    def test_a_register_indexed_space_is_written_as_an_index(self):
        self.enable()
        self.edit("defs/uart.toml", "[registers.status]\n", '[spaces.idx]\nunit = "reg"\n\n[registers.status]\nspace = "idx"\n')
        self.edit("defs/uart.toml", "offset = 0x14\n", "offset = 0x5\n")
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn("#define TEST_UART0_STATUS_INDEX 5 /* established */\n", text)
        self.assertIn("\n/* A register-indexed space has _INDEX numbers, not byte offsets. */\n", text)
        self.assertNotIn("REG32(TEST_UART0_STATUS", text)
        self.assertIn("FIELD(TEST_UART0_STATUS, RX_READY, 0, 1)", text)

    def test_an_indexed_array_counts_in_indices(self):
        self.enable()
        self.edit("defs/uart.toml", "[registers.status]\n", '[spaces.idx]\nunit = "reg"\n\n[registers.status]\nspace = "idx"\ncount = 4\n')
        text = self.render()["gen/qemu/uart.h"]
        self.assertIn("#define TEST_UART0_STATUS_COUNT 4\n#define TEST_UART0_STATUS_STRIDE 1\n", text)

    def test_unchecked_names_are_refused(self):
        self.enable()
        self.edit("defs/uart.toml", 'name_source = "ours"\n', "")
        _files, errors = gen.render(loader.load_repo(self.root))
        self.assertTrue(any("imported-unchecked" in e and "ctl.divisor" in e and "status" in e for e in errors), errors)

    def test_one_unchecked_register_is_refused_by_name(self):
        self.enable()
        self.edit("defs/uart.toml", "[registers.status]\n", '[registers.status]\nname_source = "imported-unchecked"\n')
        _files, errors = gen.render(loader.load_repo(self.root))
        self.assertTrue(any("status, status.rx_ready" in e for e in errors), errors)

    def test_a_name_defined_twice_is_refused(self):
        self.enable()
        reg = '[registers.%s]\noffset = %s\naccess = "r"\nwidth = 32\ngrade = "inferred"\n\n[registers.%s.fields]\n%s = { bits = [0, 0], grade = "inferred" }\n\n'
        self.edit("defs/uart.toml", "[registers.status]\n", reg % ("a", "0x30", "a", "b_c") + reg % ("a_b", "0x34", "a_b", "c") + "[registers.status]\n")
        _files, errors = gen.render(loader.load_repo(self.root))
        self.assertTrue(any("R_TEST_UART0_A_B_C_SHIFT is defined twice" in e for e in errors), errors)

    def test_a_new_name_defined_twice_is_refused(self):
        self.enable()
        self.edit("defs/uart.toml", "[constants]\n", "[constants]\nCTL_RESET = { value = 1, grade = \"inferred\" }\n")
        _files, errors = gen.render(loader.load_repo(self.root))
        self.assertTrue(any("TEST_UART0_CTL_RESET is defined twice" in e for e in errors), errors)

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
        self.edit("defs/uart.toml", 'unit = "uart"\n', 'unit = "uart"\nname_source = "ours"\n')
        self.edit("defs/uart.toml", "[registers.status]\n", '[registers.status]\nname_source = "public"\nname_cite = "a datasheet"\n')
        repo = loader.load_repo(self.root)
        text = gen.render(repo)[0]["gen/qemu/uart.h"]
        self.assertIn("name source: ours", text.split("#ifndef")[0])
        self.assertIn("name source: public (a datasheet)", text)

    def test_dups_across_repositories(self):
        self.write("defs/check.toml", self.read("defs/check.toml") + SETTINGS)
        self.edit("defs/uart.toml", 'unit = "uart"\n', 'unit = "uart"\nname_source = "ours"\n')
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
