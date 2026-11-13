#!/usr/bin/env python3
"""Tests for defs-check: layout, leaks, prose claims, notes, plugins and freshness."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from testkit import HERE, RepoTest  # noqa: E402

CHECK = os.path.join(HERE, "defs-check")
GEN = os.path.join(HERE, "defs-gen")


def run(tool, *args):
    return subprocess.run([sys.executable, tool, *args], capture_output=True, text=True)


class ChecksTest(RepoTest):
    def setUp(self):
        super().setUp()
        self.generate()

    def generate(self):
        r = run(GEN, "--root", self.root)
        self.assertEqual(r.returncode, 0, r.stderr)

    def check(self, *extra):
        return run(CHECK, "--root", self.root, *extra)

    def assert_fails(self, needle, regen=True):
        if regen:
            self.generate()
        r = self.check()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(needle, r.stdout)
        return r

    def test_fixture_is_clean(self):
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ok: 2 unit(s)", r.stdout)

    # -- layout ---------------------------------------------------------
    def test_layout_error_is_reported_with_the_file(self):
        self.edit("defs/uart.toml", "enable = { bits = [0, 0]", "enable = { bits = [1, 0]")
        self.assert_fails("defs/uart.toml: uart.ctl.enable: overlaps field")

    def test_register_overlap_across_units_in_one_space(self):
        self.edit("defs/uart.rev2.toml", "offset = 0x18", "offset = 0x12")
        self.assert_fails("overlaps")

    # -- leaks ----------------------------------------------------------
    def test_leak_in_prose_is_caught_in_every_rendering(self):
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "Reads irix/stand/foo from the board IP27."')
        r = self.assert_fails("banned content")
        for rel in ("gen/c/uart.h", "gen/docs/uart.md", "gen/rust/src/uart.rs", "gen/genxml/uart.xml"):
            self.assertIn(rel, r.stdout)

    def test_private_source_does_not_leak_into_public_output(self):
        self.edit("defs/uart.toml", 'from = "fixture notes (status page)"', 'from = "libfoo.so, mixedCase(0)"')
        self.generate()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_internal_profile_still_checks_the_public_rendering(self):
        self.edit("defs/check.toml", "[project]", '[gen]\nprofile = "internal"\n\n[project]')
        self.edit("defs/uart.toml", 'from = "fixture notes (status page)"', 'from = "libfoo.so"')
        self.generate()
        self.assertEqual(self.check().returncode, 0)
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "see libfoo.so"')
        self.assert_fails("banned content")

    def test_generated_rust_must_not_name_the_project(self):
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "The mini board register."')
        r = self.assert_fails("project name in generated Rust")
        self.assertIn("gen/rust/src/uart.rs", r.stdout)
        self.assertNotIn("gen/c/uart.h", r.stdout)       # C and docs may name the project

    def test_crate_name_is_chosen_not_derived_from_the_project(self):
        self.assertIn('name = "hwdefs"', self.read("gen/rust/Cargo.toml"))

    def test_repo_specific_banned_rule(self):
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "calls mini_probe"')
        self.assert_fails("driver routine prefix")

    def test_register_offset_spelled_out_in_prose(self):
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "Sits at 0x120 in the window."')
        self.assert_fails("0x120 (a register offset) in prose")

    def test_prose_offsets_are_only_checked_for_units_with_registers(self):
        self.write("defs/tbl.toml", 'unit = "tbl"\nprefix = "TBL"\nfrom = "fixture notes"\n'
                   '[constants]\nA = { value = 1, grade = "unknown", doc = "scale 0x1000 by default" }\n')
        self.generate()
        self.assertEqual(self.check().returncode, 0)
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "scale 0x1000 by default"')
        self.assert_fails("0x1000 (a 4-digit value in the register address space) in prose")

    def test_plugin_header_text_includes_the_helpers(self):
        self.write("defs/uart_helpers.h", "static inline int uart_twice(int n) { return 2 * n; }\n")
        self.with_plugin('''
def check_header(ctx, hdr):
    if hdr.unit.name == "uart" and "uart_twice" not in hdr.text:
        ctx.rep.fail(hdr.file, "helpers missing from the header text")
''')
        self.generate()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_plugin_header_text_carries_the_old_annotation_grammar(self):
        self.with_plugin('''
import re
def check_header(ctx, hdr):
    if hdr.unit.name != "uart":
        return
    t = hdr.text
    for want in ("/* REG: UART.ctl 0x010 rw32 reset=0x0 established */",
                 "/* REG: UART.data 0x120 rw8 count=16 reset=unknown inferred */",
                 "/* FIELD: UART.ctl.divisor 31:16 established */",
                 "/* FIELD: FRAME.payload 8:1 established */",
                 "/* ENUM: UART.ctl.parity 1 odd established */",
                 "/* WORD: FRAME 32 */",
                 " * TESTVEC: 0x40003 as UART.ctl => enable=1, parity=1, divisor=4",
                 " * EXAMPLE (unverified): 0xff as UART.ctl => enable=1, parity=7, divisor=0"):
        if want not in t:
            ctx.rep.fail(hdr.file, "missing: " + want)
    # the old checker's own regular expressions read it
    vec = [l for l in t.splitlines() if "TESTVEC:" in l and "UART.ctl" in l][0]
    if not ctx.lib.TV2_RE.search(vec):
        ctx.rep.fail(hdr.file, "TV2_RE")
    if not [l for l in t.splitlines() if ctx.lib.REG_RE.match(l)]:
        ctx.rep.fail(hdr.file, "REG_RE matches no line")
''')
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_addresses_scans_the_helpers_too(self):
        self.edit("defs/check.toml", "[units.uart]", "[units.uart]\nno_addresses = true")
        self.write("defs/uart_helpers.h", "#define UART_WHERE 0x12345678\n")
        self.assert_fails("defs/uart_helpers.h:1: hex literal 0x12345678")

    def test_prose_offsets_setting_turns_the_rule_off(self):
        self.edit("defs/uart.toml", 'doc = "Control register."', 'doc = "Sits at 0x120 in the window."')
        self.edit("defs/check.toml", "[units.uart]", "[units.uart_rev2]\nprose_offsets = false\n\n[units.uart]\nprose_offsets = false")
        self.generate()
        self.assertEqual(self.check().returncode, 0)

    def test_hand_written_helper_is_scanned(self):
        self.write("defs/uart_helpers.h", "/* see libfoo.so */\n#define H 1\n")
        self.assert_fails("defs/uart_helpers.h:1")

    # -- prose ------------------------------------------------------------
    def test_claims_pass_and_drift_in_the_header_is_caught(self):
        self.assertEqual(self.check().returncode, 0)
        self.edit("defs/uart.toml", "divisor = { bits = [31, 16]", "divisor = { bits = [31, 17]")
        self.edit("defs/uart.toml", "value = 0x00040003", "value = 0x00040003\n")
        self.assert_fails("UART.ctl.divisor is 31:17 in the header but 31:16")

    def test_claims_drift_in_the_prose_is_caught(self):
        self.edit("docs/uart.md", "bits 31:16", "bits 31:15")
        self.assert_fails("UART.ctl.divisor is 31:16 in the header but 31:15")

    def test_claim_whose_passage_vanished(self):
        self.edit("docs/uart.md", "payload in bits 8:1", "payload somewhere")
        self.assert_fails('prose for "frame payload" not found')

    def test_claim_naming_unknown_group_is_a_setup_error(self):
        self.edit("defs/check.toml", 'group = "uart"\nlabel = "frame payload"', 'group = "nope"\nlabel = "frame payload"')
        r = self.check()
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown group", r.stderr)

    def test_group_setting_renames_a_group(self):
        self.edit("defs/check.toml", '[units.uart]', '[units.uart]\ngroup = "serial"')
        self.write("defs/check.toml", self.read("defs/check.toml").replace('group = "uart"', 'group = "serial"'))
        self.assertEqual(self.check().returncode, 0)

    def test_claim_can_bind_a_macro(self):
        self.edit("docs/uart.md", "The control register", "The FIFO holds 16 entries. The control register")
        self.write("defs/check.toml", self.read("defs/check.toml") + '\n[[claims]]\ngroup = "uart"\nlabel = "fifo"\ndoc = "docs/uart.md"\nregex = \'FIFO holds (\\d+)\'\nbinds = [["DEF", "UART_FIFO_DEPTH", 1]]\n')
        self.assertEqual(self.check().returncode, 0)
        self.edit("docs/uart.md", "holds 16", "holds 8")
        self.assert_fails("UART_FIFO_DEPTH is 16 but docs/uart.md says 8")

    def test_missing_prose_document_is_a_setup_error(self):
        os.remove(self.path("docs/uart.md"))
        r = self.check()
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot read docs/uart.md", r.stderr)

    # -- notes corpus -----------------------------------------------------
    def test_vector_must_be_recorded_in_the_notes(self):
        self.edit("docs/uart.md", "0x00040003 (control), ", "")
        self.assert_fails("vector value 0x40003 is not recorded in the notes")

    def test_examples_need_no_notes(self):
        self.assertEqual(self.check().returncode, 0)  # the 0xff example is not in the notes

    # -- descriptors with no address --------------------------------------
    def test_no_addresses_refuses_a_wide_literal(self):
        self.edit("defs/check.toml", "[units.uart]", "[units.uart]\nno_addresses = true")
        self.edit("defs/uart.toml", "FIFO_DEPTH = { value = 16,", "FIFO_DEPTH = { value = 0x123456,")
        self.assert_fails("could be an address")

    def test_no_addresses_allows_inplace_macros_but_not_other_address_macros(self):
        self.edit("defs/check.toml", "[units.uart]", "[units.uart]\nno_addresses = true")
        self.edit("defs/uart.toml", "start = { bits = [0, 0]", 'addr_hi = { bits = [20, 12], grade = "unknown" }\nstart = { bits = [0, 0]')
        self.generate()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)          # ADDR_HI_INPLACE is a mask expression
        self.edit("defs/uart.toml", "[constants]", '[constants]\nADDR_LIMIT = { value = 5, grade = "unknown" }')
        self.assert_fails("address macro UART_ADDR_LIMIT is not a SHIFT, MASK, BITS or INPLACE")

    def test_no_addresses_allows_masks_and_names_the_address_field(self):
        self.edit("defs/check.toml", "[units.uart]", "[units.uart]\nno_addresses = true")
        self.assertEqual(self.check().returncode, 0)
        self.edit("defs/uart.toml", "payload = { bits = [8, 1]", "addr_lo = { bits = [8, 1]")
        self.edit("defs/uart.toml", "expect = { start = 1, payload = 0x35 }", "expect = { start = 1, addr_lo = 0x35 }")
        self.edit("defs/uart.toml", "expect = { start = 0, payload = 8 }", "expect = { start = 0 }")
        self.assert_fails("address field")

    # -- plugins ----------------------------------------------------------
    PLUGIN = '''
CLAIMS = [{"group": "uart", "label": "plugin claim", "doc": "docs/uart.md",
           "regex": r"payload in bits (\\d+):(\\d+)", "binds": [["F", "FRAME.payload", 1, 2]]}]
SEEN = []

def check_header(ctx, hdr):
    if hdr.unit.name != "uart":
        return
    SEEN.append(hdr.file)
    f = hdr.fields.get("FRAME.payload")
    if f and f[1] != 1:
        ctx.rep.fail(hdr.file, "payload moved")
    if "UART.ctl" in hdr.regs and hdr.regs["UART.ctl"]["off"] != 0x10:
        ctx.rep.fail(hdr.file, "ctl moved")
    if hdr.defs.get("UART_FIFO_DEPTH") != 16:
        ctx.rep.fail(hdr.file, "fifo depth")
    if "#define UART_CTL_OFFSET" not in hdr.text:
        ctx.rep.fail(hdr.file, "text has no offset macro")

def check_group(ctx, group, hdrs):
    if group == "uart" and sorted(h.unit.name for h in hdrs) != ["uart"]:
        ctx.rep.fail(group, "members")

def check_final(ctx):
    if "gen/c/uart.h" not in ctx.hdrs or not ctx.allregs:
        ctx.rep.fail("final", "no headers")
    if ctx.lib.parse_defines("#define A 3\\n")["A"] != 3:
        ctx.rep.fail("final", "lib")
'''

    def with_plugin(self, body=None):
        self.write("scripts/plug.py", body or self.PLUGIN)
        self.edit("defs/check.toml", "[project]\nname = \"mini\"", '[project]\nname = "mini"\nplugin = "scripts/plug.py"')

    def test_plugin_hooks_see_the_model_in_the_old_shapes(self):
        self.with_plugin()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_plugin_finds_a_header_by_unit_name(self):
        self.with_plugin('''
def check_final(ctx):
    if ctx.hdrs["uart"] is not ctx.hdrs["gen/c/uart.h"] or ctx.hdrs.get("nosuch") is not None:
        ctx.rep.fail("final", "unit name does not find the header")
    try:
        ctx.hdrs["nosuch"]
    except KeyError:
        pass
    else:
        ctx.rep.fail("final", "an unknown unit name must raise KeyError")
    if "uart" in ctx.hdrs or "uart" in list(ctx.hdrs):
        ctx.rep.fail("final", "iteration sees file keys only")
''')
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_plugin_failure_is_reported(self):
        self.with_plugin(self.PLUGIN.replace("f[1] != 1", "f[1] != 2"))
        self.assert_fails("payload moved")

    def test_plugin_claims_are_checked(self):
        self.with_plugin()
        self.edit("docs/uart.md", "payload in bits 8:1", "payload in bits 8:2")
        self.assert_fails("FRAME.payload is 8:1 in the header but 8:2")

    def test_missing_plugin_is_a_setup_error(self):
        self.edit("defs/check.toml", "[project]\nname = \"mini\"", '[project]\nname = "mini"\nplugin = "scripts/none.py"')
        self.assertEqual(self.check().returncode, 2)

    def test_legacy_form_vectors_for_plugins(self):
        self.edit("defs/check.toml", "[units.uart]", '[units.uart]\nplugin_form = "legacy"')
        self.with_plugin('''
def check_header(ctx, hdr):
    if hdr.unit.name == "uart" and hdr.vecs.get((0x6b, "FRAME"), {}).get("payload") != 0x35:
        ctx.rep.fail(hdr.file, "legacy vecs %r" % (hdr.vecs,))
''')
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    # -- freshness ----------------------------------------------------------
    def test_stale_output_fails(self):
        self.edit("defs/uart.toml", "divisor = { bits = [31, 16]", "divisor = { bits = [30, 16]")
        self.edit("docs/uart.md", "bits 31:16", "bits 30:16")
        self.assert_fails("gen/c/uart.h: stale", regen=False)

    def test_no_fresh_skips_the_comparison(self):
        self.edit("defs/uart.toml", 'title = "made-up UART (fixture for the defs tools)"', 'title = "other"')
        self.assertEqual(self.check().returncode, 1)
        self.assertEqual(self.check("--no-fresh").returncode, 0)

    def test_unit_filter_checks_one_unit_only(self):
        self.edit("defs/uart.rev2.toml", "offset = 0x18", "offset = 0x18\nwidth = 99")
        r = self.check("--unit", "uart")
        self.assertEqual(r.returncode, 2)  # the overlay no longer loads
        r = self.check("--unit", "nope")
        self.assertEqual(r.returncode, 2)

    def test_directory_without_defs(self):
        self.assertEqual(run(CHECK, "--root", self.tmp).returncode, 2)


if __name__ == "__main__":
    unittest.main()
