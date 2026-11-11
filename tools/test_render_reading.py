#!/usr/bin/env python3
"""Tests for the facts-only reading entry renderer."""
import importlib.util
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("render_reading", os.path.join(HERE, "render_reading.py"))
render_reading = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render_reading)


class AccessRenderingTests(unittest.TestCase):
    def test_drops_stack_and_gp_and_groups_same_shaped_accesses(self):
        accesses = [
            {"address": "0x1000", "base": "a0", "kind": "store", "mnemonic": "sw", "width": 4,
             "origin": "a0", "origin_offset": 0, "text": "sw zero,0(a0)"},
            {"address": "0x1004", "base": "a0", "kind": "store", "mnemonic": "sw", "width": 4,
             "origin": "a0", "origin_offset": 0, "text": "sw zero,0(a0)"},
            {"address": "0x1008", "base": "a0", "kind": "store", "mnemonic": "sw", "width": 4,
             "origin": "a0", "origin_offset": 0, "text": "sw zero,0(a0)"},
            {"address": "0x100c", "base": "sp", "stack": True, "kind": "store", "mnemonic": "sw",
             "width": 4, "origin": "sp", "origin_offset": -4, "text": "sw ra,-4(sp)"},
            {"address": "0x1010", "base": "gp", "kind": "load", "mnemonic": "lw", "width": 4,
             "origin": "0x2000", "origin_offset": 0, "absolute": "0x2000", "symbol": "global"},
        ]

        self.assertEqual(render_reading.access_sentences(accesses, 2), [
            "3 such `sw` accesses store 4 bytes to a0 (arg0 at entry) +0x0, including "
            "`sw` at 0x1000, `sw` at 0x1004, `sw` at 0x1008."
        ])

    def test_shared_filter_excludes_sp_and_gp_accesses(self):
        accesses = [
            {"address": "0x1000", "base": "a0", "kind": "load", "mnemonic": "lw", "width": 4,
             "origin": "a0", "origin_offset": 0},
            {"address": "0x1004", "base": "sp", "kind": "load", "mnemonic": "lw", "width": 4,
             "origin": "sp", "origin_offset": 0},
            {"address": "0x1008", "base": "gp", "kind": "load", "mnemonic": "lw", "width": 4,
             "origin": "gp", "origin_offset": 0},
        ]

        self.assertEqual(len(render_reading.access_sentences(accesses, 1)), 1)
        self.assertEqual(render_reading.hostfacts.is_stack_or_global_access(accesses[1]), True)
        self.assertEqual(render_reading.hostfacts.is_stack_or_global_access(accesses[2]), True)

    def test_return_lists_all_distinct_path_values(self):
        exit_fact = {"v0": "?", "paths": [
            {"v0": "0x0"}, {"v0": "0x1"}, {"v0": "0x0"}
        ]}

        self.assertEqual(render_reading.return_value(exit_fact), "one of 0x0, 0x1")

    def test_return_lists_flatten_and_deduplicate_nested_choices(self):
        exit_fact = {"v0": "?", "paths": [
            {"v0": "one of (ret(foo, bar)), 0x1"},
            {"v0": "one of 0x1, 0x2"},
        ]}

        self.assertEqual(render_reading.return_value(exit_fact), "one of (ret(foo, bar)), 0x1, 0x2")

    def test_return_keeps_a_loaded_word_choice_as_one_value(self):
        exit_fact = {"v0": "?", "paths": [
            {"v0": "[one of 0x2000, 0x2004]"}, {"v0": "table(0x3000)"},
        ]}

        self.assertEqual(render_reading.return_value(exit_fact),
                         "one of [one of 0x2000, 0x2004], table(0x3000)")

    def test_return_uses_the_single_path_value_when_the_merged_value_is_unknown(self):
        exit_fact = {"v0": "?", "paths": [{"v0": "ret(?)"}]}

        self.assertEqual(render_reading.return_value(exit_fact), "ret(?)")

    def test_header_preserves_the_requested_alias_name(self):
        routine = SimpleNamespace(nargs=0, insns=[], in_states={})
        facts = {"routine": {"name": "canonical_name", "address": "0x1000", "end": "0x1004",
                              "size": 4, "abi": "o32"}}
        with patch.object(render_reading, "_call_sentences", return_value=[]), \
                patch.object(render_reading, "_branch_sentences", return_value=[]):
            output = render_reading.render_entry(
                routine, facts, "usr/lib/a.so", "Inferred", requested_name="requested_alias")

        self.assertTrue(output.startswith("- `requested_alias` in `usr/lib/a.so`"))


def have_capstone():
    try:
        import capstone  # noqa: F401
        import elftools  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(have_capstone(), "needs capstone and pyelftools")
class SegmentTests(unittest.TestCase):
    """`--root` reads a routine from the segment a firmware row key names."""

    def render(self, key, address, size, config=True):
        import contextlib
        import io
        import json
        import sys
        import tempfile
        sys.path.insert(0, HERE)
        import test_firmware_layout as fl
        with tempfile.TemporaryDirectory() as work:
            fl.workspace(os.path.join(work, "root"))
            path = os.path.join(work, "inventory-config.json")
            with open(path, "w") as handle:
                json.dump(fl.CONFIG if config else {}, handle)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                render_reading.main([key, address, "--size", str(size), "--path", key,
                                     "--root", os.path.join(work, "root"), "--config", path])
            return out.getvalue()

    def test_a_coldfire_segment_is_read_at_its_load_address(self):
        text = self.render("fw/l1.bin(l1#0)", "0xffe00008", 16)
        self.assertIn("Architecture: coldfire, load 0xffe00000, offset 0x0.", text)
        self.assertIn("loads 4 bytes from abs 0x10000014", text)

    def test_a_powerpc_kernel_segment_is_read_at_its_link_address(self):
        text = self.render("fw/l2.bin(kernel)", "0xc0000000", 20)
        self.assertIn("Architecture: ppc32, load 0xc0000000, offset 0x0.", text)
        self.assertIn("loads 4 bytes from abs 0x10000014", text)

    def test_a_key_outside_every_layout_group_is_refused(self):
        with self.assertRaises(SystemExit):
            self.render("usr/sbin/tool", "0x0", 4)


if __name__ == "__main__":
    unittest.main()
