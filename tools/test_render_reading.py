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


if __name__ == "__main__":
    unittest.main()
