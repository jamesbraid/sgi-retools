#!/usr/bin/env python3
"""Tests for the facts-only reading entry renderer."""
import importlib.util
import os
import unittest


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

    def test_return_lists_all_distinct_path_values(self):
        exit_fact = {"v0": "?", "paths": [
            {"v0": "0x0"}, {"v0": "0x1"}, {"v0": "0x0"}
        ]}

        self.assertEqual(render_reading.return_value(exit_fact), "one of 0x0, 0x1")


if __name__ == "__main__":
    unittest.main()
