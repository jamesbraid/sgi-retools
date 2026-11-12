#!/usr/bin/env python3
"""Tests for the small C scanner the importer uses instead of a preprocessor."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import c_scan  # noqa: E402

SAMPLE = """#ifndef G
#define G
#include <stdint.h>
/* leading doc for A */
#define A 0x10u /* multi
 * line trailing */
/* about the table */
static const int t[] = {
    [0] = 5, /* five */
    /* a comment inside */
    [1] = 6, /* six */
};
#define B(x) ((x) \\
              + 1)
static inline int f(void) { return 1; } // trailing
#endif /* G */
"""


class CScanTest(unittest.TestCase):
    def test_defines_with_continuations_and_comments(self):
        d = {x.name: x for x in c_scan.scan_defines(SAMPLE)}
        self.assertEqual(d["A"].body, "0x10u")
        self.assertEqual(d["A"].comment, "multi line trailing")
        self.assertEqual(d["B"].params, "(x)")
        self.assertEqual(d["B"].body, "((x) + 1)")
        self.assertEqual(len(d["B"].raw), 2)

    def test_include_guard(self):
        self.assertEqual(c_scan.include_guard(SAMPLE), "G")
        self.assertIsNone(c_scan.include_guard("int x;\n"))

    def test_literals(self):
        self.assertEqual(c_scan.num_literal("0x10u"), 16)
        self.assertEqual(c_scan.num_literal("(0x20)"), 32)
        self.assertEqual(c_scan.num_literal("12UL"), 12)
        self.assertIsNone(c_scan.num_literal("(1u << 3)"))
        self.assertIsNone(c_scan.num_literal("FOO"))

    def test_strip_comments_keeps_lines_and_strings(self):
        out = c_scan.strip_comments('a /* x\ny */ b "/* not */" // tail\nc')
        self.assertEqual(out.count("\n"), 2)
        self.assertIn('"/* not */"', out)
        self.assertNotIn("tail", out)

    def test_code_keeps_trailing_comments_and_the_comment_above(self):
        code = c_scan.extract_code(SAMPLE, "G")
        self.assertIn("/* about the table */\nstatic const int t[] = {", code)
        self.assertIn("[0] = 5, /* five */", code)
        self.assertIn("/* a comment inside */", code)
        self.assertIn("static inline int f(void) { return 1; } // trailing", code)

    def test_code_leaves_out_defines_guard_stdint_and_their_comments(self):
        code = c_scan.extract_code(SAMPLE, "G")
        for gone in ("#define", "#ifndef", "#endif", "stdint", "leading doc", "line trailing", "(x) +"):
            self.assertNotIn(gone, code)

    def test_no_code_is_the_empty_string(self):
        self.assertEqual(c_scan.extract_code("#ifndef G\n#define G\n#define A 1 /* c */\n#endif\n", "G"), "")

    def test_unknown_annotations(self):
        text = "/*\n * REG: A.b 0x0 r32\n * CALC: 4 => 4\n * CALC: 5 => 6\n * TESTVEC: 1 as A => x=1\n */\n"
        self.assertEqual(c_scan.unknown_annotations(text), {"CALC": 2})
        self.assertEqual([l for _k, l in c_scan.unknown_annotation_lines(text)], [" * CALC: 4 => 4", " * CALC: 5 => 6"])
        one = c_scan.unknown_annotation_lines("/* COPY: rectangle copy, count 8. */\n")
        self.assertEqual(one, [("COPY", " * COPY: rectangle copy, count 8.")])        # no nested comment opener


if __name__ == "__main__":
    unittest.main()
