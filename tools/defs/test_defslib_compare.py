#!/usr/bin/env python3
"""Tests for the old-header against new-header comparison and the migration flow."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import compare  # noqa: E402
from testkit import HERE, OldRepoTest, which  # noqa: E402

COMPARE = os.path.join(HERE, "defs-compare")
IMPORT = os.path.join(HERE, "defs-import")
GEN = os.path.join(HERE, "defs-gen")
CHECK = os.path.join(HERE, "defs-check")
CC = which("cc", "gcc")


def run(tool, *args):
    return subprocess.run([sys.executable, tool, *args], capture_output=True, text=True)


OLD = """#ifndef OLD_H
#define OLD_H
#include <stdint.h>
#define A_SHIFT 3
#define A_MASK 0x1fu
#define B 0x10
#define C (A_MASK << A_SHIFT)
#define NAME "text"
#define GET(w, s) (((w) >> (s)) & 1)
#endif
"""


@unittest.skipUnless(CC, "no C compiler")
class CompareHeadersTest(OldRepoTest):
    def compare(self, old, new, dropped=None):
        self.write("old.h", old)
        self.write("new.h", new)
        return compare.compare_headers(self.path("old.h"), self.path("new.h"), "t", dropped)

    def test_same_values_written_differently_are_equal(self):
        new = OLD.replace("0x10", "16").replace("0x1fu", "31").replace("(A_MASK << A_SHIFT)", "248")
        out = self.compare(OLD, new)
        self.assertTrue(out.ok, out.different)
        self.assertEqual((out.old, out.paired, out.equal), (6, 6, 6))

    def test_guard_is_not_counted(self):
        out = self.compare(OLD, OLD)
        self.assertEqual(out.old, 6)

    def test_a_different_value_fails(self):
        out = self.compare(OLD, OLD.replace("0x1fu", "0x3fu"))
        self.assertFalse(out.ok)
        names = [d[0] for d in out.different]
        self.assertIn("A_MASK", names)
        self.assertIn("C", names)           # derived macros differ too

    def test_a_missing_macro_fails_unless_dropped(self):
        new = OLD.replace("#define B 0x10\n", "")
        out = self.compare(OLD, new)
        self.assertEqual(out.missing, ["B"])
        out = self.compare(OLD, new, {"B": "obsolete"})
        self.assertTrue(out.ok)
        self.assertEqual(out.dropped, 1)

    def test_a_drop_that_is_not_needed_is_reported(self):
        out = self.compare(OLD, OLD, {"B": "stale entry", "OTHER_UNIT_MACRO": "belongs to another header"})
        self.assertEqual(out.unused_drops, ["B"])      # the other unit's name is not this header's business

    def test_function_like_macro_is_compared_by_text(self):
        out = self.compare(OLD, OLD.replace("& 1)", "& 3)"))
        self.assertEqual([d[0] for d in out.different], ["GET"])

    def test_non_integer_macro_is_compared_by_text(self):
        out = self.compare(OLD, OLD.replace('"text"', '"other"'))
        self.assertEqual([d[0] for d in out.different], ["NAME"])

    def test_extra_macros_in_the_new_header_are_counted_not_failed(self):
        out = self.compare(OLD, OLD.replace("#endif", "#define EXTRA 1\n#endif"))
        self.assertTrue(out.ok)
        self.assertEqual(out.new_only, 1)

    def test_a_header_that_does_not_compile_fails_with_its_error(self):
        out = self.compare(OLD, OLD.replace("#endif", "static const int t[UNDEFINED_COUNT] = {0};\n#endif"))
        self.assertFalse(out.ok)
        self.assertEqual(len(out.broken), 1)
        self.assertIn("new header does not compile", out.broken[0])
        self.assertIn("UNDEFINED_COUNT", out.broken[0])
        self.assertEqual(out.different, [])          # it does not pretend the macros differ
        old_broken = self.compare(OLD.replace("#endif", "int x = ;\n#endif"), OLD)
        self.assertIn("old header does not compile", old_broken.broken[0])

    def test_cli_with_two_files(self):
        self.write("old.h", OLD)
        self.write("new.h", OLD.replace("0x10", "17"))
        r = run(COMPARE, "--old", self.path("old.h"), "--new", self.path("new.h"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIFFERENT B: old 0x10, new 0x11", r.stdout)
        self.write("new.h", OLD)
        self.assertEqual(run(COMPARE, "--old", self.path("old.h"), "--new", self.path("new.h")).returncode, 0)

    def test_cli_needs_both_files(self):
        self.assertEqual(run(COMPARE, "--old", "x.h").returncode, 2)


@unittest.skipUnless(CC, "no C compiler")
class MigrationFlowTest(OldRepoTest):
    """The command sequence a repo agent runs, on the old-format fixture."""

    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "old headers")
        self.assertEqual(run(IMPORT, "--root", self.root).returncode, 0)

    def compare(self):
        return run(COMPARE, "--root", self.root)

    def resolve(self):
        """What the migrating agent does with the report: grade or drop, alias or drop."""
        self.edit("defs/leg.toml", "[constants]", '[constants]\nOP_WORDS = { value = 8, grade = "established" }')
        self.edit("defs/leg.toml", "[c.aliases]", '[c.aliases]\nLEG_CMD_FRONT_BIT = "LEG_CMD_FRONT_INPLACE"\nLEG_CMD_BOTH_BITS = "(LEG_CMD_FRONT_BIT | 0x1u)"')
        self.edit("defs/tab.toml", "[constants]", '[constants]\nREQ_RESET = { value = 0x2001, grade = "unknown" }')

    def test_the_forwarding_headers_fail_the_comparison_until_the_report_is_resolved(self):
        self.assertEqual(run(GEN, "--root", self.root).returncode, 0)
        r = self.compare()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("MISSING LEG_OP_WORDS", r.stdout)
        self.assertIn("MISSING TAB_REQ_RESET", r.stdout)
        self.assertIn("MISSING LEG_CMD_BOTH_BITS", r.stdout)
        self.assertNotIn("DIFFERENT", r.stdout)

    def test_resolved_migration_compares_equal_and_checks_clean(self):
        self.resolve()
        self.assertEqual(run(GEN, "--root", self.root).returncode, 0)
        r = self.compare()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 different, 0 missing", r.stdout)
        r = run(CHECK, "--root", self.root, "--build")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_old_header_text_comes_from_git_not_from_the_working_tree(self):
        self.resolve()
        run(GEN, "--root", self.root)
        self.assertIn("Transition header", self.read("LEG_DECODE.h"))   # overwritten by the forwarding header
        self.assertEqual(self.compare().returncode, 0)

    def test_dropping_a_macro_on_purpose(self):
        self.edit("defs/leg.toml", "[constants]", '[constants]\nOP_WORDS = { value = 8, grade = "established" }')
        self.edit("defs/leg.toml", "[c.aliases]", '[c.aliases]\nLEG_CMD_FRONT_BIT = "LEG_CMD_FRONT_INPLACE"')
        self.edit("defs/tab.toml", "[constants]", '[constants]\nREQ_RESET = { value = 0x2001, grade = "unknown" }')
        run(GEN, "--root", self.root)
        self.assertEqual(self.compare().returncode, 1)
        self.write("defs/legacy-dropped.txt", "LEG_CMD_BOTH_BITS\tonly the old header used it\n")
        r = self.compare()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("1 dropped on purpose", r.stdout)

    def test_a_wrong_alias_is_caught(self):
        self.resolve()
        self.edit("defs/leg.toml", 'LEG_CMD_SIZEFLD_SHIFT = "LEG_CMD_SIZE_FIELD_SHIFT"', 'LEG_CMD_SIZEFLD_SHIFT = "LEG_CMD_CLASS_SHIFT"')
        run(GEN, "--root", self.root)
        r = self.compare()
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIFFERENT LEG_CMD_SIZEFLD_SHIFT: old 0x3, new 0x0", r.stdout)

    def test_a_changed_layout_is_caught(self):
        self.resolve()
        self.edit("defs/cen.toml", "offset = 0x20", "offset = 0x30")
        run(GEN, "--root", self.root)
        r = self.compare()
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIFFERENT CEN_CFG0: old 0x20, new 0x30", r.stdout)

    def test_missing_forwarding_header_is_a_setup_error(self):
        self.resolve()
        r = self.compare()
        self.assertEqual(r.returncode, 0)    # the old headers are still in place, and equal themselves
        os.remove(self.path("CEN.h"))
        r = self.compare()
        self.assertEqual(r.returncode, 2)
        self.assertIn("run defs-gen", r.stderr)

    def test_revision_not_in_git(self):
        r = run(COMPARE, "--root", self.root, "--old-rev", "nope")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
