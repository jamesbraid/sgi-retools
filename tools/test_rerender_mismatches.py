#!/usr/bin/env python3
"""Tests for the reading re-renderer. Grading and rendering are stubbed: they need real binaries."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rerender_mismatches as rr

DOC = """# Readings

Intro text that is not an entry.

- `good` in `usr/lib/a.so` at 0x1000 (o32).
  Evidence grade: inferred.
  Exact binary: `usr/lib/a.so`.
  Range: 0x1000-0x1008 (8 bytes).
  It occupies 8 bytes.

- `stale` in `usr/lib/b.a(obj.o)` at 0x2000 (n64).
  Evidence grade: established.
  Exact binary: `usr/lib/b.a(obj.o)`.
  Range: 0x2000-0x2010 (16 bytes).
  It occupies 16 bytes.
  The return at 0x200c has v0 = OLD.

- `stuck` in `usr/lib/c.so` at 0x3000 (o32).
  It occupies 4 bytes.

Trailing prose.
"""

NEW_STALE = """- `stale` in `usr/lib/b.a(obj.o)` at 0x2000 (n64).
  Evidence grade: established.
  Exact binary: `usr/lib/b.a(obj.o)`.
  Range: 0x2000-0x2010 (16 bytes).
  It occupies 16 bytes.
  The return at 0x200c has v0 = NEW.
  A second line.
"""


def fake_grade(root, entry):
    text = " ".join(entry["sentences"])
    if entry["name"] == "stuck" or "OLD" in text:
        return "MISMATCH", "stubbed"
    return "OK", ""


def fake_render(root, entry):
    if entry["name"] == "stuck":
        return "- `stuck` in `usr/lib/c.so` at 0x3000 (o32).\n  It occupies 4 bytes.\n"
    assert entry["install"] == "usr/lib/b.a(obj.o)" and entry["grade"] == "established"
    return NEW_STALE


class RerenderDoc(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.doc = os.path.join(self.dir.name, "instruction-readings-test.md")
        with open(self.doc, "w", encoding="utf-8") as sink:
            sink.write(DOC)

    def test_replaces_failing_entry_and_leaves_the_rest_alone(self):
        counts, conflicts = rr.rerender_doc(self.doc, "root", grade=fake_grade, render=fake_render)

        self.assertEqual((counts["entries"], counts["ok"], counts["rerendered"], counts["conflict"]),
                         (3, 1, 1, 1))
        self.assertEqual([(e["name"], "still MISMATCH" in d) for e, d in conflicts], [("stuck", True)])
        with open(self.doc, encoding="utf-8") as source:
            self.assertEqual(source.read(), DOC.replace(
                "  The return at 0x200c has v0 = OLD.\n",
                "  The return at 0x200c has v0 = NEW.\n  A second line.\n"))

    def test_unrenderable_entry_is_a_conflict_and_the_file_is_untouched(self):
        def broken(root, entry):
            raise SystemExit("cannot resolve address")

        counts, conflicts = rr.rerender_doc(self.doc, "root", grade=fake_grade, render=broken)

        self.assertEqual((counts["rerendered"], counts["conflict"]), (0, 2))
        self.assertIn("cannot render: cannot resolve address", conflicts[0][1])
        with open(self.doc, encoding="utf-8") as source:
            self.assertEqual(source.read(), DOC)

    def test_prose_documents_are_refused(self):
        for name in ("hw-explanations-x.md", "kona-reads.md"):
            with self.assertRaises(ValueError):
                rr.rerender_doc(os.path.join(self.dir.name, name), "root")


if __name__ == "__main__":
    unittest.main()
