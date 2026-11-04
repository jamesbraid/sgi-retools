#!/usr/bin/env python3
"""Tests for the shared facts-only reading grader."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import grade_readings as grade


class EntryLayouts(unittest.TestCase):
    def test_bullet_and_exact_binary_headers(self):
        content = """# Readings

- `routine_a` in `usr/lib/a.so` at 0x1000 (o32).
  It occupies 24 bytes.
  The return at 0x1010 has v0 = ?.

- `routine_b` (`usr/lib/b.so`, 0x2000, 32 bytes) Inferred.
  Evidence grade: established.
  Exact binary: `usr/lib/b.so`.
  Range: 0x2000-0x2020 (32 bytes).
  Role: unknown.
  Returns v0 = 0x0 (`jr` at 0x201c).

- `routine_c` in `usr/lib/c.a(obj.o)` at 0x3000 (n64).
  It occupies 8 bytes.
"""
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as doc:
            doc.write(content)
            doc.flush()
            entries = grade.parse_entries(doc.name)
        self.assertEqual([(e["name"], e["binary"], e["address"], e["size"])
                          for e in entries], [
                              ("routine_a", "usr/lib/a.so", "0x1000", 24),
                              ("routine_b", "usr/lib/b.so", "0x2000", 32),
                              ("routine_c", "usr/lib/c.a:obj.o", "0x3000", 8),
                          ])
        self.assertEqual(len(entries[1]["sentences"]), 1)


class SentenceChecks(unittest.TestCase):
    def setUp(self):
        self.facts = {
            "routine": {"size": 24},
            "accesses": [
                {"address": "0x1004", "kind": "load", "width": 4, "mnemonic": "lw", "base": "s0",
                 "origin": "a0", "origin_offset": 196, "text": "lw v0,196(s0)", "value": None},
                {"address": "0x1008", "kind": "load", "width": 4, "mnemonic": "lw", "base": "s0",
                 "origin": "a0", "origin_offset": 196, "text": "lw v0,196(s0)", "value": None},
            ],
            "branches": [], "exits": [], "unreached": ["0x1014", "0x1018"],
        }
        self.rendered = [
            "  0x100c jal foo via direct",
            "      args: a0=[a0+4], a1=0x1, a2=?, a3=ret(bar)",
            "  0x1010 `beq a0,zero,1018` -> 0x1018 (B1)",
            "      taken when condition not analyzed -> B1",
            "      falls through when condition not analyzed -> B2",
            "      delay slot 0x1014 `nop`: runs on both paths",
            "  0x1020 `jr ra` returns; delay slot 0x1024 `nop` runs",
            "  0x1020 in B3: v0 = ?; reached from blocks B0 B1",
            "      from 0x100c: v0 = 0x0",
            "      from 0x1010: v0 = 0x1",
        ]
        self.maps = grade._render_maps(self.facts, self.rendered)

    def check(self, sentence):
        return grade.check_sentence(sentence, self.facts, self.rendered, self.maps)

    def test_context_notes_do_not_change_target_values(self):
        self.assertEqual(grade._value("sp (at entry) -0x64"), "sp -0x64")
        self.assertEqual(grade._value("? (base unknown)"), "?")
        self.assertEqual(grade._value("(ret(foo) << 2)"), "(ret(foo) << 2)")
        self.assertEqual(grade._value("ret(unknown)"), "ret(?)")

    def test_grouped_access_counts_and_addresses(self):
        sentence = ("2 such accesses load 4 bytes from a0 (arg0 at entry) +0xc4 via base s0 (a0), "
                    "including `lw` at 0x1004, `lw` at 0x1008.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_old_access_sentence_with_value_qualifier(self):
        self.facts["accesses"].append({"address": "0x100c", "kind": "store", "width": 8,
                                       "mnemonic": "sd", "base": "zero", "origin": None,
                                       "absolute": "0xffffffffaff10028", "text": "sd at,0(zero)",
                                       "value": "0x4000000000000"})
        self.maps = grade._render_maps(self.facts, self.rendered)
        sentence = "Stores 8 bytes from at to abs 0xffffffffaff10028 (`sd` at 0x100c) with value 0x4000000000000."
        self.assertEqual(self.check(sentence), ("OK", None))
        self.assertEqual(self.check(sentence.replace("0x4000000000000", "0x0"))[0], "MISMATCH")

    def test_current_access_sentence_compares_store_value(self):
        self.facts["accesses"].append({"address": "0x100c", "kind": "store", "width": 4,
                                       "mnemonic": "sw", "base": "zero", "origin": None,
                                       "absolute": "0x2000", "text": "sw t0,0(zero)", "value": "0x4"})
        self.maps = grade._render_maps(self.facts, self.rendered)
        sentence = "The `sw` at 0x100c stores 4 bytes to abs 0x2000 with value 0x4."
        self.assertEqual(self.check(sentence), ("OK", None))
        self.assertEqual(self.check(sentence.replace("0x4", "0x8"))[0], "MISMATCH")

    def test_store_uses_resolved_offset_and_accepts_parenthesized_value(self):
        self.facts["accesses"].append({"address": "0x1010", "kind": "store", "width": 4,
                                       "mnemonic": "sw", "base": "a2", "origin": "[a0+280]",
                                       "origin_offset": 308, "offset": 20, "text": "sw a1,20(a2)",
                                       "value": "0x3"})
        self.maps = grade._render_maps(self.facts, self.rendered)
        sentence = "The `sw` at 0x1010 stores 4 bytes to [a0+280] +0x134 (value 0x3)."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_unknown_matches_unknown_argument_value_forms(self):
        expected = "a0=ret(?), a1=?, a2=0x3, a3=0x4"
        rendered = ["  0x100c jal foo via direct", "      args: " + expected]
        maps = grade._render_maps(self.facts, rendered)
        sentence = "The `jal` at 0x100c calls `foo` with a0=unknown, a1=unknown, a2=0x3, a3=0x4."
        self.assertEqual(grade.check_sentence(sentence, self.facts, rendered, maps), ("OK", None))

    def test_unknown_matches_unknown_return_value_forms(self):
        returns = self.maps[3]
        returns["0x1020"]["value"] = "ret(?)"
        self.assertEqual(self.check("The return at 0x1020 has v0 = unknown."), ("OK", None))

    def test_old_call_compares_every_argument_slot(self):
        sentence = "Calls `foo` via direct with a0=[a0+4], a1=0x1, a2=?, a3=ret(bar) (`jal` at 0x100c)."
        self.assertEqual(self.check(sentence), ("OK", None))
        mismatch = sentence.replace("a3=ret(bar)", "a3=?")
        self.assertEqual(self.check(mismatch), ("MISMATCH", "a0=[a0+4], a1=0x1, a2=?, a3=ret(bar)"))

    def test_unknown_callee_with_nested_values(self):
        expected = "a0=[[[0x1010]+12744]+112], a1=?, a2=(ret(foo) + 8), a3=?"
        rendered = ["  0x100c jalr (unknown callee) via register", "      args: " + expected]
        maps = grade._render_maps(self.facts, rendered)
        sentence = "The `jalr` at 0x100c calls `(unknown callee)` with " + expected + "."
        self.assertEqual(grade.check_sentence(sentence, self.facts, rendered, maps), ("OK", None))

    def test_branch_unanalyzed_condition_and_delay_slot(self):
        sentence = "The `beq` at 0x1010 is taken when condition not analyzed and falls through when condition not analyzed."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_return_one_of_and_per_path_values(self):
        self.assertEqual(self.check("The return at 0x1020 has v0 = one of 0x0 or 0x1."), ("OK", None))
        self.assertEqual(self.check("The return at 0x1020 has v0 = 0x0 on the path from 0x100c."), ("OK", None))

    def test_return_value_and_delay_slot(self):
        returns = self.maps[3]
        returns["0x1020"]["delay"] = ("0x1024", "nop")
        sentence = "The `jr` at 0x1020 returns with v0 = one of 0x0, 0x1; its delay slot executes `nop` at 0x1024."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_branch_likely_delay_slot(self):
        branch = self.maps[2]["0x1010"]
        branch.update(mn="bnel", likely=True, delay=("0x1014", "lw"))
        sentence = ("The `bnel` branch at 0x1010 is taken when condition not analyzed and falls through when "
                    "condition not analyzed; its `lw` delay slot at 0x1014 runs only when taken and is annulled on fall-through.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_size_and_unreached_ranges(self):
        self.assertEqual(self.check("It occupies 24 bytes."), ("OK", None))
        self.assertEqual(self.check("The instructions from 0x1014 to 0x1018 are not reached by any path from the entry, and their branches are not listed."), ("OK", None))

    def test_unknown_sentence_is_reported(self):
        self.assertEqual(self.check("This sentence is not a hostfacts claim."), ("UNPARSED", "This sentence is not a hostfacts claim."))


if __name__ == "__main__":
    unittest.main()
