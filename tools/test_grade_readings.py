#!/usr/bin/env python3
"""Tests for the shared facts-only reading grader."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fact_check
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

    def test_entries_report_their_extent_install_path_and_grade(self):
        lines = ["# Readings", "", "- `a` in `usr/lib/a.a(x.o)` at 0x10 (n64).",
                 "  Evidence grade: established.", "  It occupies 8 bytes.", "", "prose"]
        (entry,) = grade.parse_lines(lines)

        self.assertEqual((entry["line"], entry["end"]), (3, 5))
        self.assertEqual((entry["install"], entry["binary"], entry["grade"]),
                         ("usr/lib/a.a(x.o)", "usr/lib/a.a:x.o", "established"))

    def test_entry_ends_at_first_non_indented_line(self):
        content = """- `routine_a` in `usr/lib/a.so` at 0x1000 (o32).
  It occupies 24 bytes.

Skipped targets:
These are not part of the last entry.
"""
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as doc:
            doc.write(content)
            doc.flush()
            entries = grade.parse_entries(doc.name)

        self.assertEqual(entries[0]["sentences"], ["It occupies 24 bytes."])


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

    def test_grouped_access_count_ignores_sp_and_gp_bases(self):
        self.facts["accesses"] = [
            {"address": "0x100c", "kind": "load", "width": 4, "mnemonic": "lw", "base": "s0",
             "text": "lw v0,196(s0)", "value": None},
            {"address": "0x1010", "kind": "load", "width": 4, "mnemonic": "lw", "base": "sp",
             "text": "lw v0,196(sp)", "value": None},
            {"address": "0x1014", "kind": "load", "width": 4, "mnemonic": "lw", "base": "gp",
             "text": "lw v0,196(gp)", "value": None},
        ]
        self.maps = grade._render_maps(self.facts, self.rendered)
        sentence = "1 such `lw` accesses load 4 bytes from ?, including `lw` at 0x100c."

        self.assertEqual(self.check(sentence), ("OK", None))

    def test_kona_g25_grouped_access_without_base_clause(self):
        for access in self.facts["accesses"]:
            access["origin_offset"] = 332
        sentence = ("2 such `lw` accesses load 4 bytes from a0 (arg0 at entry) +0x14c, "
                    "including `lw` at 0x1004, `lw` at 0x1008.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_kona_g23_grouped_access_legacy_form(self):
        for access in self.facts["accesses"]:
            access["absolute"] = "0x100a90d4"
            access.pop("origin", None)
        sentence = ("3 such accesses, including `lw` at 0x1004, 0x1008, 0x100c, "
                    "loads 4 bytes from abs 0x100a90d4.")
        self.facts["accesses"].append(dict(self.facts["accesses"][0], address="0x100c"))
        self.maps = grade._render_maps(self.facts, self.rendered)
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g24_grouped_access_form(self):
        sentence = ("2 4-byte lw loads at a0 +0xc4, including `lw` at 0x1004, `lw` at 0x1008.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g24_single_access_form(self):
        sentence = "Loads 4 bytes at a0 +0xc4 (`lw` at 0x1004)."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g24_store_at_target_form(self):
        self.facts["accesses"].append({"address": "0x100c", "kind": "store", "width": 4,
                                       "mnemonic": "swc1", "base": "a2", "origin": "a2",
                                       "origin_offset": 0, "text": "swc1 $f13,0(a2)", "value": None})
        self.maps = grade._render_maps(self.facts, self.rendered)
        sentence = "Stores 4 bytes from f13 at a2 +0x0 (`swc1` at 0x100c)."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g21_routine_size_and_address(self):
        self.facts["routine"]["address"] = "0x1000"
        sentence = "The routine occupies 24 bytes at address 0x1000."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g21_grouped_store_form(self):
        for address in ("0x100c", "0x1010"):
            self.facts["accesses"].append({"address": address, "kind": "store", "width": 4,
                                            "mnemonic": "sw", "base": "zero",
                                            "text": "sw zero,0(zero)", "value": "0x0"})
        self.maps = grade._render_maps(self.facts, self.rendered)
        sentence = ("2 such accesses: Stores 4 bytes from zero to ? (base unknown) "
                    "(including `sw` at 0x100c, 0x1010).")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_kona_g25_call_with_unquoted_callee(self):
        sentence = ("The `jal` at 0x100c calls update__18VkwindowMainWindowGv with "
                    "a0=[sym(vkwindow)], a1=[a2+8], a2=[a0+328], a3=0x7d8c0.")
        self.maps[1]["0x100c"] = {"tail": False, "mn": "jal", "callee": "update__18VkwindowMainWindowGv",
                                  "via": "direct", "args": "a0=[sym(vkwindow)], a1=[a2+8], a2=[a0+328], a3=0x7d8c0"}
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_kona_g22_call_with_address_qualified_callee(self):
        sentence = ("The `jalr` at 0x100c calls `__glNamesIsName [0x2e580d0]` with "
                    "a0=[0x1020]:8, a1=[[0x1020]:8+6864]:8, a2=a0 at entry (arg0), "
                    "a3=a3 at entry (arg3).")
        self.maps[1]["0x100c"] = {"tail": False, "mn": "jalr", "callee": "__glNamesIsName [0x2e580d0]",
                                  "via": "register-constant", "args": "a0=[0x1020]:8, a1=[[0x1020]:8+6864]:8, a2=a0 at entry (arg0), a3=a3 at entry (arg3)"}
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

    def test_kona_g23_branch_with_target_and_conditions(self):
        self.maps[2]["0x1010"].update(mn="beq", target="0x1018", taken="a0 == 0", fall="a0 != 0")
        sentence = ("The `beq` branch at 0x1010 targets 0x1018, is taken when a0 == 0, "
                    "and falls through when a0 != 0.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_kona_g23_never_taken_branch(self):
        rendered = ["  0x1010 `beq a0,zero,1018` never taken (its condition can never hold for these operands); falls through; runs"]
        self.maps = grade._render_maps(self.facts, rendered)
        sentence = ("The `beq` branch at 0x1010 targets 0x1018 and is never taken: its condition can never hold for these operands, "
                    "so execution always falls through.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_kona_g25_always_taken_branch(self):
        rendered = ["  0x1010 `beq zero,zero,1018` always taken -> B1"]
        self.maps = grade._render_maps(self.facts, rendered)
        sentence = "The `beq` branch at 0x1010 targets 0x1018 and is always taken."
        self.assertEqual(self.check(sentence), ("OK", None))
        self.assertEqual(self.check(sentence.replace("0x1018", "0x1020"))[0], "MISMATCH")

    def test_kona_g22_always_taken_branch(self):
        branch = self.maps[2]["0x1010"]
        branch.update(mn="beq", target="0x1018", always=True)
        sentence = "At `beq` at 0x1010 (target 0x1018), the branch is always taken."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_kona_g25_branch_condition_not_analyzed(self):
        sentence = "The `beq` branch at 0x1010 targets 0x1018; its condition is not analyzed."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_return_one_of_and_per_path_values(self):
        self.assertEqual(self.check("The return at 0x1020 has v0 = one of 0x0 or 0x1."), ("OK", None))
        self.assertEqual(self.check("The return at 0x1020 has v0 = 0x0 on the path from 0x100c."), ("OK", None))

    def test_return_choices_split_only_outside_parentheses(self):
        self.maps[3]["0x1020"]["value"] = "?"
        self.maps[3]["0x1020"]["paths"] = {
            "0x100c": "(ret(foo, bar))", "0x1010": "0x1"
        }
        sentence = "The return at 0x1020 has v0 = one of (ret(foo, bar)), 0x1."

        self.assertEqual(self.check(sentence), ("OK", None))

    def test_return_choice_that_is_one_loaded_word_stays_whole(self):
        # "[one of A, B]" is a single word loaded from one of two addresses, not two choices.
        self.maps[3]["0x1020"]["value"] = "?"
        self.maps[3]["0x1020"]["paths"] = {
            "0x100c": "[one of 0x2000, 0x2004]", "0x1010": "table(0x3000)"
        }
        sentence = "The return at 0x1020 has v0 = one of [one of 0x2000, 0x2004], table(0x3000)."
        self.assertEqual(self.check(sentence), ("OK", None))
        split = "The return at 0x1020 has v0 = one of 0x2000, 0x2004, table(0x3000)."
        self.assertEqual(self.check(split)[0], "MISMATCH")

    def test_return_value_all_paths_agree_while_merged_value_is_unknown(self):
        self.maps[3]["0x1020"]["value"] = "?"
        self.maps[3]["0x1020"]["paths"] = {"0x100c": "ret(?)"}
        self.assertEqual(self.check("The return at 0x1020 has v0 = ret(?)."), ("OK", None))
        self.assertEqual(self.check("The return at 0x1020 has v0 = 0x0.")[0], "MISMATCH")
        self.maps[3]["0x1020"]["paths"] = {"0x100c": "ret(?)", "0x1010": "0x1"}
        self.assertEqual(self.check("The return at 0x1020 has v0 = ret(?).")[0], "MISMATCH")

    def test_return_value_and_delay_slot(self):
        returns = self.maps[3]
        returns["0x1020"]["delay"] = ("0x1024", "nop")
        sentence = "The `jr` at 0x1020 returns with v0 = one of 0x0, 0x1; its delay slot executes `nop` at 0x1024."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g24_return_with_float_result(self):
        self.maps[3]["0x1020"]["value"] = "ret(foo); f0 = ret(foo)"
        sentence = "Returns v0 = ret(foo), f0 = ret(foo) (`jr` at 0x1020)."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g24_tail_call_sentence(self):
        self.maps[1]["0x100c"].update(tail=True, mn="jr", callee="(unnamed) [0xd980438]",
                                      via="register-constant", args="a0=a0 at entry (arg0), a1=a1 at entry (arg1), a2=a2 at entry (arg2), a3=a3 at entry (arg3)")
        sentence = ("Calls (unknown callee) via register-constant with a0=a0 at entry (arg0), "
                    "a1=a1 at entry (arg1), a2=a2 at entry (arg2), a3=a3 at entry (arg3) "
                    "(`jr` at 0x100c).")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g23_instruction_description(self):
        self.facts["instructions"] = {"0x1010": "nmsub.s"}
        sentence = ("The instruction at 0x1010 is `nmsub.s`, a single-precision floating-point "
                    "negative multiply-subtract.")
        self.assertEqual(self.check(sentence), ("OK", None))
        self.assertEqual(self.check(sentence.replace("nmsub.s", "nmadd.s"))[0], "MISMATCH")

    def test_kona_g24_nonbranch_instruction_list(self):
        self.facts["instructions"] = {"0x1004": "madd.s", "0x1008": "madd.s"}
        self.facts["branch_likely"] = []
        sentence = "The `madd.s` at 0x1004, 0x1008 is not a branch."
        self.assertEqual(self.check(sentence), ("OK", None))
        self.facts["branches"].append({"address": "0x1008"})
        self.assertEqual(self.check(sentence)[0], "MISMATCH")

    def test_branch_likely_delay_slot(self):
        branch = self.maps[2]["0x1010"]
        branch.update(mn="bnel", likely=True, delay=("0x1014", "lw"))
        sentence = ("The `bnel` branch at 0x1010 is taken when condition not analyzed and falls through when "
                    "condition not analyzed; its `lw` delay slot at 0x1014 runs only when taken and is annulled on fall-through.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_odsy_g24_branch_likely_delay_wording(self):
        rendered = [
            "  0x1010 `bc1fl 1018` -> 0x1018 (B1)",
            "      taken when not (f2 < f4 (c.lt.d at 0x100c)) -> B1",
            "      falls through when f2 < f4 (c.lt.d at 0x100c) -> B2",
            "      delay slot 0x1014 `sqrt.d $f0,$f2`: branch-likely: runs only when taken, annulled on fall-through",
        ]
        self.maps = grade._render_maps(self.facts, rendered)
        sentence = ("At `bc1fl` at 0x1010 (target 0x1018), taken when not (f2 < f4 (c.lt.d at 0x100c)) "
                    "and falls through when f2 < f4 (c.lt.d at 0x100c); its branch-likely delay slot "
                    "`sqrt.d $f0,$f2` at 0x1014 runs only when taken and is annulled on fall-through.")
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_size_and_unreached_ranges(self):
        self.assertEqual(self.check("It occupies 24 bytes."), ("OK", None))
        self.assertEqual(self.check("The instructions from 0x1014 to 0x1018 are not reached by any path from the entry, and their branches are not listed."), ("OK", None))

    def test_jump_table_targets(self):
        self.facts["jump_tables"] = [{"jump": "0x1020", "table": "0x2000",
                                       "targets": ["0x1030", "0x1040"]}]
        sentence = "The indirect jump at 0x1020 uses the jump table at 0x2000 with targets 0x1030, 0x1040."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_unresolved_jump_table_note(self):
        self.rendered.append("  0x1020 `jr t9` (jump table; successors unresolved)")
        sentence = "The indirect jump at 0x1020 uses a jump table whose successors are unresolved."
        self.assertEqual(self.check(sentence), ("OK", None))

    def test_unknown_sentence_is_reported(self):
        self.assertEqual(self.check("This sentence is not a hostfacts claim."), ("UNPARSED", "This sentence is not a hostfacts claim."))


class CheckDoc(unittest.TestCase):
    """--check-doc: the lint of a docs/routines file, one entry at a time."""
    BINARY = "sw22/var/sysgen/boot/swfs.o"
    OTHER = "sw23/var/sysgen/boot/swfs.o"
    ROLE = ("Copies a 12-byte block in at 0x1f9c and calls `swf_mount_fs` at 0x2080. The return is the "
            "constant 0xe or the mount result at 0x2084.")

    def lint(self, text, table=True, rows=None, review=False, routines=False, intro=True):
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory)
        doc = os.path.join(directory, "b000.md")
        with open(doc, "w", encoding="utf-8") as handle:
            handle.write(("# Readings\n\nIntro that names `swfio_mount` at 0x1f80 and is not an entry.\n\n" if intro
                          else "") + text)
        path = None
        if table:
            path = os.path.join(directory, "functions.tsv")
            rows = rows or [(self.BINARY, "0x1f80", "aa"), (self.OTHER, "0x1fe0", "bb")]
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("binary\taddress\tname\tcode_sha\n")
                for binary, address, code in rows:
                    handle.write("%s\t%s\tswfio_mount\t%s\n" % (binary, address, code))
        out = io.StringIO()
        problems = grade.check_doc(doc, path, out, review=review, routines=routines)
        return problems, out.getvalue()

    def test_the_canonical_entry_has_no_problem(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n" % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 0, out)
        self.assertIn("understood=1", out)

    def test_an_emulator_run_called_measured_is_a_problem(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s The reset value 0x5 was measured in a QEMU run.\n"
                                  % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 1, out)
        self.assertIn("model behaviour", out)

    def test_an_emulator_run_described_as_a_model_result_is_fine(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s The QEMU model returns 0x5 here.\n"
                                  % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 0, out)

    def test_a_measurement_without_an_emulator_is_fine(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s The size was measured from the symbol table.\n"
                                  % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 0, out)

    def test_an_unreviewed_entry_is_a_note_when_the_file_requires_review(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n" % (self.BINARY, self.ROLE),
                                  review=True)
        self.assertEqual(problems, 0, out)
        self.assertIn("located=1", out)
        self.assertIn("no Reviewed line", out)

    def test_a_reviewed_entry_is_understood_when_the_file_requires_review(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n  Reviewed: 2026-11-12\n"
                                  % (self.BINARY, self.ROLE), review=True)
        self.assertEqual(problems, 0, out)
        self.assertIn("understood=1", out)

    def test_review_is_read_from_the_workspace_config(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory)
        os.makedirs(os.path.join(directory, "scripts"))
        os.makedirs(os.path.join(directory, "docs", "routines"))
        with open(os.path.join(directory, "scripts", "inventory-config.json"), "w") as handle:
            handle.write('{"review_required": ["docs/routines/t2-*.md"]}')
        self.assertTrue(grade.needs_review(os.path.join(directory, "docs", "routines", "t2-a.md"), directory))
        self.assertFalse(grade.needs_review(os.path.join(directory, "docs", "routines", "r3.md"), directory))
        self.assertFalse(grade.needs_review(os.path.join(directory, "docs", "routines", "t2-a.md"),
                                            os.path.join(directory, "docs")))

    def test_a_routines_file_with_unread_bullet_headers_is_reported(self):
        # both shapes that once parsed to zero entries and passed
        text = ("- swfio_mount in `%s` at 0x1f80\n  %s\n\n- `swfio_umount` at 0x1fe0 in `%s`\n  %s\n"
                % (self.BINARY, self.ROLE, self.BINARY, self.ROLE))
        problems, out = self.lint(text, table=False, routines=True)
        self.assertEqual(problems, 2, out)
        self.assertIn(":5:", out)
        self.assertIn(":8:", out)
        self.assertIn("not an entry the parser reads", out)

    def test_a_kona_style_header_is_reported(self):
        text = "- `swfio_mount` (`%s` 0x1f80, 424 bytes):\n  %s\n" % (self.BINARY, self.ROLE)
        problems, out = self.lint(text, table=False, routines=True)
        self.assertEqual(problems, 1, out)
        self.assertIn(":5:", out)
        self.assertEqual(grade.parse_lines(text.split("\n")), [])   # --review-pack would see no entry
        self.assertEqual([n for n, _ in grade.unread_entries(text.split("\n"))], [1])  # the line is the first

    def test_a_prose_bullet_with_a_bare_name_and_address_is_not_a_header(self):
        text = ("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n\n- swfio_umount, at 0x1fe0. A leaf.\n"
                % (self.BINARY, self.ROLE))
        problems, out = self.lint(text, table=False, routines=True)
        self.assertEqual(problems, 0, out)

    def test_the_same_file_is_not_checked_unless_it_is_a_routines_file(self):
        problems, out = self.lint("- swfio_mount in `%s` at 0x1f80\n  %s\n" % (self.BINARY, self.ROLE), table=False)
        self.assertEqual(problems, 0, out)

    def test_an_unread_header_beside_a_read_one_is_reported(self):
        text = ("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n- swfio_umount in `%s` at 0x1fe0\n  %s\n"
                % (self.BINARY, self.ROLE, self.BINARY, self.ROLE))
        problems, out = self.lint(text, table=False, routines=True)
        self.assertEqual(problems, 1, out)
        self.assertIn(":7:", out)

    def test_a_routines_file_with_every_header_read_has_no_problem(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n" % (self.BINARY, self.ROLE),
                                  table=False, routines=True)
        self.assertEqual(problems, 0, out)

    def test_an_empty_routines_file_is_reported(self):
        for text in ("", "\n \n"):
            problems, out = self.lint(text, table=False, routines=True, intro=False)
            self.assertEqual(problems, 1, out)
            self.assertIn("empty", out)

    def test_a_routines_file_with_no_entry_is_reported(self):
        problems, out = self.lint("Notes with no entries.\n", table=False, routines=True, intro=False)
        self.assertEqual(problems, 1, out)
        self.assertIn("no entry the parser reads", out)

    def test_a_listing_in_a_code_fence_is_not_an_unread_header(self):
        text = ("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n\n```\n- swfio_umount in x at 0x1fe0\n```\n"
                % (self.BINARY, self.ROLE))
        problems, out = self.lint(text, table=False, routines=True)
        self.assertEqual(problems, 0, out)

    def test_routines_file_is_read_from_the_config_or_the_directory(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory)
        os.makedirs(os.path.join(directory, "scripts"))
        with open(os.path.join(directory, "scripts", "inventory-config.json"), "w") as handle:
            handle.write('{"review_required": ["notes/t2-*.md"]}')
        for rel, expect in (("docs/routines/r3.md", True), ("notes/t2-a.md", True), ("notes/other.md", False)):
            self.assertEqual(grade.is_routines_file(os.path.join(directory, rel), directory), expect, rel)

    def test_a_heading_with_a_paragraph_has_no_problem(self):
        problems, out = self.lint("### `swfio_mount` in `%s` at 0x1f80\n\n%s\n\nGrade: inferred.\n"
                                  % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 0, out)

    def test_a_heading_without_an_address_is_reported(self):
        problems, out = self.lint("### `swfio_mount` in `%s`\n\n%s\n" % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 1)
        self.assertIn("no exact address", out)

    def test_a_heading_with_an_address_and_no_binary_is_reported(self):
        problems, out = self.lint("### `swfio_mount` at 0x1f80\n\n%s\n" % self.ROLE)
        self.assertEqual(problems, 1)
        self.assertIn("no binary", out)

    def test_a_file_at_address_colon_routine_item_is_reported(self):
        problems, out = self.lint("- swfs.o at 0x1f80: swfio_mount\n\n  %s\n" % self.ROLE)
        self.assertEqual(problems, 1, out)
        self.assertIn("not an entry the inventory reads", out)

    def test_a_section_title_is_not_a_header(self):
        problems, out = self.lint("## Scope\n\nSome words about the batch.\n")
        self.assertEqual(problems, 0, out)

    def test_a_heading_that_names_no_routine_is_reported(self):
        problems, out = self.lint("### `%s` at 0x1f80\n\n12 bytes are copied in. Grade: inferred.\n" % self.BINARY)
        self.assertEqual(problems, 1)
        self.assertIn("names no routine", out)

    def test_an_entry_that_states_no_role_is_reported_with_the_reason(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** Mounts the filesystem.\n"
                                  % self.BINARY)
        self.assertEqual(problems, 1)
        self.assertIn("named-only", out)
        self.assertIn("role words", out)

    def test_an_entry_held_at_located_by_its_own_words_is_a_note_not_a_problem(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s The 0xe is not confirmed.\n"
                                  % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 0, out)
        self.assertIn("(note)", out)
        self.assertIn("located=1", out)

    def test_a_header_that_is_not_a_row_of_the_table_is_reported(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f84\n  **Inferred.** %s\n" % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 1)
        self.assertIn("no row of the functions table", out)

    def test_a_bare_file_name_over_builds_with_different_code_is_reported(self):
        problems, out = self.lint("- `swfio_mount` in `swfs.o` at 0x1f80\n  **Inferred.** %s\n" % self.ROLE,
                                  rows=[(self.BINARY, "0x1f80", "aa"), (self.OTHER, "0x1f80", "bb")])
        self.assertEqual(problems, 1)
        self.assertIn("full path", out)

    def test_a_bare_file_name_the_routine_shares_one_code_over_is_held_at_located_only_if_code_differs(self):
        rows = [(self.BINARY, "0x1f80", "aa"), (self.OTHER, "0x1f80", "aa")]
        problems, out = self.lint("- `swfio_mount` in `swfs.o` at 0x1f80\n  **Inferred.** %s\n" % self.ROLE, rows=rows)
        self.assertEqual(problems, 0, out)

    def test_without_a_table_only_the_entry_is_checked(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f84\n  **Inferred.** %s\n" % (self.BINARY, self.ROLE),
                                  table=False)
        self.assertEqual(problems, 0, out)

    def test_main_exits_nonzero_when_it_reports_something(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory)
        doc = os.path.join(directory, "b.md")
        with open(doc, "w", encoding="utf-8") as handle:
            handle.write("### `swfio_mount` at 0x1f80\n\n%s\n" % self.ROLE)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(grade.main([doc, "--check-doc", "--inventory", os.path.join(directory, "none.tsv")]), 1)


class CheckFacts(unittest.TestCase):
    """--check-facts: the claims of each entry against the facts of its routine."""
    ENTRY = ("- `r` in `lib.so` at 0x10\n  **Inferred.** Calls f (0x900) at 0x18 with the constant 0xb4 as "
             "its fifth argument (a4).\n\n")

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.directory)
        os.mkdir(os.path.join(self.directory, "root"))
        open(os.path.join(self.directory, "root", "lib.so"), "w").close()
        self.root = os.path.join(self.directory, "root")
        self.doc = os.path.join(self.directory, "b.md")

    def sheet(self):
        return fact_check.FactSheet(
            abi="n32", calls={"0x18": {"callee": "f", "target": "0x900", "args": {3: "0xb4"}, "tail": False}})

    def run_facts(self, text, table=None, sheet=None):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + text)
        path = None
        if table:
            path = os.path.join(self.directory, "functions.tsv")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("binary\tabi\taddress\tsize\tname\n" + table)
        out = io.StringIO()
        with mock.patch.object(fact_check, "sheet_for", return_value=sheet or self.sheet()) as patched:
            reported = grade.check_facts(self.doc, self.root, path, out)
        return reported, out.getvalue(), patched

    def test_a_missing_python_module_or_binutils_stops_the_run_instead_of_counting_no_facts(self):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + self.ENTRY)
        for error in (ModuleNotFoundError("No module named 'capstone'"),
                      grade.toolchain.MissingTool("no MIPS objdump found on PATH")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(fact_check, "sheet_for", side_effect=error):
                    with self.assertRaises(SystemExit) as caught:
                        grade.check_facts(self.doc, self.root, None, io.StringIO())
                self.assertIn("cannot render facts", str(caught.exception))

    def test_an_address_the_facts_cannot_place_is_still_counted_as_no_facts(self):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + self.ENTRY)
        out = io.StringIO()
        with mock.patch.object(fact_check, "sheet_for", side_effect=SystemExit("facts: no member")):
            grade.check_facts(self.doc, self.root, None, out)
        self.assertIn("checked=0 not-mips=0 no-facts=1", out.getvalue())

    def test_a_contradicted_claim_is_reported_with_its_line_rule_and_reason(self):
        reported, out, _patched = self.run_facts(self.ENTRY)
        self.assertEqual(reported, 1)
        self.assertIn("b.md:3: r [arg-slot]", out)
        self.assertIn("passes it in a3", out)
        self.assertIn("checked=1 not-mips=0 no-facts=0 reported=1", out)

    def test_an_entry_the_facts_agree_with_is_not_reported(self):
        reported, out, _patched = self.run_facts(self.ENTRY.replace("fifth argument (a4)", "fourth argument (a3)"))
        self.assertEqual(reported, 0, out)

    def test_the_size_comes_from_the_functions_table_when_the_header_has_none(self):
        _r, _out, patched = self.run_facts(self.ENTRY, table="lib.so\tn32\t0x10\t52\tr\n")
        self.assertEqual(patched.call_args.args, (os.path.join(self.root, "lib.so"), None, "0x10", 52))

    def test_an_entry_the_table_says_is_not_mips_nor_firmware_with_facts_is_skipped(self):
        reported, out, patched = self.run_facts(self.ENTRY, table="lib.so\tarm\t0x10\t52\tr\n")
        self.assertEqual(reported, 0)
        patched.assert_not_called()
        self.assertIn("checked=0 not-mips=1", out)

    def test_an_entry_whose_binary_is_missing_is_counted_not_fatal(self):
        os.remove(os.path.join(self.root, "lib.so"))
        reported, out, _patched = self.run_facts(self.ENTRY.replace("lib.so", "gone.so"))
        self.assertEqual(reported, 0)
        self.assertIn("no-facts=1", out)

    CITED = ("- `r` in `lib.so` at 0x10\n  **Inferred.** Calls f with a4 = 0xb4 [call 1].\n"
             "  Role (from facts): a wrapper for f [call 1].\n\n")

    def run_strict(self, text):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + text)
        out = io.StringIO()
        with mock.patch.object(fact_check, "sheet_for", return_value=self.sheet_with_a4()):
            reported = grade.check_facts(self.doc, self.root, None, out, strict=True)
        return reported, out.getvalue()

    def sheet_with_a4(self):
        return fact_check.FactSheet(
            abi="n32", calls={"0x18": {"callee": "f", "target": "0x900", "args": {4: "0xb4"}, "tail": False}},
            returns={}, blocks=[])

    def test_strict_citations_accept_a_fully_cited_entry(self):
        reported, out = self.run_strict(self.CITED)
        self.assertEqual(reported, 0, out)

    def test_strict_citations_report_an_uncited_fact_and_a_wrong_slot(self):
        reported, out = self.run_strict(self.CITED.replace("a4 = 0xb4 [call 1]", "a3 = 0xb4 [call 1]. It stores a word"))
        self.assertEqual(reported, 1)
        self.assertIn("[cite-arg]", out)
        self.assertIn("[uncited]", out)

    def test_strict_citations_print_a_role_from_the_name_as_a_note_that_does_not_count(self):
        reported, out = self.run_strict(self.CITED.replace("Role (from facts)", "Role (from name)"))
        self.assertEqual(reported, 0, out)
        self.assertIn("[role-from-name] (note)", out)

    def test_a_reviewed_line_is_not_read_as_a_claim(self):
        reported, out = self.run_strict(self.CITED.replace("\n\n", "\n  Reviewed: 2026-11-12\n\n"))
        self.assertEqual(reported, 0, out)

    def test_without_the_flag_an_uncited_sentence_is_not_reported(self):
        reported, out, _patched = self.run_facts(self.CITED.replace("[call 1].\n  Role", "[call 1]. It stores a word.\n  Role"),
                                                 sheet=self.sheet_with_a4())
        self.assertEqual(reported, 0, out)

    def test_strict_citations_need_check_facts(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            grade.main([self.doc, "--check-doc", "--strict-citations"])

    def test_check_facts_needs_check_doc(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            grade.main([self.doc, "--check-facts"])


class ReviewPack(unittest.TestCase):
    """--review-pack: each entry beside its rendered facts and the checker's findings."""
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.directory)
        os.mkdir(os.path.join(self.directory, "root"))
        open(os.path.join(self.directory, "root", "lib.so"), "w").close()
        self.root = os.path.join(self.directory, "root")
        self.doc = os.path.join(self.directory, "b.md")
        self.out = os.path.join(self.directory, "pack.md")

    def sheet(self):
        return fact_check.FactSheet(
            abi="n32", calls={"0x18": {"callee": "f", "target": "0x900", "args": {0: "0x4", 4: "0xb4"}, "tail": False}},
            branches={"0x8": {"mn": "beq", "target": "0x1c", "taken": "a0 == 0", "fall": "a0 != 0"}},
            returns={"0x24": "ret(f)"},
            accesses=[{"address": "0x4", "kind": "load", "mn": "lw", "offset": 0x30}],
            blocks=[{"first": 0, "last": 12, "succ": [2, 1], "reached": True, "branch": "0x8"},
                    {"first": 16, "last": 28, "succ": [2], "reached": True},
                    {"first": 32, "last": 36, "succ": [], "reached": True}])

    GOOD = ("- `r` in `lib.so` at 0x10\n  **Inferred.** Calls f with a0 = 0x4 [call 1, @0x8 fall].\n"
            "  Role (from facts): a wrapper for f [call 1, @0x8 fall].\n\n")
    BAD = ("- `s` in `lib.so` at 0x10\n  **Inferred.** Calls f with 0xb4 as its fourth argument [call 1, @0x8 fall].\n"
           "  Role (from facts): a wrapper for f [call 1, @0x8 fall].\n\n")
    PLAIN = "- `p` in `lib.so` at 0x10\n  **Inferred.** Reads +0x30 at 0x4.\n\n"

    def pack(self, text, **kwargs):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + text)
        with mock.patch.object(fact_check, "sheet_for", return_value=self.sheet()):
            count = grade.review_pack(self.doc, self.root, None, self.out, **kwargs)
        with open(self.out, encoding="utf-8") as handle:
            return count, handle.read()

    def test_an_entry_is_written_beside_its_facts_with_the_call_numbers(self):
        count, text = self.pack(self.GOOD)
        self.assertEqual(count, 1)
        self.assertIn("## r@0x10@lib.so", text)
        row = [l for l in text.splitlines() if "Calls f with a0 = 0x4" in l][0]
        self.assertIn(" | ", row)
        self.assertIn("call 1   @0x18  f [0x900]  a0=0x4 a4=0xb4", text)
        self.assertIn("branch   @0x8  beq -> 0x1c  taken: a0 == 0 | fall: a0 != 0", text)
        self.assertIn("0 findings", text)

    def test_the_findings_of_a_cited_entry_are_listed_with_their_sentence(self):
        _count, text = self.pack(self.BAD)
        self.assertIn("- [cite-arg]", text)
        self.assertIn("a4, the fifth argument", text)
        self.assertIn("  in: Calls f with 0xb4 as its fourth argument", text)

    def test_an_entry_without_citations_is_checked_by_the_prose_rules(self):
        _count, text = self.pack(self.PLAIN)
        self.assertNotIn("[uncited]", text)
        self.assertIn("load     @0x4  lw +0x30", text)

    def test_a_routine_an_unreviewed_filter_and_a_batch_choose_the_entries(self):
        both = self.GOOD + self.BAD.replace("`s`", "`t`") + self.GOOD.replace("`r`", "`u`").replace(
            "[call 1, @0x8 fall].\n\n", "[call 1, @0x8 fall].\n  Reviewed: 2026-11-12\n\n")
        self.assertEqual(self.pack(both)[0], 3)
        self.assertEqual(self.pack(both, routines=["t"])[0], 1)
        self.assertEqual(self.pack(both, unreviewed=True)[0], 2)
        count, text = self.pack(both, batch=(2, 2))
        self.assertEqual(count, 1)
        self.assertIn("## u@", text)

    def test_an_entry_whose_facts_cannot_be_built_says_why(self):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + self.GOOD)
        with mock.patch.object(fact_check, "sheet_for", side_effect=SystemExit("no such routine")):
            grade.review_pack(self.doc, self.root, None, self.out)
        with open(self.out, encoding="utf-8") as handle:
            self.assertIn("no facts: no such routine", handle.read())

    def test_main_writes_the_pack_and_reports_the_count(self):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + self.GOOD)
        out = io.StringIO()
        with mock.patch.object(fact_check, "sheet_for", return_value=self.sheet()), contextlib.redirect_stdout(out):
            code = grade.main([self.doc, "--review-pack", self.out, "--root", self.root, "--inventory", "none.tsv"])
        self.assertEqual(code, 0)
        self.assertIn("1 entries written", out.getvalue())
        self.assertTrue(os.path.isfile(self.out))


def have_capstone():
    try:
        import capstone  # noqa: F401
        import elftools  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(have_capstone(), "needs capstone and pyelftools")
class FirmwareFacts(unittest.TestCase):
    """--check-facts and --review-pack on PowerPC and ColdFire entries, rendered from the layout's segment."""
    PPC = ("2c030000" "41820010" "38800010" "48000ff5" "60000000" "80060030" "90060034" "4e800020")
    CF = ("4e560000" "203910000014" "4a80" "6706" "4eb900004000" "23c010000018" "4e5e" "4e75")
    L2 = "fw/l2.bin(flash)"
    L1 = "fw/l1.bin(l1#0)"
    # flash at 0xfe000000: beq at 0xfe000004 skips the bl at 0xfe00000c; L1 code at 0xffe00008: jsr at 0xffe00016
    PPC_ENTRY = ("- `p` in `%s` at 0xfe000000\n  **Inferred.** It calls the routine at 0xfe00000c only when r3 is %s.\n\n")
    CF_ENTRY = ("- `c` in `%s` at 0xffe00008\n  **Inferred.** It calls the routine at 0xffe00016 only when the word at "
                "0x10000014 is %s.\n\n")
    TABLE = ("binary\tabi\taddress\tsize\tname\n"
             "fw/l2.bin(flash)\tppc32\t0xfe000000\t32\tp\n"
             "fw/l1.bin(l1#0)\tcoldfire\t0xffe00008\t30\tc\n")

    def setUp(self):
        import json
        import test_firmware_layout as fl
        self.directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.directory)
        self.root = os.path.join(self.directory, "root")
        fl.write_root(self.root, {"fw/l1.bin": fl.l1_container(bytes.fromhex(self.CF)),
                                  "fw/l2.bin": fl.l2_container(bytes.fromhex(self.PPC), b"")})
        os.mkdir(os.path.join(self.directory, "scripts"))
        with open(os.path.join(self.directory, "scripts", "inventory-config.json"), "w") as handle:
            json.dump(fl.CONFIG, handle)
        self.doc = os.path.join(self.directory, "b.md")
        self.table = os.path.join(self.directory, "functions.tsv")
        with open(self.table, "w") as handle:
            handle.write(self.TABLE)
        self.out = os.path.join(self.directory, "pack.md")

    def facts(self, text, strict=False):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + text)
        out = io.StringIO()
        reported = grade.check_facts(self.doc, self.root, self.table, out, strict=strict)
        return reported, out.getvalue()

    def test_a_powerpc_claim_is_tested_against_the_segment_it_names(self):
        reported, out = self.facts(self.PPC_ENTRY % (self.L2, "zero"))
        self.assertEqual(reported, 1, out)
        self.assertIn("p [branch-direction]", out)
        self.assertIn("checked=1 not-mips=0 no-facts=0 reported=1", out)

    def test_a_powerpc_claim_the_facts_agree_with_is_not_reported(self):
        reported, out = self.facts(self.PPC_ENTRY % (self.L2, "nonzero"))
        self.assertEqual(reported, 0, out)
        self.assertIn("checked=1", out)

    def test_a_coldfire_claim_is_tested_against_the_segment_it_names(self):
        reported, out = self.facts(self.CF_ENTRY % (self.L1, "zero"))
        self.assertEqual(reported, 1, out)
        self.assertIn("c [branch-direction]", out)
        reported, out = self.facts(self.CF_ENTRY % (self.L1, "nonzero"))
        self.assertEqual(reported, 0, out)

    def test_the_architecture_line_stands_in_for_the_table_row(self):
        text = (self.PPC_ENTRY % (self.L2, "zero")).replace(
            "\n  **Inferred.**", "\n  Range: 0xfe000000-0xfe000020 (32 bytes).\n  Architecture: ppc32, load 0xfe000000, offset 0x0.\n  **Inferred.**")
        os.remove(self.table)
        self.assertEqual(self.facts(text)[0], 1)

    def test_a_firmware_entry_in_no_layout_group_is_counted_as_no_facts(self):
        reported, out = self.facts((self.PPC_ENTRY % ("fw/other.bin", "zero")))
        self.assertEqual(reported, 0)
        self.assertIn("checked=0 not-mips=0 no-facts=1", out)

    def test_strict_citations_run_on_firmware_facts(self):
        text = ("- `p` in `%s` at 0xfe000000\n  **Inferred.** Calls 0xfe001000 with r4 = 0x20 [call 1, @0xfe000004 fall].\n"
                "  Role (from facts): a stub [call 1].\n\n" % self.L2)
        reported, out = self.facts(text, strict=True)
        self.assertEqual(reported, 1, out)
        self.assertIn("[cite-arg]", out)
        reported, out = self.facts(text.replace("0x20", "0x10"), strict=True)
        self.assertEqual(reported, 0, out)

    def test_the_review_pack_lists_the_numbered_facts_of_a_firmware_entry(self):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + (self.PPC_ENTRY % (self.L2, "zero")) + (self.CF_ENTRY % (self.L1, "zero")))
        self.assertEqual(grade.review_pack(self.doc, self.root, self.table, self.out), 2)
        with open(self.out, encoding="utf-8") as handle:
            pack = handle.read()
        self.assertIn("call 1   @0xfe00000c  (unnamed) [0xfe001000]  r3=r3 at entry r4=0x10", pack)
        self.assertIn("branch   @0xfe000004  beq -> 0xfe000014  taken: r3 == 0x0 | fall: r3 != 0x0", pack)
        self.assertIn("call 1   @0xffe00016  (unnamed) [0x4000]", pack)
        self.assertNotIn("not MIPS", pack)
        self.assertIn("[branch-direction]", pack)


class ApplyVerdicts(unittest.TestCase):
    """--apply-verdicts: a reviewer's verdicts written back into the routine-role file."""
    DOC = ("# Readings\n\nIntro.\n\n"
           "- `a` in `lib.so` at 0x10\n  **Inferred.** Calls f [call 1].\n  Role (from facts): a wrapper [call 1].\n\n"
           "- `b` in `lib.so` at 0x20\n  **Inferred.** Calls g [call 1].\n  Role (from facts): a wrapper [call 1].\n\n"
           "- `c` in `lib.so` at 0x30\n  **Inferred.** Calls h [call 1].\n  Reviewed: 2026-01-01\n\nTail text.\n")

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.directory)
        self.doc = os.path.join(self.directory, "b.md")
        self.verdicts = os.path.join(self.directory, "v.json")

    def apply(self, verdicts, doc=None):
        import json
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write(doc or self.DOC)
        with open(self.verdicts, "w", encoding="utf-8") as handle:
            json.dump(verdicts, handle)
        out = io.StringIO()
        try:
            counts = grade.apply_verdicts(self.doc, self.verdicts, "2026-11-12", out)
        except SystemExit:
            counts = None
        with open(self.doc, encoding="utf-8") as handle:
            return counts, handle.read(), out.getvalue()

    def test_ok_keeps_the_entry_and_adds_the_marker(self):
        counts, text, _out = self.apply({"a@0x10@lib.so": {"verdict": "ok"}})
        self.assertEqual(counts["ok"], 1)
        self.assertIn("  Role (from facts): a wrapper [call 1].\n  Reviewed: 2026-11-12\n\n- `b`", text)

    def test_fixed_replaces_the_lines_under_the_header_and_adds_the_marker(self):
        _c, text, _out = self.apply({"b@0x20@lib.so": {
            "verdict": "fixed", "reviewer": "sonnet",
            "text": "**Inferred.** Calls g [call 1].\nRole (from name): a wrapper."}})
        self.assertIn("- `b` in `lib.so` at 0x20\n  **Inferred.** Calls g [call 1].\n  Role (from name): a wrapper.\n"
                      "  Reviewed: 2026-11-12\n\n- `c`", text)
        self.assertNotIn("Role (from facts): a wrapper [call 1].\n  Reviewed: 2026-11-12", text)
        self.assertNotIn("sonnet", text)

    def test_reject_changes_nothing(self):
        counts, text, _out = self.apply({"a@0x10@lib.so": {"verdict": "reject"}})
        self.assertEqual(counts["reject"], 1)
        self.assertEqual(text, self.DOC)

    def test_an_older_marker_is_replaced_not_repeated(self):
        _c, text, _out = self.apply({"c@0x30@lib.so": {"verdict": "ok"}})
        self.assertEqual(text.count("Reviewed:"), 1)
        self.assertIn("Reviewed: 2026-11-12\n\nTail text.", text)

    def test_an_older_marker_with_a_reviewer_suffix_is_still_read_and_replaced(self):
        doc = self.DOC.replace("Reviewed: 2026-01-01", "Reviewed: 2026-01-01 (sonnet)")
        _c, text, _out = self.apply({"c@0x30@lib.so": {"verdict": "ok", "reviewer": "opus"}}, doc)
        self.assertEqual(text.count("Reviewed:"), 1)
        self.assertIn("Reviewed: 2026-11-12\n\nTail text.", text)
        self.assertNotIn("sonnet", text)
        self.assertNotIn("opus", text)

    def test_several_verdicts_apply_without_disturbing_each_other_or_the_text_around_them(self):
        counts, text, out = self.apply({"a@0x10@lib.so": {"verdict": "ok"}, "b@0x20@lib.so": {
            "verdict": "fixed", "text": "  **Inferred.** Calls g [call 1]."}, "c@0x30@lib.so": {"verdict": "ok"}})
        self.assertEqual(dict(counts), {"ok": 2, "fixed": 1})
        self.assertEqual(text.count("Reviewed: 2026-11-12"), 3)
        self.assertTrue(text.startswith("# Readings\n\nIntro.\n\n- `a`") and text.endswith("Tail text.\n"))
        self.assertIn("verdicts: ok=2 fixed=1 reject=0", out)

    def test_a_wrong_key_verdict_or_empty_fix_stops_the_run_before_anything_is_written(self):
        for verdicts in ({"nope@0x1@lib.so": {"verdict": "ok"}}, {"a@0x10@lib.so": {"verdict": "maybe"}},
                         {"a@0x10@lib.so": {"verdict": "fixed", "text": " "}},
                         {"a@0x10@lib.so": {"verdict": "ok"}, "zz@0x1@lib.so": {"verdict": "ok"}}):
            counts, text, out = self.apply(verdicts)
            self.assertIsNone(counts)
            self.assertEqual(text, self.DOC)
            self.assertTrue(out)

    def test_a_reviewed_entry_then_counts_as_understood_in_a_file_that_requires_review(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inventory", os.path.join(os.path.dirname(grade.__file__), "inventory.py"))
        inv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inv)
        doc = ("- `swfio_mount` in `sw22_474-ip30-flame834/var/sysgen/boot/swfs.o` at 0x1f80\n"
               "  **Inferred.** Copies a 12-byte block in at 0x1f9c and calls `swf_mount_fs` at 0x2080. The\n"
               "  return is the constant 0xe or the mount result at 0x2084.\n")
        key = "swfio_mount@0x1f80@sw22_474-ip30-flame834/var/sysgen/boot/swfs.o"
        _c, text, _o = self.apply({key: {"verdict": "ok"}}, doc=doc)
        root = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, root)
        os.makedirs(os.path.join(root, "docs", "routines"))
        for name, body in (("before.md", doc), ("after.md", text)):
            with open(os.path.join(root, "docs", "routines", name), "w") as handle:
                handle.write(body)
        levels = {}
        for name in ("before.md", "after.md"):
            saved, inv.REPO = inv.REPO, root
            try:
                index = inv.DocIndex({"docs": {"prose": ["docs/routines/%s" % name], "index": [], "skip": []},
                                      "review_required": ["docs/routines/*.md"]})
            finally:
                inv.REPO = saved
            levels[name] = [e.level for e in index.entries]
        self.assertEqual(levels, {"before.md": ["located"], "after.md": ["understood"]})


class InventoryShapes(unittest.TestCase):
    """The entry shapes the inventory credits (README-analysis.md, "Routine role entries") are packed,
    fact-checked and verdict-applied like a bullet: a heading that gives the binary and address, with a
    paragraph that opens with the routine, and a header-only bullet whose paragraph follows a blank line."""
    ROLE = "**Inferred.** Calls f with a0 = 0x4 [call 1, @0x8 fall].\nRole (from facts): a wrapper for f [call 1, @0x8 fall]."
    HEAD = "### lib.so at 0x10\n\n`r`, 52 bytes. " + ROLE + "\n\n"
    NAMED_HEAD = "### `r` in `usr/lib/lib.so` at 0x10\n\n" + ROLE + "\n\n"
    LIST = "- `r` in `lib.so` at 0x10\n\n  " + ROLE.replace("\n", "\n  ") + "\n\n"
    SHAPES = (("head", HEAD), ("named head", NAMED_HEAD), ("list", LIST))

    @classmethod
    def shapes(cls, role):
        return tuple((label, text.replace(cls.ROLE, role).replace(cls.ROLE.replace("\n", "\n  "), role.replace("\n", "\n  ")))
                     for label, text in cls.SHAPES)

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.directory)
        os.makedirs(os.path.join(self.directory, "root", "usr", "lib"))
        for name in ("lib.so", os.path.join("usr", "lib", "lib.so")):
            open(os.path.join(self.directory, "root", name), "w").close()
        self.root = os.path.join(self.directory, "root")
        self.doc = os.path.join(self.directory, "b.md")
        self.out = os.path.join(self.directory, "pack.md")
        self.verdicts = os.path.join(self.directory, "v.json")

    def write(self, text):
        with open(self.doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\n" + text + "## Tail\n\nProse.\n")

    def read(self):
        with open(self.doc, encoding="utf-8") as handle:
            return handle.read()

    def sheet(self):
        return fact_check.FactSheet(
            abi="n32", calls={"0x18": {"callee": "f", "target": "0x900", "args": {0: "0x4"}, "tail": False}},
            branches={"0x8": {"mn": "beq", "target": "0x1c", "taken": "a0 == 0", "fall": "a0 != 0"}})

    def apply(self, verdicts):
        import json
        with open(self.verdicts, "w", encoding="utf-8") as handle:
            json.dump(verdicts, handle)
        return grade.apply_verdicts(self.doc, self.verdicts, "2026-11-12", io.StringIO())

    def test_parse_reads_the_binary_address_name_and_role_of_each_shape(self):
        for label, text in self.SHAPES:
            self.write(text)
            (entry,) = grade.parse_entries(self.doc)
            with self.subTest(label):
                self.assertEqual((entry["name"], entry["address"], entry["install"]),
                                 ("r", "0x10", "usr/lib/lib.so" if "named" in label else "lib.so"))
                self.assertEqual(len(entry["sentences"]), 2)
                self.assertTrue(entry["sentences"][-1].startswith("Role (from facts)"))
                self.assertEqual(entry["shape"], "list" if label == "list" else "head")
                self.assertEqual(self.read().splitlines()[entry["end"] - 1][:4], "Role" if label != "list" else "  Ro")

    def test_a_heading_without_a_binary_or_a_routine_is_not_an_entry(self):
        for heading in ("### Calls at 0x10\n\n`r` does things.\n", "### lib.so at 0x10\n\nIt calls f.\n"):
            self.write(heading)
            self.assertEqual(grade.parse_entries(self.doc), [])

    def test_a_bullet_whose_header_has_text_still_ends_at_a_blank_line(self):
        self.write("- `r` in `lib.so` at 0x10 (n32).\n  It occupies 8 bytes.\n\n  Not part of it.\n\n")
        (entry,) = grade.parse_entries(self.doc)
        self.assertEqual(entry["sentences"], ["It occupies 8 bytes."])

    def test_a_listing_in_a_fence_is_not_an_entry(self):
        self.write("```\n- `r` in `lib.so` at 0x10\n  Calls f.\n```\n")
        self.assertEqual(grade.parse_entries(self.doc), [])

    def test_the_pack_holds_each_shape_beside_its_facts(self):
        for label, text in self.SHAPES:
            self.write(text)
            with mock.patch.object(fact_check, "sheet_for", return_value=self.sheet()):
                count = grade.review_pack(self.doc, self.root, None, self.out)
            with open(self.out, encoding="utf-8") as handle:
                pack = handle.read()
            with self.subTest(label):
                self.assertEqual(count, 1)
                self.assertIn("## r@0x10@", pack)
                self.assertIn("call 1   @0x18  f [0x900]  a0=0x4", pack)
                self.assertIn("0 findings", pack)

    def test_the_fact_check_reads_each_shape(self):
        wrong = "**Inferred.** Calls f (0x900) at 0x18 with the constant 0xb4 as its fifth argument (a4)."
        sheet = fact_check.FactSheet(
            abi="n32", calls={"0x18": {"callee": "f", "target": "0x900", "args": {3: "0xb4"}, "tail": False}})
        for label, text in self.shapes(wrong):
            self.write(text)
            out = io.StringIO()
            with mock.patch.object(fact_check, "sheet_for", return_value=sheet):
                reported = grade.check_facts(self.doc, self.root, None, out)
            with self.subTest(label):
                self.assertEqual(reported, 1, out.getvalue())
                self.assertIn("[arg-slot]", out.getvalue())
                self.assertIn("checked=1", out.getvalue())

    def test_ok_marks_each_shape_reviewed_and_keeps_its_shape(self):
        for label, text in self.SHAPES:
            self.write(text)
            before = self.read()
            key = "r@0x10@" + ("usr/lib/lib.so" if "named" in label else "lib.so")
            self.assertEqual(self.apply({key: {"verdict": "ok", "reviewer": "x"}})["ok"], 1)
            after = self.read()
            with self.subTest(label):
                marker = "  Reviewed: 2026-11-12\n" if label == "list" else "\nReviewed: 2026-11-12\n"
                self.assertIn(marker, after)
                self.assertEqual(after.replace(marker, "\n" if label != "list" else "", 1).count("Reviewed"), 0)
                self.assertEqual(after.split("\n", 3)[2], before.split("\n", 3)[2])
                (entry,) = grade.parse_entries(self.doc)
                self.assertEqual(entry["shape"], "list" if label == "list" else "head")
                self.assertIn("## Tail\n\nProse.\n", after)

    def test_fixed_replaces_the_paragraphs_of_a_heading_and_keeps_the_heading(self):
        self.write(self.HEAD)
        self.apply({"r@0x10@lib.so": {"verdict": "fixed", "text": "`r`, 52 bytes. **Inferred.** A wrapper for f."}})
        self.assertIn("### lib.so at 0x10\n\n`r`, 52 bytes. **Inferred.** A wrapper for f.\n\nReviewed: 2026-11-12\n\n## Tail",
                      self.read())

    def test_fixed_indents_the_paragraph_of_a_header_only_bullet(self):
        self.write(self.LIST)
        self.apply({"r@0x10@lib.so": {"verdict": "fixed", "text": "**Inferred.** A wrapper for f.\n\nSecond."}})
        self.assertIn("- `r` in `lib.so` at 0x10\n  **Inferred.** A wrapper for f.\n\n  Second.\n  Reviewed: 2026-11-12\n\n## Tail",
                      self.read())

    def test_a_marked_entry_leaves_the_unreviewed_pack_and_applying_twice_keeps_one_marker(self):
        for label, text in self.SHAPES:
            self.write(text)
            key = "r@0x10@" + ("usr/lib/lib.so" if "named" in label else "lib.so")
            self.apply({key: {"verdict": "ok"}})
            self.apply({key: {"verdict": "ok"}})
            with mock.patch.object(fact_check, "sheet_for", return_value=self.sheet()):
                count = grade.review_pack(self.doc, self.root, None, self.out, unreviewed=True)
            with self.subTest(label):
                self.assertEqual(self.read().count("Reviewed:"), 1)
                self.assertEqual(count, 0)

    def test_a_reviewed_heading_entry_is_understood_in_a_file_that_requires_review(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inventory", os.path.join(os.path.dirname(grade.__file__), "inventory.py"))
        inv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inv)
        role = ("It copies a 12-byte block in at 0x1f9c and calls `swf_mount_fs` at 0x2080. The return is "
                "the constant 0xe or the mount result at 0x2084.")
        self.write("### `swfio_mount` in `a/b/swfs.o` at 0x1f80\n\n**Inferred.** " + role + "\n\n")
        self.apply({"swfio_mount@0x1f80@a/b/swfs.o": {"verdict": "ok"}})
        os.makedirs(os.path.join(self.directory, "docs", "routines"))
        os.replace(self.doc, os.path.join(self.directory, "docs", "routines", "b.md"))
        saved, inv.REPO = inv.REPO, self.directory
        try:
            index = inv.DocIndex({"docs": {"prose": ["docs/routines/b.md"], "index": [], "skip": []},
                                  "review_required": ["docs/routines/*.md"]})
        finally:
            inv.REPO = saved
        self.assertIn("understood", [e.level for e in index.entries])


if __name__ == "__main__":
    unittest.main()
