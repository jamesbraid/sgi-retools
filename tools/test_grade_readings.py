#!/usr/bin/env python3
"""Tests for the shared facts-only reading grader."""
import contextlib
import io
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

    def lint(self, text, table=True, rows=None):
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory)
        doc = os.path.join(directory, "b000.md")
        with open(doc, "w", encoding="utf-8") as handle:
            handle.write("# Readings\n\nIntro that names `swfio_mount` at 0x1f80 and is not an entry.\n\n" + text)
        path = None
        if table:
            path = os.path.join(directory, "functions.tsv")
            rows = rows or [(self.BINARY, "0x1f80", "aa"), (self.OTHER, "0x1fe0", "bb")]
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("binary\taddress\tname\tcode_sha\n")
                for binary, address, code in rows:
                    handle.write("%s\t%s\tswfio_mount\t%s\n" % (binary, address, code))
        out = io.StringIO()
        problems = grade.check_doc(doc, path, out)
        return problems, out.getvalue()

    def test_the_canonical_entry_has_no_problem(self):
        problems, out = self.lint("- `swfio_mount` in `%s` at 0x1f80\n  **Inferred.** %s\n" % (self.BINARY, self.ROLE))
        self.assertEqual(problems, 0, out)
        self.assertIn("understood=1", out)

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


if __name__ == "__main__":
    unittest.main()
