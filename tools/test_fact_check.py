#!/usr/bin/env python3
"""Tests for the mechanical fact check of routine-role entries."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fact_check as fc


def call(callee, target, args=None, tail=False):
    return {"callee": callee, "target": target, "args": args or {}, "tail": tail}


def block(first, last, succ, branch=None):
    entry = {"first": first, "last": last, "succ": succ, "reached": True}
    if branch:
        entry["branch"] = branch
    return entry


def guarded_call_sheet(site="0x10", callee="f", target="0x900", taken="at(=[0xece8bf0]) == 0",
                       fall="at(=[0xece8bf0]) != 0", args=None):
    """beq at 0x8 skips the call at site when the flag word is zero; both ways meet at the return."""
    return fc.FactSheet(
        name="r", abi="n32", text="",
        calls={site: call(callee, target, args or {0: "a0 at entry (arg0)"})},
        branches={"0x8": {"mn": "beq", "target": "0x18", "taken": taken, "fall": fall}},
        returns={"0x1c": "?"},
        blocks=[block(0x0, 0xc, [2, 1], "0x8"), block(0x10, 0x14, [2]), block(0x18, 0x1c, [])])


def rules(sentences, sheet):
    return sorted({rule for rule, _reason, _sentence in fc.check_entry(sentences, sheet)})


class Prose(unittest.TestCase):
    def test_sentences_drop_the_grade_marker_and_backticks(self):
        self.assertEqual(fc.sentences_of(["  **Inferred.** Calls `f` at 0x10. It then returns 0 (0x1c)."]),
                         ["Calls f at 0x10.", "It then returns 0 (0x1c)."])


class ArgumentSlots(unittest.TestCase):
    def sheet(self):
        return fc.FactSheet(abi="n64", calls={
            "0x20": call("pack", "0x900", {0: "0x1", 1: "a3 at entry (arg3)", 3: "0xec7ef90", 4: "0xb4"})})

    def test_a_fourth_argument_that_is_a4_is_reported_with_the_convention(self):
        found = fc.check_entry(["It packs a block with pack at 0x20, passing the constant 0xb4 as its fourth argument."],
                               self.sheet())
        self.assertEqual([rule for rule, _r, _s in found], ["arg-slot"])
        self.assertIn("a4, the fifth argument", found[0][1])
        self.assertIn("n64 passes the first eight arguments in a0-a7", found[0][1])

    def test_the_fifth_argument_that_is_a4_is_accepted(self):
        self.assertEqual(rules(["It calls pack at 0x20 with 0xb4 as its fifth argument (a4)."], self.sheet()), [])

    def test_an_ordinal_that_disagrees_with_its_register_is_reported(self):
        found = fc.check_entry(["It calls pack at 0x20 with 0xb4 as its fourth argument (a4)."], self.sheet())
        self.assertIn("arg-register", [rule for rule, _r, _s in found])

    def test_a_register_given_a_different_value_is_reported(self):
        self.assertEqual(rules(["It calls pack at 0x20 with a0 = 0x2 and a4 = 0xb4."], self.sheet()), ["arg-slot"])
        self.assertEqual(rules(["It calls pack at 0x20 with a0 = 1 and a4 = 0xb4."], self.sheet()), [])

    def test_a_small_value_in_another_slot_is_not_evidence(self):
        sheet = fc.FactSheet(abi="n64", calls={"0x20": call("pack", "0x900", {1: "0x0", 3: "?"})})
        self.assertEqual(rules(["It calls pack at 0x20 with a3 = 0x0."], sheet), [])

    def test_values_listed_against_calls_one_by_one_are_not_guessed_at(self):
        sheet = fc.FactSheet(abi="n64", calls={
            "0x20": call("f", "0x900", {3: "0x4"}), "0x30": call("f", "0x900", {3: "0x6"})})
        self.assertEqual(rules(["The calls at 0x20 and 0x30 pass 0x4 and 0x6 as their fourth argument."], sheet), [])

    def test_a_site_after_the_claim_narrows_it_to_that_call(self):
        sheet = fc.FactSheet(abi="n64", calls={
            "0x20": call("f", "0x900", {1: "0x1"}), "0x30": call("f", "0x900", {1: "0x0"})})
        self.assertEqual(rules(["It calls f with a1 of 1 at 0x20 and of 0 at 0x30."], sheet), [])
        self.assertEqual(rules(["It calls f with a1 = 5 (jal at 0x30)."], sheet), ["arg-slot"])

    def test_a_callee_the_sentence_does_not_name_is_not_guessed(self):
        self.assertEqual(rules(["It passes 0xb4 as its fourth argument."], self.sheet()), [])


class BranchDirection(unittest.TestCase):
    def test_a_clear_flag_that_the_branch_treats_as_set_is_reported(self):
        found = fc.check_entry(["Checks the flag at 0xece8bf0 and, when it is clear, calls f (0x900) first."],
                               guarded_call_sheet())
        self.assertEqual([rule for rule, _r, _s in found], ["branch-direction"])
        self.assertIn("!= 0", found[0][1])

    def test_a_set_flag_is_accepted(self):
        self.assertEqual(rules(["Checks the flag at 0xece8bf0 and, when it is set, calls f (0x900) first; a clear "
                                "flag skips that call."], guarded_call_sheet()), [])

    def test_the_condition_after_the_call_counts_too(self):
        self.assertEqual(rules(["It calls f at 0x10 only when the flag at 0xece8bf0 is zero."], guarded_call_sheet()),
                         ["branch-direction"])

    def test_unless_and_skips_reverse_the_word(self):
        sheet = guarded_call_sheet()
        self.assertEqual(rules(["It calls f at 0x10 unless the flag at 0xece8bf0 is zero."], sheet), [])
        self.assertEqual(rules(["It skips f at 0x10 when the flag at 0xece8bf0 is zero."], sheet), [])

    def test_a_condition_on_another_word_is_not_compared(self):
        self.assertEqual(rules(["When the flag at 0xece9000 is clear, it calls f (0x900)."], guarded_call_sheet()), [])

    def test_a_condition_on_a_result_is_not_a_flag(self):
        self.assertEqual(rules(["It calls f at 0x10 and returns 1 when that result is zero."], guarded_call_sheet()), [])

    def test_a_compound_condition_is_not_split(self):
        self.assertEqual(rules(["When the flag at 0xece8bf0 is clear and a1 allows it, it calls f at 0x10."],
                               guarded_call_sheet()), [])

    def test_a_register_inside_a_bracket_is_a_field_not_the_register(self):
        sheet = guarded_call_sheet(taken="v0(=[a0+114]:2) == 0", fall="v0(=[a0+114]:2) != 0")
        self.assertEqual(rules(["It calls f at 0x10 when a0 is zero."], sheet), [])
        sheet = guarded_call_sheet(taken="a0 == 0", fall="a0 != 0")
        self.assertEqual(rules(["It calls f at 0x10 when a0 is zero."], sheet), ["branch-direction"])


class CallOrder(unittest.TestCase):
    def sheet(self):
        """compile sits first in memory but runs second when the word is zero: insert, then compile."""
        return fc.FactSheet(
            calls={"0x10": call("compile", "0x900"), "0x30": call("insert", "0x910")},
            blocks=[block(0x0, 0xc, [2, 1], "0x8"), block(0x30, 0x34, [2]), block(0x10, 0x14, [])])

    def test_a_then_that_runs_the_other_way_is_reported(self):
        found = fc.check_entry(["It calls compile (0x900) with a stack buffer, then insert (0x910) with the table."],
                               self.sheet())
        self.assertEqual([rule for rule, _r, _s in found], ["call-order"])

    def test_the_order_the_facts_show_is_accepted(self):
        self.assertEqual(rules(["It calls insert (0x910), then falls into the compile (0x900) call."], self.sheet()), [])

    def test_after_and_before_are_read(self):
        self.assertEqual(rules(["It calls compile (0x900) after insert (0x910)."], self.sheet()), [])
        self.assertEqual(rules(["It calls compile (0x900) before insert (0x910)."], self.sheet()), ["call-order"])

    def test_calls_on_exclusive_paths_say_nothing_about_order(self):
        sheet = fc.FactSheet(calls={"0x10": call("a", "0x900"), "0x20": call("b", "0x910")},
                             blocks=[block(0x0, 0xc, [1, 2], "0x8"), block(0x10, 0x14, []), block(0x20, 0x24, [])])
        self.assertEqual(rules(["It calls a (0x900), then b (0x910)."], sheet), [])

    def test_a_then_that_belongs_to_another_action_is_not_a_call_order(self):
        text = "It calls compile (0x900), stores a word, then decrements the count with insert (0x910)."
        self.assertEqual(rules([text], self.sheet()), [])

    def test_a_returned_value_is_not_a_call(self):
        self.assertEqual(rules(["It calls insert (0x910) and stores ret(compile), then returns."], self.sheet()), [])

    def test_a_panic_is_not_a_step(self):
        sheet = fc.FactSheet(calls={"0x10": call("assfail", "0x900"), "0x30": call("splhi", "0x910")},
                             blocks=[block(0x0, 0xc, [2, 1], "0x8"), block(0x30, 0x34, [2]), block(0x10, 0x14, [])])
        self.assertEqual(rules(["It leads to assfail at 0x10, then splhi at 0x30."], sheet), [])


class ConditionalWording(unittest.TestCase):
    def test_unconditionally_over_a_guarded_call_is_reported(self):
        self.assertEqual(rules(["It unconditionally calls f at 0x10."], guarded_call_sheet()), ["conditional-wording"])

    def test_unconditionally_over_a_call_on_every_path_is_accepted(self):
        sheet = guarded_call_sheet(site="0x4")
        self.assertEqual(rules(["It unconditionally calls f at 0x4."], sheet), [])

    def test_the_otherwise_side_of_a_branch_cannot_hold_an_unguarded_store(self):
        sheet = guarded_call_sheet()
        sheet.accesses = [{"address": "0x4", "kind": "store", "mn": "sw", "offset": 0}]
        found = fc.check_entry(["When the flag is clear it calls f at 0x10; otherwise it stores a word at 0x4."], sheet)
        self.assertEqual([rule for rule, _r, _s in found], ["conditional-wording"])
        self.assertIn("every path", found[0][1])

    def test_a_flat_release_that_a_branch_skips_is_reported(self):
        sheet = guarded_call_sheet(callee="free", target="0x940")
        self.assertEqual(rules(["It then frees the buffer (0x10) and resets the pointer."], sheet),
                         ["conditional-wording"])

    def test_a_release_with_a_condition_is_accepted(self):
        sheet = guarded_call_sheet(callee="free", target="0x940")
        self.assertEqual(rules(["It then frees the buffer (0x10) unless it is null."], sheet), [])

    def test_a_release_the_entry_ties_to_its_branch_is_accepted(self):
        sheet = guarded_call_sheet(callee="free", target="0x940")
        self.assertEqual(rules(["It frees the buffer (0x10).", "The beq at 0x8 skips it for a null buffer."], sheet), [])

    def test_other_flat_calls_are_left_alone(self):
        self.assertEqual(rules(["It then calls f (0x10) and resets the pointer."], guarded_call_sheet()), [])


class Graph(unittest.TestCase):
    def test_a_call_in_the_entry_block_is_never_guarded(self):
        self.assertFalse(guarded_call_sheet().guarded("0x4"))

    def test_a_block_a_branch_can_skip_is_guarded_and_optional(self):
        sheet = guarded_call_sheet()
        self.assertTrue(sheet.guarded("0x10"))
        self.assertTrue(sheet.optional("0x10"))
        self.assertEqual(sheet.deciding("0x10"), [("0x8", "fall")])

    def test_a_call_on_one_of_two_exits_is_guarded_but_not_optional(self):
        sheet = fc.FactSheet(blocks=[block(0x0, 0xc, [1, 2], "0x8"), block(0x10, 0x14, []), block(0x20, 0x24, [])])
        self.assertTrue(sheet.guarded("0x10"))
        self.assertFalse(sheet.optional("0x10"))

    def test_a_block_no_path_reaches_is_not_an_exit(self):
        sheet = fc.FactSheet(blocks=[block(0x0, 0xc, [1, 2], "0x8"), block(0x10, 0x14, [2]), dict(
            block(0x20, 0x24, []), reached=False)])
        sheet.blocks[0]["succ"] = [1]
        self.assertFalse(sheet.guarded("0x10"))

    def test_a_sheet_round_trips_through_json(self):
        sheet = guarded_call_sheet()
        again = fc.FactSheet.from_dict(json.loads(json.dumps(sheet.to_dict())))
        self.assertEqual(again.calls, sheet.calls)
        self.assertEqual(again.deciding("0x10"), sheet.deciding("0x10"))


class RenderedFacts(unittest.TestCase):
    RENDERED = """- `r` in `lib.so` at 0x10 (n32).
  Evidence grade: inferred.
  The `jalr` at 0x20 calls f [0x900] with a0=0x1, a1=a1 at entry (arg1), a2=[0xecd6c4c]+16, a4=0xb4.
  Calls g [0x910] via jr with a0=0x2 (`j` at 0x30).
  The `beq` branch at 0x18 targets 0x28, is taken when a0 == 0, and falls through when a0 != 0.
  The return at 0x34 has v0 = ret(g).
"""

    def test_calls_branches_and_returns_are_read_from_the_rendering(self):
        sheet = fc.sheet_from_text(self.RENDERED)
        self.assertEqual(sheet.abi, "n32")
        self.assertEqual(sheet.calls["0x20"]["args"], {0: "0x1", 1: "a1 at entry (arg1)", 2: "[0xecd6c4c]+16", 4: "0xb4"})
        self.assertEqual((sheet.calls["0x20"]["callee"], sheet.calls["0x20"]["target"]), ("f", "0x900"))
        self.assertTrue(sheet.calls["0x30"]["tail"])
        self.assertEqual(sheet.branches["0x18"]["taken"], "a0 == 0")
        self.assertEqual(sheet.returns["0x34"], "ret(g)")


if __name__ == "__main__":
    unittest.main()
