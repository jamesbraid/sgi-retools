#!/usr/bin/env python3
"""Tests of reading_round.py target selection on a small synthetic inventory.

Run from the repository root: python3 scripts/test_reading_round.py
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("reading_round", os.path.join(HERE, "reading_round.py"))
rr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rr)

HEADER = "binary\trole\taddress\tsize\tname\tscope\tstatus\n"


def inventory(*rows):
    return rr.read_tsv(HEADER + "".join("\t".join(r) + "\n" for r in rows))


def row(binary, address, size, name, status="named-only", scope="in", role="shared-library"):
    return (binary, role, address, size, name, scope, status)


def pick(rows, doc_lines=(), links=((), ())):
    names, addrs = rr.header_keys(list(doc_lines))
    return [(r["binary"], r["name"]) for r in rr.select_targets(
        inventory(*rows), names, addrs, set(links[0]), set(links[1]))]


class SelectionTests(unittest.TestCase):
    def test_scope_and_status_filter(self):
        got = pick([
            row("usr/lib/a.so", "0x100", "8", "keep_named"),
            row("usr/lib/a.so", "0x200", "8", "keep_undoc", status="undocumented"),
            row("usr/lib/a.so", "0x300", "8", "out_scope", scope="out:3"),
            row("usr/lib/a.so", "0x400", "8", "understood", status="understood"),
            row("usr/lib/a.so", "0x500", "8", "located", status="located"),
        ])
        self.assertEqual([n for _b, n in got], ["keep_named", "keep_undoc"])

    def test_dedupe_against_entry_headers(self):
        docs = [
            "- `by_name` in `usr/lib/a.so` at 0x900 (n32).",
            "- `other` in `usr/lib/a.so` at 0x200 (n32).",
            "- `legacy` (`usr/lib/b.so`, 0x40, 16 bytes) Inferred.",
            "- `member_fn` in `usr/k/kona.a(m.o)` at 0x0 (n64).",
        ]
        got = pick([
            row("usr/lib/a.so", "0x100", "8", "by_name"),      # name matches, address differs
            row("usr/lib/a.so", "0x200", "8", "by_addr"),      # address matches under another name
            row("usr/lib/b.so", "0x40", "16", "legacy_addr"),  # legacy header, address
            row("usr/k/kona.a(m.o)", "0x0", "12", "member_fn"),
            row("usr/k/kona.a(n.o)", "0x0", "12", "member_fn"),  # other member: kept
            row("usr/lib/c.so", "0x200", "8", "by_addr"),      # other binary: kept
        ], docs)
        self.assertEqual(got, [("usr/k/kona.a(n.o)", "member_fn"), ("usr/lib/c.so", "by_addr")])

    def test_colon_member_header_matches_parenthesised_row(self):
        got = pick([row("usr/k/kona.a(m.o)", "0x8", "4", "f")],
                   ["- `f` in `usr/k/kona.a:m.o` at 0x8 (n64)."])
        self.assertEqual(got, [])

    def test_address_zero_without_size_is_dropped(self):
        got = pick([
            row("usr/lib/a.so", "0x0", "", "nosize"),
            row("usr/lib/a.so", "0x0", "4", "member_start"),
            row("usr/lib/a.so", "", "4", "noaddr"),
        ])
        self.assertEqual([n for _b, n in got], ["member_start"])

    def test_one_row_per_binary_and_address(self):
        got = pick([
            row("usr/lib/a.so", "0x100", "8", "glFoo"),
            row("usr/lib/a.so", "0x100", "8", "glFooEXT"),
            row("usr/lib/b.so", "0x100", "8", "glFooEXT"),
        ])
        self.assertEqual(got, [("usr/lib/a.so", "glFoo"), ("usr/lib/b.so", "glFooEXT")])

    def test_ranking_order(self):
        rows = [
            row("usr/lib/a.so", "0x10", "8", "plain1"),
            row("usr/lib/a.so", "0x20", "8", "linked_name"),
            row("usr/lib/a.so", "0x30", "8", "plain2"),
            row("usr/lib/a.so", "0x40", "8", "linked_addr"),
            row("usr/gfx/x.o", "0x0", "8", "kernel_role", role="board-kernel"),
            row("usr/cpu/sysgen/IP27boot/k.a(k.o)", "0x8", "8", "boot_path", role="board-library"),
            row("usr/lib/a.so", "0x50", "8", "plain3"),
        ]
        got = [n for _b, n in pick(rows, links=({"linked_name"}, {("usr/lib/a.so", 0x40)}))]
        self.assertEqual(got, ["kernel_role", "boot_path", "linked_name", "linked_addr",
                               "plain1", "plain2", "plain3"])

    def test_hardware_links_from_tables(self):
        mmio = rr.read_tsv("functions\texample\n"
                           "fa;fb;+18 more\tusr/k/kona.a(x.o):fc\n")
        ioctls = rr.read_tsv("handler\tsenders\texample\n"
                             "h1\ts1;s2\tusr/bin/t:routine@0x10001a20\n")
        tokens = rr.read_tsv("example\nusr/k/kona.a(y.o):tk\n")
        names, addrs = rr.hardware_links(mmio, ioctls, tokens)
        self.assertEqual(names, {"fa", "fb", "fc", "h1", "s1", "s2", "tk"})
        self.assertEqual(addrs, {("usr/bin/t", 0x10001a20)})

    def test_closing_sentence(self):
        self.assertEqual(rr.closing_sentence({"renderer": 0, "grader": 0}), "Skipped no routines.")
        self.assertEqual(rr.closing_sentence({"renderer": 2, "grader": 1}),
                         "Skipped 3 routines: 2 because the renderer could not read them and "
                         "1 because the grader flagged a rendered sentence.")


if __name__ == "__main__":
    unittest.main()
