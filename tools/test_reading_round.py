#!/usr/bin/env python3
"""Tests of reading_round.py target selection on a small synthetic inventory.

Run from the repository root: python3 tools/test_reading_round.py
"""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
spec = importlib.util.spec_from_file_location("reading_round", os.path.join(HERE, "reading_round.py"))
rr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rr)

HEADER = "binary\trole\taddress\tsize\tname\tscope\tstatus\trejected\n"


def inventory(*rows):
    return rr.read_tsv(HEADER + "".join("\t".join(r) + "\n" for r in rows))


def row(binary, address, size, name, status="named-only", scope="in", role="shared-library", rejected=""):
    return (binary, role, address, size, name, scope, status, rejected)


def pick(rows, doc_lines=(), links=((), ()), **options):
    names, addrs = rr.header_keys(list(doc_lines))
    return [(r["binary"], r["name"]) for r in rr.select_targets(
        inventory(*rows), names, addrs, set(links[0]), set(links[1]), **options)]


class SelectionTests(unittest.TestCase):
    def test_container_segments_are_offered(self):
        got = pick([
            row("6.5.30/usr/cpu/firmware/sysco/l1.bin(l1#2)", "0xffe10000", "64", "sub_ffe10000", role="sysco-l1-firmware"),
            row("6.5.30/usr/cpu/firmware/sysco/l2.bin(kernel)", "0xc0001000", "64", "sub_c0001000", role="sysco-l2-firmware"),
            row("usr/lib/lib.a(m.o)", "0x10", "8", "in_archive")])
        self.assertEqual([n for _, n in got], ["sub_ffe10000", "sub_c0001000", "in_archive"])

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

    def test_address_unknown_rows_are_never_targets(self):
        r = row("usr/lib/a.so", "0x0", "4", "unplaced", rejected="address-unknown")
        got = pick([r, row("usr/lib/a.so", "0x100", "8", "placed")])
        self.assertEqual([n for _b, n in got], ["placed"])

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

    def test_from_grade_located_adds_located_rows_only(self):
        rows = [
            row("usr/lib/a.so", "0x100", "8", "named"),
            row("usr/lib/a.so", "0x200", "8", "undoc", status="undocumented"),
            row("usr/lib/a.so", "0x300", "8", "located", status="located"),
            row("usr/lib/a.so", "0x400", "8", "understood", status="understood"),
        ]
        self.assertEqual([n for _b, n in pick(rows)], ["named", "undoc"])
        self.assertEqual([n for _b, n in pick(rows, from_grade="named-only")], ["named", "undoc"])
        self.assertEqual([n for _b, n in pick(rows, from_grade="located")], ["named", "undoc", "located"])
        self.assertEqual([n for _b, n in pick(rows, from_grade="undocumented")], ["undoc"])

    def test_hardware_only_keeps_table_linked_rows_in_rank_order(self):
        rows = [
            row("usr/lib/a.so", "0x10", "8", "plain"),
            row("usr/lib/a.so", "0x20", "8", "by_name", status="located"),
            row("usr/lib/a.so", "0x30", "8", "by_addr", status="located"),
            row("usr/k/kona.a(k.o)", "0x40", "8", "kernel_plain", role="board-kernel"),
            row("usr/k/kona.a(k.o)", "0x50", "8", "kernel_linked", role="board-kernel"),
        ]
        links = ({"by_name", "kernel_linked"}, {("usr/lib/a.so", 0x30)})
        got = [n for _b, n in pick(rows, links=links, from_grade="located", hardware_only=True)]
        self.assertEqual(got, ["kernel_linked", "by_name", "by_addr"])
        # without the option the plain rows come back, after the linked ones
        everything = [n for _b, n in pick(rows, links=links, from_grade="located")]
        self.assertEqual(everything, ["kernel_plain", "kernel_linked", "by_name", "by_addr", "plain"])

    def test_binary_filter(self):
        rows = [row("fw/a.bin", "0x100", "8", "one"), row("fw/b.bin", "0x100", "8", "two")]
        self.assertEqual(pick(rows, binaries={"fw/b.bin"}), [("fw/b.bin", "two")])

    def test_closing_sentence(self):
        self.assertEqual(rr.closing_sentence({"renderer": 0, "grader": 0}), "Skipped no routines.")
        self.assertEqual(rr.closing_sentence({"renderer": 2, "grader": 1}),
                         "Skipped 3 routines: 2 because the renderer could not read them and "
                         "1 because the grader flagged a rendered sentence.")


def have_capstone():
    try:
        import capstone  # noqa: F401
        import elftools  # noqa: F401
    except ImportError:
        return False
    return True


# coldfire: move.l #7,-(a7); jsr 0x2000; addq.l #4,a7; movea.l #0x10000000,a0; move.b -4(a0),d0; rts
COLDFIRE = bytes.fromhex("2f3c000000074eb900002000588f207c100000001028fffc4e75")
# ppc32: stwu r1,-16(r1); mflr r0; stw r0,20(r1); lis r3,0x1000; ori r3,r3,0x10; lwz r4,8(r3);
# cmpwi r4,0; beq +16; li r5,5; bl +0xf00; lwz r0,20(r1); mtlr r0; addi r1,r1,16; blr
PPC = bytes.fromhex("9421fff07c0802a690010014" "3c601000" "60630010" "80830008" "2c040000" "41820010"
                    "38a00005" "48000f01" "80010014" "7c0803a6" "38210010" "4e800020")
FUNCTIONS = ("binary\trole\taddress\tsize\tname\tscope\tstatus\trejected\n"
             "fw/img.bin\tfirmware\t0x1000\t%d\tfw_routine\tin\t%s\t\n")


@unittest.skipUnless(have_capstone(), "needs capstone and pyelftools")
class FirmwareRoundTests(unittest.TestCase):
    """A whole round on a throwaway workspace: select, render, grade, call-check, commit."""

    def run_round(self, image, arch, status="located", from_grade="located", extra=(), mutate=None):
        with tempfile.TemporaryDirectory() as work:
            os.makedirs(os.path.join(work, "root", "fw"))
            os.makedirs(os.path.join(work, "docs", "inventory"))
            with open(os.path.join(work, "root", "fw", "img.bin"), "wb") as handle:
                handle.write(image)
            with open(os.path.join(work, "docs", "inventory", "functions.tsv"), "w") as handle:
                handle.write(FUNCTIONS % (len(image), status))
            for name in ("mmio", "ioctls", "tokens"):
                with open(os.path.join(work, "docs", "inventory", name + ".tsv"), "w") as handle:
                    handle.write("functions\texample\n" if name == "mmio" else "example\n")
            git = lambda *a: subprocess.run(("git",) + a, cwd=work, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.com")
            git("config", "user.name", "t")
            git("add", ".")
            git("commit", "-q", "-m", "inventory")
            old = os.getcwd()
            os.chdir(work)
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out):
                    code = rr.main(["--repo-name", "fw", "--round", "g1", "--out-dir", "out",
                                    "--arch", arch, "--load", "0x1000"]
                                   + (["--from-grade", from_grade] if from_grade else []) + list(extra))
                with open("docs/instruction-readings-fw-g1.md") as handle:
                    doc = handle.read()
                if mutate:
                    # re-run only the checks on an edited document
                    import grade_readings
                    with open("docs/edited.md", "w") as handle:
                        handle.write(mutate(doc))
                    with contextlib.redirect_stdout(io.StringIO()):
                        graded = grade_readings.main(["docs/edited.md", "--root", "root", "--count", "0"])
                    return rr.check_call_addrs("docs/edited.md", "root"), graded, doc
            finally:
                os.chdir(old)
            return code, out.getvalue(), doc

    def test_coldfire_round_selects_located_rows_and_passes_both_checks(self):
        code, out, doc = self.run_round(COLDFIRE, "coldfire")
        self.assertEqual(code, 0, out)
        self.assertIn("1 entries written", out)
        self.assertIn("call check (exit 0): 1 calls checked, 0 problems", out)
        self.assertIn("Architecture: coldfire, load 0x1000, offset 0x0.", doc)
        self.assertIn("The `jsr` at 0x1006 calls (unnamed) [0x2000] with stack arg0=0x7.", doc)
        self.assertIn("The return at 0x1018 has d0 = ?.", doc)

    def test_default_grade_leaves_located_rows_alone(self):
        code, out, doc = self.run_round(COLDFIRE, "coldfire", from_grade=None)
        self.assertIn("targets: 0", out)
        self.assertNotIn("- `", doc)

    def test_hardware_only_drops_unlinked_rows(self):
        code, out, _doc = self.run_round(COLDFIRE, "coldfire", extra=["--hardware-only"])
        self.assertIn("targets: 0", out)

    def test_ppc_round(self):
        code, out, doc = self.run_round(PPC, "ppc32")
        self.assertEqual(code, 0, out)
        self.assertIn("The `bl` at 0x1024 calls (unnamed) [0x1f24] with r3=0x10000010, r4=[0x10000018], r5=0x5.", doc)
        self.assertIn("The `beq` branch at 0x101c targets 0x102c, is taken when [0x10000018] == 0x0, "
                      "and falls through when [0x10000018] != 0x0.", doc)

    def test_call_check_rejects_a_wrong_address_and_target(self):
        (calls, problems), grade, _doc = self.run_round(
            COLDFIRE, "coldfire", mutate=lambda d: d.replace("at 0x1006 calls (unnamed) [0x2000]",
                                                             "at 0x1004 calls (unnamed) [0x2000]"))
        self.assertEqual((calls, len(problems)), (1, 1))
        self.assertIn("0x1004 is not a call site", problems[0])
        self.assertEqual(grade, 1)
        (calls, problems), _grade, _doc = self.run_round(
            COLDFIRE, "coldfire", mutate=lambda d: d.replace("[0x2000]", "[0x3000]"))
        self.assertIn("reaches 0x2000, not 0x3000", problems[0])

    def test_arch_without_load_is_refused(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            rr.main(["--repo-name", "x", "--round", "g1", "--out-dir", "o", "--arch", "arm"])


@unittest.skipUnless(have_capstone(), "needs capstone and pyelftools")
class SegmentRoundTests(unittest.TestCase):
    """Rows keyed by a segment of a firmware container render and grade like any other routine."""

    def run_round(self, rows, extra=()):
        import test_firmware_layout as fl
        with tempfile.TemporaryDirectory() as work:
            fl.workspace(os.path.join(work, "root"))
            os.makedirs(os.path.join(work, "docs", "inventory"))
            os.makedirs(os.path.join(work, "scripts"))
            with open(os.path.join(work, "scripts", "inventory-config.json"), "w") as handle:
                json.dump(fl.CONFIG, handle)
            with open(os.path.join(work, "docs", "inventory", "functions.tsv"), "w") as handle:
                handle.write(HEADER + "".join("\t".join(r) + "\n" for r in rows))
            for name in ("mmio", "ioctls", "tokens"):
                with open(os.path.join(work, "docs", "inventory", name + ".tsv"), "w") as handle:
                    handle.write("functions\texample\n" if name == "mmio" else "example\n")
            git = lambda *a: subprocess.run(("git",) + a, cwd=work, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.com")
            git("config", "user.name", "t")
            git("add", ".")
            git("commit", "-q", "-m", "inventory")
            old = os.getcwd()
            os.chdir(work)
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out):
                    code = rr.main(["--repo-name", "fw", "--round", "g1", "--out-dir", "out",
                                    "--from-grade", "located"] + list(extra))
                with open("docs/instruction-readings-fw-g1.md") as handle:
                    doc = handle.read()
                with open("out/renderer-conflicts-fw-g1.tsv") as handle:
                    conflicts = handle.read()
            finally:
                os.chdir(old)
            return code, out.getvalue(), doc, conflicts

    def test_each_architecture_renders_and_grades_end_to_end(self):
        import test_firmware_layout as fl
        rows = [row("fw/l1.bin(l1#0)", hex(fl.L1_LOAD + 8), str(len(fl.CF_CODE)), "sub_l1", "located", role="fw"),
                row("fw/l2.bin(flash)", hex(fl.L2_LOAD), str(len(fl.PPC_CODE)), "sub_flash", "located", role="fw"),
                row("fw/l2.bin(kernel)", hex(fl.KERNEL_LOAD), str(len(fl.PPC_CODE)), "sub_kernel", "located", role="fw"),
                row("fw/flat.bin()", "0x2000", str(len(fl.CF_CODE)), "sub_flat", "located", role="fw")]
        code, out, doc, conflicts = self.run_round(rows)
        self.assertEqual(code, 0, out)
        self.assertIn("4 entries written", out)
        self.assertEqual(conflicts.count("\n"), 1, conflicts)
        self.assertIn("- `sub_l1` in `fw/l1.bin(l1#0)` at 0x%x (m68k-sysv)." % (fl.L1_LOAD + 8), doc)
        self.assertIn("Architecture: coldfire, load 0x%x, offset 0x0." % fl.L1_LOAD, doc)
        self.assertIn("The `move.l` at 0x%x loads 4 bytes from abs 0x10000014." % (fl.L1_LOAD + 8 + 10), doc)
        self.assertIn("- `sub_flash` in `fw/l2.bin(flash)` at 0x%x (ppc-sysv)." % fl.L2_LOAD, doc)
        self.assertIn("Architecture: ppc32, load 0x%x, offset 0x0." % fl.L2_LOAD, doc)
        self.assertIn("Architecture: ppc32, load 0x%x, offset 0x0." % fl.KERNEL_LOAD, doc)
        self.assertIn("The `lwz` at 0x%x loads 4 bytes from abs 0x10000014." % (fl.KERNEL_LOAD + 8), doc)
        self.assertIn("Architecture: coldfire, load 0x2000, offset 0x0.", doc)

    def test_a_segment_the_container_lacks_is_a_renderer_conflict(self):
        import test_firmware_layout as fl
        code, out, doc, conflicts = self.run_round(
            [row("fw/l2.bin(rom)", hex(fl.L2_LOAD), "20", "sub_rom", "located", role="fw")])
        self.assertIn("0 entries written", out)
        self.assertIn("has no segment 'rom'", conflicts)

    def test_the_grader_rejects_an_entry_whose_header_names_another_load_address(self):
        import test_firmware_layout as fl
        rows = [row("fw/l2.bin(kernel)", hex(fl.KERNEL_LOAD), str(len(fl.PPC_CODE)), "sub_kernel", "located", role="fw")]
        with tempfile.TemporaryDirectory() as work:
            fl.workspace(os.path.join(work, "root"))
            os.makedirs(os.path.join(work, "scripts"))
            with open(os.path.join(work, "scripts", "inventory-config.json"), "w") as handle:
                json.dump(fl.CONFIG, handle)
            row_ = inventory(*rows)[0]
            import firmware_layout
            config = firmware_layout.read_config(work)
            text = rr.render_one(row_, os.path.join(work, "root"), None, config)
            bad = text.replace("load 0x%x" % fl.KERNEL_LOAD, "load 0x%x" % fl.L2_LOAD)
            scratch = os.path.join(work, "entry.md")
            self.assertEqual(rr.grade_one(text, os.path.join(work, "root"), scratch), (True, ""))
            with self.assertRaisesRegex(ValueError, "layout gives ppc32 at 0xc0000000"):
                rr.grade_one(bad, os.path.join(work, "root"), scratch)


if __name__ == "__main__":
    unittest.main()
