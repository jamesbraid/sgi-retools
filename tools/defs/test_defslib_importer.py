#!/usr/bin/env python3
"""Tests for the header importer: what it converts, what it reports, what it refuses."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen_c, importer, loader, toml_emit  # noqa: E402
from defslib.model import normalize  # noqa: E402
from defslib.modelcheck import check_overlap  # noqa: E402
from testkit import HERE, OldRepoTest  # noqa: E402

IMPORT = os.path.join(HERE, "defs-import")
GEN = os.path.join(HERE, "defs-gen")
CHECK = os.path.join(HERE, "defs-check")


def run(tool, *args):
    return subprocess.run([sys.executable, tool, *args], capture_output=True, text=True)


class ImporterTest(OldRepoTest):
    def result(self, **kw):
        return importer.import_repo(self.root, "defs.toml", **kw)

    def test_one_unit_per_header(self):
        res = self.result()
        self.assertEqual(list(res.units), ["uart", "leg", "cen", "tab"])
        self.assertEqual(res.header_of["leg"], "LEG_DECODE.h")

    def test_regs_form_keeps_registers_fields_enums_and_vectors(self):
        u = normalize(self.result().units["uart"])
        ctl = u["registers"]["ctl"]
        self.assertEqual((ctl["offset"], ctl["access"], ctl["width"], ctl["reset"], ctl["grade"]), (0x10, "rw", 32, 0, "established"))
        self.assertEqual(ctl["fields"]["parity"]["bits"], [3, 1])
        self.assertEqual(ctl["fields"]["parity"]["enums"]["even"], {"value": 2, "grade": "inferred"})
        self.assertEqual([t["kind"] for t in ctl["tests"]], ["example", "vector"])
        self.assertEqual(u["registers"]["data"]["count"], 16)
        self.assertEqual(u["constants"]["FIFO_DEPTH"], {"value": 16, "grade": "established"})
        self.assertEqual(u["words"]["FRAME"]["grade"], "established")

    def test_grade_comes_from_the_header_not_from_a_guess(self):
        res = self.result()
        u = res.units["leg"]
        self.assertEqual(u["constants"]["OP_COPY"]["grade"], "established")
        self.assertNotIn("OP_WORDS", u["constants"])
        self.assertIn(("leg", "LEG_OP_WORDS", "8", "no grade in the header"), res.report.ungraded)
        self.assertIn(("tab", "TAB_REQ_RESET", "0x2001", "no grade in the header"), res.report.ungraded)

    def test_defaulted_grades_are_reported(self):
        res = self.result()
        self.assertTrue([d for d in res.report.defaulted if "enum fmt: 1 of 2 values" in d[1] and "rgb" in d[1]])
        self.assertTrue([d for d in res.report.defaulted if "word grades" in d[1]])

    def test_legacy_tables_become_aliases_and_helpers_are_copied(self):
        res = self.result()
        aliases = res.units["leg"]["c"]["aliases"]
        self.assertEqual(aliases["LEG_CMD_SIZEFLD_SHIFT"], "LEG_CMD_SIZE_FIELD_SHIFT")
        self.assertEqual(aliases["LEG_CMD_SIZEFLD_MASK"], "LEG_CMD_SIZE_FIELD_MASK")
        self.assertEqual(aliases["LEG_CMD_FRONT"], "LEG_CMD_FRONT_INPLACE")
        self.assertIn("LEG_FIELD_GET", res.helpers["leg"])
        self.assertIn(("leg", "LEG_FIELD_GET"), res.report.helpers)

    def test_c_code_outside_the_defines_is_carried_in_the_helpers(self):
        res = self.result()
        self.assertIn("static inline uint32_t leg_round_even", res.helpers["leg"])
        self.assertTrue([h for h in res.report.helpers if "lines of C code" in h[1]])
        self.assertNotIn("#ifndef", res.helpers["leg"])
        self.assertNotIn("LEG_DECODE_H", res.helpers["leg"])
        self.assertNotIn("uart", res.helpers.get("uart", ""))

    def test_annotations_the_importer_does_not_read_are_reported(self):
        res = self.result()
        self.assertTrue([n for n in res.report.notes if n.startswith("leg: 1 comment lines starting 'CALC:'")], res.report.notes)
        self.assertFalse([n for n in res.report.notes if "'TESTVEC:'" in n or "'REG:'" in n])
        self.assertIn(" * CALC: 4 rounded up to even => 4", res.helpers["leg"])     # kept for a plugin that reads it

    def test_old_macros_that_cannot_be_carried_are_listed(self):
        res = self.result()
        self.assertIn(("leg", "LEG_CMD_FRONT_BIT", "(1u << 31)"), res.report.unmapped)
        self.assertIn(("leg", "LEG_CMD_BOTH_BITS", "(LEG_CMD_FRONT_BIT | 0x1u)"), res.report.unmapped)

    def test_macro_with_another_prefix_keeps_its_full_name(self):
        self.edit("TAB.h", "#define TAB_REQ_RESET", "#define OTHER_LIMIT   0x40     /* [E] belongs to another family */\n#define OTHER_NOGRADE 0x41\n#define TAB_REQ_RESET")
        res = self.result()
        c = res.units["tab"]["constants"]["OTHER_LIMIT"]
        self.assertEqual((c["value"], c["grade"], c["macro"]), (0x40, "established", "OTHER_LIMIT"))
        self.assertIn(("tab", "OTHER_NOGRADE", "0x41", "no grade in the header"), res.report.ungraded)
        self.assertEqual([r for r in res.report.unmapped if r[0] == "tab"], [])

    MULTI = """/* MULTI_DECODE.h - a header with two register blocks */
#ifndef MULTI_DECODE_H
#define MULTI_DECODE_H
/* REG: SIU.ctl 0x004 rw32 reset=unknown established */
/* REG: PCIB.ctl 0x004 rw32 reset=unknown inferred */
/* REG: PCIB.cfg 0x008 rw32 reset=unknown inferred */
/* FIELD: PCIB.cfg.mode 3:0 inferred */
#define M_PCIB_CFG_MODE_SHIFT 0
#define M_PCIB_CFG_MODE_MASK 0xfu
#define M_MAGIC_OLD 0x1234u /* established */
/* FIELD: WORD.magic 15:0 established */
#define M_WORD_MAGIC_SHIFT 0
#define M_WORD_MAGIC_MASK 0xffffu
/* ENUM: WORD.magic 0x1234 old established */
#define M_WORD_MAGIC_OLD 0x1234
#endif
"""

    def multi_result(self):
        self.write("MULTI_DECODE.h", self.MULTI)
        self.edit("defs.toml", '[[headers]]\nfile = "TAB.h"', '[[headers]]\nfile = "MULTI_DECODE.h"\nprefix = "M"\n\n[[headers]]\nfile = "TAB.h"')
        return self.result()

    def test_header_with_several_register_blocks_gets_a_space_per_block(self):
        res = self.multi_result()
        u = normalize(res.units["multi"])
        self.assertNotIn("block", u)                                  # the macros use the prefix
        self.assertEqual(sorted(u["registers"]), ["cfg", "pcib_ctl", "siu_ctl"])   # `ctl` is in both blocks, so both are qualified
        self.assertEqual(u["registers"]["siu_ctl"]["space"], "multi_siu")
        self.assertEqual(u["registers"]["pcib_ctl"]["space"], "multi_pcib")
        self.assertEqual(u["registers"]["cfg"]["fields"]["mode"]["bits"], [3, 0])
        self.assertEqual(check_overlap([u]), [])
        self.assertTrue([s for s in res.report.spaces if s[0] == "multi" and "one per register block" in s[1]])
        self.assertTrue([n for n in res.report.notes if n.startswith("multi: REG lines name 2 register blocks")])

    def test_a_constant_is_not_taken_for_an_enum_macro_because_the_label_matches(self):
        u = normalize(self.multi_result().units["multi"])
        self.assertEqual(u["constants"]["MAGIC_OLD"], {"value": 0x1234, "grade": "established"})
        self.assertEqual(u["words"]["WORD"]["fields"]["magic"]["enums"]["old"]["value"], 0x1234)

    def test_constant_the_layout_already_generates_is_dropped_not_defined_twice(self):
        self.edit("UART_DECODE.h", "#define UART_FIFO_DEPTH 16 /* established */", "#define UART_FIFO_DEPTH 16 /* established */\n#define UART_DATA_COUNT 16 /* established */")
        res = self.result()
        self.assertNotIn("DATA_COUNT", res.units["uart"].get("constants", {}))
        self.assertIn(("uart", "UART_DATA_COUNT", "the same macro is generated from the layout, with the same value"), res.report.dropped)
        self.assertEqual(res.report.mismatched, [])
        gen_c.gen_c(normalize(res.units["uart"]), "x")          # renders: no duplicate macro

    def test_a_derived_constant_with_another_value_is_reported_as_a_mismatch(self):
        self.edit("UART_DECODE.h", "#define UART_FIFO_DEPTH 16 /* established */", "#define UART_FIFO_DEPTH 16 /* established */\n#define UART_DATA_COUNT 15 /* established */")
        res = self.result()
        self.assertEqual(res.report.mismatched, [("uart", "UART_DATA_COUNT", "0xf", "0x10")])

    def test_report_lists_each_item_once(self):
        r = importer.Report()
        r.unmapped += [("u", "A", "1"), ("u", "A", "1"), ("u", "B", "2")]
        lines = r.lines()
        self.assertEqual([l for l in lines if l.strip().startswith("u: A")], ["  u: A = 1"])
        self.assertTrue([l for l in lines if l.startswith("old macros with no counterpart") and l.endswith(": 2")])

    def test_bare_literals_are_never_smuggled_in_as_aliases(self):
        self.edit("LEG_DECODE.h", "#define LEG_OP_WORDS 8", "#define LEG_OP_WORDS 8\n#define LEG_ODD (3 * 4096)")
        res = self.result()
        self.assertNotIn("LEG_ODD", res.units["leg"]["c"]["aliases"])
        self.assertIn(("leg", "LEG_ODD", "(3 * 4096)"), res.report.unmapped)

    def test_census_header(self):
        u = normalize(self.result().units["cen"])
        self.assertEqual(u["c"]["offset_macro"], "bare")
        self.assertEqual(u["registers"]["mode"]["width"], 64)
        self.assertEqual(u["registers"]["mode"]["from"], "census: 78 sites, 34 routines")
        self.assertEqual(u["public_from"], ["census:"])      # the old header showed these counts publicly
        self.assertEqual(u["registers"]["stat"]["grade"], "unknown")
        self.assertEqual(u["registers"]["stat"]["width"], 32)
        self.assertEqual(u["constants"]["MODE_B_3_0"], {"value": 0xf, "grade": "inferred"})
        self.assertEqual(u["constants"]["MODE_V_200000"]["grade"], "inferred")
        self.assertEqual(u["c"]["aliases"], {"CEN_CFG0_20": "CEN_CFG0"})

    def test_census_line_without_width_and_access_is_a_constant_not_a_register(self):
        self.edit("CEN.h", "#define CEN_STAT                         0x000028   /* [U] width 4 byte(s) at slot+4, access r */",
                  "#define CEN_STAT                         0x000028   /* [U] width 4 byte(s) at slot+4, access r */\n"
                  "#define CEN_ODD                          0x000030   /* [E] offset and read-only access from the specification; width 4 byte(s) [I] */\n"
                  "#define CEN_ARW                          0x000038   /* [E] width 0/4 byte(s), access arw */")
        res = self.result()
        u = normalize(res.units["cen"])
        self.assertNotIn("odd", u["registers"])
        self.assertEqual((u["constants"]["ODD"]["value"], u["constants"]["ODD"]["grade"]), (0x30, "established"))
        self.assertEqual((u["constants"]["ARW"]["value"], u["constants"]["ARW"]["grade"]), (0x38, "established"))
        self.assertTrue([n for n in res.report.notes if "cen: 2 top-level census lines" in n])
        self.assertIn("stat", u["registers"])

    def test_a_macro_ending_in_h_is_not_taken_for_the_include_guard(self):
        self.edit("CEN.h", "#define CEN_STAT ", "#define CEN_HI_H                         0x000040   /* [E] width 4 byte(s), access rw */\n#define CEN_STAT ")
        u = normalize(self.result().units["cen"])
        self.assertIn("hi_h", u["registers"])
        self.assertEqual(self.result().units["cen"]["c"]["legacy_guard"], "CEN_H")
        self.assertNotIn("h", u["constants"])

    def test_address_space_in_register_indexes_is_detected(self):
        res = self.result()
        self.assertEqual(res.units["uart"]["spaces"]["uart_regs"]["unit"], "reg")
        self.assertTrue([s for s in res.report.spaces if s[0] == "uart"])

    def test_space_can_be_forced(self):
        self.edit("defs.toml", 'file = "UART_DECODE.h"\nblock = "UART"', 'file = "UART_DECODE.h"\nblock = "UART"\nspace = "hq"')
        res = self.result(space_units=["hq"])
        self.assertEqual(res.units["uart"]["spaces"]["hq"]["unit"], "reg")
        self.assertEqual(res.units["uart"]["registers"]["ctl"]["space"], "hq")
        self.assertTrue([s for s in res.report.spaces if "set by --space-unit" in s[1]])
        self.assertEqual(self.result().units["uart"]["spaces"]["hq"]["unit"], "reg")      # detected anyway: registers overlap in bytes

    def test_each_unit_gets_its_own_default_space(self):
        self.edit("CEN.h", "#define CEN_STAT ", "#define CEN_DUP                          0x000024   /* [E] width 4 byte(s), access rw */\n#define CEN_STAT ")
        res = self.result()
        spaces = {n: set(u.get("spaces", {})) for n, u in res.units.items()}
        self.assertEqual(spaces["uart"], {"uart_regs"})
        self.assertEqual(spaces["cen"], {"cen_regs"})        # not one shared name, which would collide across units

    def test_census_window_is_its_own_address_space(self):
        self.edit("CEN.h", "#define CEN_STAT ", "#define CEN_BOOT_20                      0x000020   /* [E] width 4 byte(s), access r, through the boot-space window */\n#define CEN_STAT ")
        res = self.result()
        u = normalize(res.units["cen"])
        self.assertEqual(u["registers"]["boot_20"]["space"], "cen_boot_space")
        self.assertIn("cen_boot_space", u["spaces"])
        self.assertEqual(u["registers"]["cfg0"]["space"], None)          # the main window keeps the default
        self.assertEqual(check_overlap([u]), [])                          # same offset, different window

    def test_census_family_twin_is_an_alias_whatever_its_name(self):
        self.edit("CEN.h", "#define CEN_STAT ", "#define CEN_MODE_IDX                     0x000000   /* [E] width 4 byte(s), access rw, indexed (family base) */\n#define CEN_STAT ")
        u = self.result().units["cen"]
        self.assertEqual(u["c"]["aliases"]["CEN_MODE_IDX"], "CEN_MODE")
        self.assertNotIn("mode_idx", u["registers"])

    def test_headers_the_old_check_never_scanned_get_prose_offsets_false(self):
        c = self.result().check
        self.assertNotIn("prose_offsets", c["units"]["uart"])        # a REG header with a block was scanned
        for u in ("leg", "cen", "tab"):
            self.assertIs(c["units"][u]["prose_offsets"], False)

    def test_check_settings_keep_everything_but_the_header_list(self):
        c = self.result().check
        self.assertEqual(c["project"]["name"], "oldmini")
        self.assertEqual(c["checks"]["address_bits"], 32)
        labels = [e["label"] for e in c["banned"]["extra"]]
        self.assertEqual(labels, ["driver routine prefix", "project name"])
        self.assertEqual(c["units"]["uart"], {"group": "uart", "notes_corpus": ["docs/uart.md"]})
        self.assertEqual(c["units"]["leg"]["plugin_form"], "legacy")
        self.assertEqual(c["units"]["cen"]["group"], "CEN.h")
        self.assertEqual(c["claims"][0]["label"], "frame payload")
        self.assertNotIn("headers", c)

    def test_layout_notes_use_the_old_checks_settings(self):
        self.edit("CEN.h", "0x000028   /* [U]", "0x2000000   /* [U]")
        self.assertEqual([n for n in self.result().report.notes if n.startswith("layout:")], [])      # address_bits = 32 in the fixture
        self.edit("defs.toml", "address_bits = 32\nmax_reg_offset = 0xffffffff\n", "")
        self.assertTrue([n for n in self.result().report.notes if n.startswith("layout:") and "outside the register space" in n])

    def test_census_prefix_comes_from_the_names_not_the_file_name(self):
        self.write("CEN_extra.h", "#define CEN_FIRST 0x10 /* [E] one */\n#define CEN_SECOND 0x20 /* [I] two */\n")
        self.edit("defs.toml", '[[headers]]\nfile = "TAB.h"', '[[headers]]\nfile = "CEN_extra.h"\n\n[[headers]]\nfile = "TAB.h"')
        u = self.result().units["cen_extra"]
        self.assertEqual(u["prefix"], "CEN")
        self.assertEqual(sorted(u["constants"]), ["FIRST", "SECOND"])

    def test_unit_is_named_by_the_old_rust_module(self):
        self.edit("defs.toml", '[[headers]]\nfile = "TAB.h"', '[[headers]]\nfile = "TAB.h"\nmodule = "requests"')
        self.assertIn("requests", self.result().units)

    def test_unit_name_can_be_given(self):
        res = self.result(names={"TAB.h": "requests"})
        self.assertIn("requests", res.units)

    def test_toml_roundtrip_is_exact(self):
        for name, src in self.result().units.items():
            m = normalize(src)
            self.write("defs/%s.toml" % name, toml_emit.emit_unit(m))
        self.write("defs/check.toml", "")
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        for name, src in self.result().units.items():
            self.assertEqual(repo.units[name].model, normalize(src), name)

    def test_regex_in_claims_stays_readable(self):
        text = toml_emit.emit_check(self.result().check)
        self.assertIn("regex = 'payload in bits (\\d+):(\\d+)'", text)

    def test_claim_binds_with_lists_survive(self):
        self.edit("defs.toml", 'binds = [["F", "FRAME.payload", 1, 2]]', 'binds = [["F", "FRAME.payload", 1, 2], ["M", ["FRAME.start", "FRAME.payload"], 3]]')
        text = toml_emit.emit_check(self.result().check)
        self.assertIn('["M", ["FRAME.start", "FRAME.payload"], 3]', text)
        import tomllib
        self.assertEqual(tomllib.loads(text)["claims"][0]["binds"][1], ["M", ["FRAME.start", "FRAME.payload"], 3])

    def test_cli_writes_files_report_and_refuses_to_overwrite(self):
        r = run(IMPORT, "--root", self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        for f in ("uart.toml", "leg.toml", "cen.toml", "tab.toml", "leg_helpers.h", "check.toml", "import-report.txt"):
            self.assertTrue(os.path.isfile(self.path("defs/" + f)), f)
        self.assertIn("constants with no grade", self.read("defs/import-report.txt"))
        for h in ("UART_DECODE.h", "LEG_DECODE.h", "CEN.h", "TAB.h"):
            self.assertTrue(os.path.isfile(self.path(h)))          # headers are never touched
        r = run(IMPORT, "--root", self.root)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--force", r.stderr)
        self.assertEqual(run(IMPORT, "--root", self.root, "--force").returncode, 0)

    def test_dry_run_writes_nothing(self):
        r = run(IMPORT, "--root", self.root, "--dry-run")
        self.assertEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.path("defs")))

    def test_imported_repo_generates_and_checks_clean_once_its_leftovers_are_resolved(self):
        self.assertEqual(run(IMPORT, "--root", self.root).returncode, 0)
        self.assertEqual(run(GEN, "--root", self.root).returncode, 0)
        r = run(CHECK, "--root", self.root, "--build")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_missing_header_is_a_setup_error(self):
        os.remove(self.path("TAB.h"))
        r = run(IMPORT, "--root", self.root)
        self.assertEqual(r.returncode, 2)
        self.assertIn("TAB.h", r.stderr)


if __name__ == "__main__":
    unittest.main()
