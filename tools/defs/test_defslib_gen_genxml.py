#!/usr/bin/env python3
"""Tests for the genxml export, run through the vendored upstream pack generator."""
import hashlib
import os
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defslib import gen_genxml, loader  # noqa: E402
from defslib.genutil import GenError  # noqa: E402
from testkit import HERE, RepoTest, which  # noqa: E402

CC = which("cc", "gcc")
VENDOR = os.path.join(HERE, "vendor", "genxml")
PRELUDE = os.path.join(HERE, "genxml_prelude.h")


def run_upstream(xml_path):
    """Run the vendored generator exactly as Mesa's build does; return the C it prints."""
    r = subprocess.run([sys.executable, "-I", os.path.join(VENDOR, "gen_pack.py"), xml_path, PRELUDE],
                       capture_output=True, text=True)
    return r


class GenXmlTest(RepoTest):
    def unit(self, name="uart"):
        repo = loader.load_repo(self.root)
        self.assertEqual(repo.errors, [])
        return repo.units[name].model

    def build_and_run(self, u):
        self.write("u.xml", gen_genxml.gen_genxml(u, "defs/x.toml"))
        r = run_upstream(self.path("u.xml"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.write("u_pack.h", r.stdout)
        self.write("t.c", gen_genxml.genxml_selftest_c(u, "u_pack.h"))
        exe = self.path("t")
        c = subprocess.run([CC, "-std=gnu11", "-Wall", "-Wno-unused-function", "-o", exe, self.path("t.c")],
                           capture_output=True, text=True)
        self.assertEqual(c.returncode, 0, c.stderr)
        return subprocess.run([exe], capture_output=True, text=True)

    def test_vendored_copy_is_the_pinned_file(self):
        with open(os.path.join(VENDOR, "SOURCE"), encoding="utf-8") as f:
            note = f.read()
        want = re.search(r"sha256:\s+([0-9a-f]{64})", note).group(1)
        with open(os.path.join(VENDOR, "gen_pack.py"), "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(got, want, "vendored gen_pack.py was edited; change the export instead")
        self.assertIn("mesa-25.3.0", note)
        self.assertTrue(os.path.isfile(os.path.join(VENDOR, "LICENSE")))

    def test_export_shape(self):
        root = ET.fromstring(gen_genxml.gen_genxml(self.unit(), "defs/uart.toml"))
        self.assertEqual(root.tag, "genxml")
        structs = {s.get("name"): s for s in root.findall("struct")}
        self.assertEqual(sorted(structs), ["CTL", "DATA", "FRAME", "STATUS"])
        ctl = structs["CTL"]
        self.assertEqual((ctl.get("size"), ctl.get("offset"), ctl.get("access")), ("4", "0x10", "rw"))
        f = {x.get("name"): x for x in ctl.findall("field")}
        self.assertEqual((f["divisor"].get("start"), f["divisor"].get("size")), ("16", "16"))
        self.assertEqual(f["parity"].get("type"), "parity")
        self.assertEqual(f["parity"].get("grade"), "inferred")
        self.assertEqual(structs["DATA"].get("count"), "16")
        self.assertEqual([v.get("name") for v in root.find("enum").findall("value")], ["none", "odd", "even"])

    def test_extensions_avoid_upstream_element_names(self):
        root = ET.fromstring(gen_genxml.gen_genxml(self.unit(), "defs/uart.toml"))
        for el in root.iter():
            if el.tag == "value":
                self.assertIn(el, list(root.find("enum")), "a <value> outside an enum would confuse the upstream parser")

    @unittest.skipUnless(CC, "no C compiler")
    def test_upstream_generator_packs_the_export_and_vectors_roundtrip(self):
        r = self.build_and_run(self.unit())
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("10 genxml checks, 0 failed", r.stdout)

    @unittest.skipUnless(CC, "no C compiler")
    def test_sixty_four_bit_word_with_a_field_across_the_word_boundary(self):
        value = 0xa00123456789a0ff
        lo, mid, top = value & 0xfff, (value >> 20) & 0xfffffff, value >> 60
        self.write("defs/wide.toml", "\n".join([
            'unit = "wide"', 'prefix = "WIDE"', 'from = "x"',
            "[words.W]", "width = 64", 'grade = "inferred"',
            "[words.W.fields]",
            'lo = { bits = [11, 0], grade = "inferred" }',
            'mid = { bits = [47, 20], grade = "inferred" }',
            'top = { bits = [63, 60], grade = "inferred" }',
            "[[words.W.tests]]", "value = 0x%x" % value, "expect = { lo = %d, mid = %d, top = %d }" % (lo, mid, top)]))
        r = self.build_and_run(self.unit("wide"))
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("0 failed", r.stdout)

    @unittest.skipUnless(CC, "no C compiler")
    def test_field_named_like_a_c_keyword_still_compiles(self):
        self.write("defs/kw.toml", "\n".join([
            'unit = "kw"', 'prefix = "KW"', 'from = "x"',
            "[words.W]", "width = 32", 'grade = "inferred"',
            "[words.W.fields]",
            'register = { bits = [7, 0], grade = "inferred" }',
            'int = { bits = [15, 8], grade = "inferred" }',
            "[[words.W.tests]]", "value = 0x1234", "expect = { register = 0x34, int = 0x12 }"]))
        u = self.unit("kw")
        xml = gen_genxml.gen_genxml(u, "defs/kw.toml")
        self.assertIn('name="register_"', xml)
        self.assertIn('<expect field="register" value="52"/>', xml)      # the model's name stays in the extension elements
        r = self.build_and_run(u)
        self.assertEqual(r.returncode, 0, r.stdout)

    @unittest.skipUnless(CC, "no C compiler")
    def test_thirty_three_bit_field_survives(self):
        self.write("defs/w33.toml", "\n".join([
            'unit = "w33"', 'prefix = "W33"', 'from = "x"',
            "[words.W]", "width = 64", 'grade = "inferred"',
            "[words.W.fields]",
            'f = { bits = [40, 8], grade = "inferred" }',
            "[[words.W.tests]]", "value = 0x1ffffffff00", "expect = { f = 0x1ffffffff }"]))
        self.assertIn('type="address"', gen_genxml.gen_genxml(self.unit("w33"), "defs/w33.toml"))
        r = self.build_and_run(self.unit("w33"))
        self.assertEqual(r.returncode, 0, r.stdout)

    @unittest.skipUnless(CC, "no C compiler")
    def test_roundtrip_fails_when_the_layout_is_wrong(self):
        u = self.unit()
        vec = [t for t in u["registers"]["ctl"]["tests"] if t["kind"] == "vector"][0]
        vec["expect"]["divisor"] = 7
        r = self.build_and_run(u)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL ctl.divisor", r.stdout)

    def test_name_collision_is_refused(self):
        u = self.unit()
        u["words"]["CTL"] = dict(u["words"]["FRAME"])
        with self.assertRaises(GenError):
            gen_genxml.gen_genxml(u, "defs/uart.toml")


if __name__ == "__main__":
    unittest.main()
