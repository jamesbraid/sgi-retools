#!/usr/bin/env python3
"""Tests for the layout resolver: the current layout, the old one, and a workspace part-way between."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _layout  # noqa: E402
from _layout import Layout  # noqa: E402


class LayoutTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def touch(self, rel, text=""):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def lay(self):
        return Layout(self.root)


class ConfigTest(LayoutTest):
    def test_current_files_are_found_under_tools_config(self):
        for n in ("inventory-config.json", "inventory-root.sha256", "inventory-siblings.json", "binaries_manifest.json", "scope.json"):
            self.touch("tools/config/" + n)
        lay = self.lay()
        self.assertEqual(lay.inventory_config, "tools/config/inventory-config.json")
        self.assertEqual(lay.root_manifest, "tools/config/inventory-root.sha256")
        self.assertEqual(lay.sibling_pins, "tools/config/inventory-siblings.json")
        self.assertEqual(lay.binaries_manifest, "tools/config/binaries_manifest.json")
        self.assertEqual(lay.scope_file, "tools/config/scope.json")

    def test_old_files_are_found_under_scripts_and_the_top(self):
        for n in ("scripts/inventory-config.json", "scripts/inventory-root.sha256", "scripts/inventory-siblings.json",
                  "scripts/scope.json", "binaries_manifest.json", "defs/check.toml", "defs/legacy-dropped.txt"):
            self.touch(n)
        lay = self.lay()
        self.assertEqual(lay.inventory_config, "scripts/inventory-config.json")
        self.assertEqual(lay.root_manifest, "scripts/inventory-root.sha256")
        self.assertEqual(lay.sibling_pins, "scripts/inventory-siblings.json")
        self.assertEqual(lay.scope_file, "scripts/scope.json")
        self.assertEqual(lay.binaries_manifest, "binaries_manifest.json")
        self.assertEqual(lay.defs_check_file, "defs/check.toml")
        self.assertEqual(lay.legacy_dropped_file, "defs/legacy-dropped.txt")

    def test_current_wins_when_both_exist(self):
        self.touch("scripts/inventory-config.json")
        self.touch("tools/config/inventory-config.json")
        self.assertEqual(self.lay().inventory_config, "tools/config/inventory-config.json")

    def test_defs_settings_move_to_tools_config(self):
        self.touch("tools/config/defs-check.toml")
        self.touch("tools/config/defs-legacy-dropped.txt")
        lay = self.lay()
        self.assertEqual(lay.defs_check_file, "tools/config/defs-check.toml")
        self.assertEqual(lay.legacy_dropped_file, "tools/config/defs-legacy-dropped.txt")

    def test_a_missing_file_is_where_the_workspace_keeps_such_files(self):
        self.touch("scripts/other.json")                     # an old workspace
        self.assertEqual(self.lay().inventory_config, "scripts/inventory-config.json")
        self.touch("tools/config/other.json")                # now it shows the current layout too
        self.assertEqual(self.lay().inventory_config, "tools/config/inventory-config.json")

    def test_an_empty_workspace_gets_the_current_layout(self):
        lay = self.lay()
        self.assertEqual(lay.inventory_config, "tools/config/inventory-config.json")
        self.assertEqual(lay.inventory_dir, "evidence/inventory")
        self.assertEqual(lay.readings_dir, "evidence")


class EvidenceTest(LayoutTest):
    def test_current_evidence(self):
        for n in ("evidence/inventory/functions.tsv", "evidence/coverage.md", "evidence/routines/a.md"):
            self.touch(n)
        lay = self.lay()
        self.assertEqual(lay.inventory_dir, "evidence/inventory")
        self.assertEqual(lay.functions_table, "evidence/inventory/functions.tsv")
        self.assertEqual(lay.audits_file, "evidence/inventory/audits.tsv")
        self.assertEqual(lay.coverage_file, "evidence/coverage.md")
        self.assertEqual(lay.routines_dir, "evidence/routines")

    def test_old_evidence(self):
        for n in ("docs/inventory/functions.tsv", "docs/coverage.md", "docs/routines/a.md"):
            self.touch(n)
        lay = self.lay()
        self.assertEqual(lay.inventory_dir, "docs/inventory")
        self.assertEqual(lay.functions_table, "docs/inventory/functions.tsv")
        self.assertEqual(lay.coverage_file, "docs/coverage.md")
        self.assertEqual(lay.routines_dir, "docs/routines")
        self.assertEqual(lay.readings_dir, "docs")

    def test_readings_follow_the_pages_that_exist(self):
        self.touch("docs/instruction-readings-x-g1.md")
        self.touch("evidence/other.md")
        self.assertEqual(self.lay().readings_dir, "docs")
        self.touch("evidence/instruction-readings-x-g2.md")
        self.assertEqual(self.lay().readings_dir, "evidence")

    def test_census_directory(self):
        self.touch("chips/heart/census/census.tsv")
        self.assertEqual(self.lay().census_dir("heart"), "chips/heart/census")
        self.touch("devices/heart/census/census.tsv")
        self.assertEqual(self.lay().census_dir("heart"), "devices/heart/census")


class SourcesTest(LayoutTest):
    def test_register_sources_in_the_current_layout(self):
        for n in ("devices/bridge/registers.toml", "devices/bridge/registers.xbridge.toml", "devices/bridge/registers-extra.toml",
                  "devices/bridge/README.md", "devices/bridge/notes.toml", "formats/efs/format.toml", "formats/efs/registers.toml",
                  "devices/heart/registers.toml"):
            self.touch(n)
        got = [(s.rel, s.kind, s.rev) for s in self.lay().register_sources()]
        self.assertEqual(got, [
            ("devices/bridge/registers-extra.toml", "extra", None),
            ("devices/bridge/registers.toml", "base", None),
            ("devices/bridge/registers.xbridge.toml", "overlay", "xbridge"),
            ("devices/heart/registers.toml", "base", None),
            ("formats/efs/format.toml", "base", None)])
        self.assertEqual(self.lay().defs_mode, "new")

    def test_old_sources_skip_the_settings_file(self):
        for n in ("defs/a.toml", "defs/a.rev.toml", "defs/check.toml", "defs/a_helpers.h"):
            self.touch(n)
        lay = self.lay()
        self.assertEqual([s.rel for s in lay.old_sources()], ["defs/a.rev.toml", "defs/a.toml"])
        self.assertEqual(lay.defs_mode, "old")

    def test_no_register_maps(self):
        self.touch("README.md")
        lay = self.lay()
        self.assertIsNone(lay.defs_mode)
        self.assertFalse(lay.has_defs())

    def test_an_empty_devices_directory_is_not_a_register_map(self):
        os.makedirs(os.path.join(self.root, "devices", "x"))
        self.assertIsNone(self.lay().defs_mode)


class GeneratedPathsTest(LayoutTest):
    class U:
        def __init__(self, name, dirname=None, stem=None):
            self.name, self.dir, self.stem = name, dirname, stem

    def test_current_outputs(self):
        self.touch("devices/u/registers.toml")
        lay = self.lay()
        self.assertEqual(lay.gen_root(), "generated")
        self.assertEqual([lay.gen_file(k, "u") for k in ("c", "py", "json", "xml")],
                         ["generated/c/u.h", "generated/python/u.py", "generated/json/u.json", "generated/xml/u.xml"])
        self.assertEqual(lay.gen_dir("rust"), "generated/rust")
        self.assertEqual(lay.doc_file(self.U("u", "devices/u", "registers")), "devices/u/registers.md")
        self.assertEqual(lay.doc_file(self.U("u_x", "devices/u", "registers.x")), "devices/u/registers.x.md")
        self.assertEqual(lay.doc_file(self.U("f", "formats/f", "format")), "formats/f/format.md")
        self.assertEqual(lay.helpers_file(self.U("u", "devices/u", "registers")), "devices/u/helpers.h")
        self.assertEqual(lay.helpers_file(self.U("u_x", "devices/u", "registers.x")), "devices/u/helpers.x.h")
        self.assertEqual(lay.helpers_file(self.U("u_e", "devices/u", "registers-extra")), "devices/u/helpers-extra.h")

    def test_old_outputs(self):
        self.touch("defs/u.toml")
        lay = self.lay()
        self.assertEqual(lay.gen_root(), "gen")
        self.assertEqual([lay.gen_file(k, "u") for k in ("c", "py", "json", "xml")],
                         ["gen/c/u.h", "gen/py/u.py", "gen/json/u.json", "gen/genxml/u.xml"])
        self.assertEqual(lay.doc_file(self.U("u")), "gen/docs/u.md")
        self.assertEqual(lay.helpers_file(self.U("u")), "defs/u_helpers.h")


class WorkspaceTest(LayoutTest):
    def test_of_takes_a_root(self):
        self.assertEqual(_layout.of(self.root).root, os.path.abspath(self.root))


if __name__ == "__main__":
    unittest.main()
