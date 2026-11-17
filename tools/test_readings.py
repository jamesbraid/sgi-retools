#!/usr/bin/env python3
"""Readings are filed by subject and binary."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _readings  # noqa: E402

BATCH = """# A batch

Preface text.

- `a` in `IP27/usr/cpu/sysgen/IP27boot/pcibr.o` at 0x20 (n64).
  Evidence grade: inferred.
  It stores to a0.

- `b` in `IP27/usr/cpu/sysgen/IP27boot/pcibr.o` at 0x10 (n64).
  Reviewed: 2026-11-12

- `c` in `IP35/unix` at 0x30 (n64).
  See [the page](../devices/x/README.md).

### `d` in `sbin/stand/symmon.IP32` at 0x40

Prose of a heading entry.

Skipped routines: none.
"""

RULES = {"default": "software/kernel/{1}",
         "rules": [{"match": "/pcibr\\.o$", "dir": "devices/bridge"},
                   {"match": "^sbin/stand/", "dir": "software/firmware"}]}


class Repo(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.ws)
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.org")
        self.git("config", "user.name", "t")
        self.write("tools/config/readings-subjects.json", json.dumps(RULES))
        self.git("add", "-A")
        self.git("commit", "-qm", "start")

    def git(self, *a):
        return subprocess.run(("git", "-C", self.ws) + a, check=True, capture_output=True, text=True).stdout

    def write(self, rel, text):
        p = os.path.join(self.ws, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def read(self, rel):
        with open(os.path.join(self.ws, rel)) as f:
            return f.read()


class ParseTests(unittest.TestCase):
    def test_entries_and_stray_text(self):
        entries, stray = _readings.parse(BATCH)
        self.assertEqual([b for b, _ in entries], ["IP27/usr/cpu/sysgen/IP27boot/pcibr.o"] * 2
                         + ["IP35/unix", "sbin/stand/symmon.IP32"])
        self.assertEqual(stray, ["# A batch", "Preface text."])
        self.assertIn("Skipped routines: none.", "\n".join(entries[-1][1]))     # a heading entry owns the text below it

    def test_file_names(self):
        self.assertEqual(_readings.reading_name("IP27/usr/cpu/sysgen/IP27boot/pcibr.o"), "IP27-pcibr.o.md")
        self.assertEqual(_readings.reading_name("IP32/usr/cpu/sysgen/IP32boot/crime.a(crime_i2c.o)"),
                         "IP32-crime.a-crime_i2c.o.md")
        self.assertEqual(_readings.reading_name("sbin/stand/symmon.IP32"), "sbin-stand-symmon.IP32.md")


class FileEntriesTests(Repo):
    def test_entries_go_to_the_page_of_their_binary(self):
        pages = _readings.file_entries(self.ws, BATCH)
        self.assertEqual(pages, ["devices/bridge/readings/IP27-pcibr.o.md", "software/firmware/readings/sbin-stand-symmon.IP32.md",
                                 "software/kernel/ip35/readings/IP35-unix.md"])
        again = _readings.file_entries(self.ws, "- `e` in `IP27/usr/cpu/sysgen/IP27boot/pcibr.o` at 0x50\n  Text.\n")
        self.assertEqual(again, ["devices/bridge/readings/IP27-pcibr.o.md"])
        text = self.read("devices/bridge/readings/IP27-pcibr.o.md")
        self.assertEqual(text.count("\n- `"), 3)
        self.assertTrue(text.startswith("# Readings: `IP27/usr/cpu/sysgen/IP27boot/pcibr.o`"))


if __name__ == "__main__":
    unittest.main()
