"""Helpers shared by the defs tests: copy the fixture repo to a scratch directory."""
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
UNITS_FIXTURE = os.path.join(HERE, "testdata", "units")


class RepoTest(unittest.TestCase):
    """Each test gets its own copy of testdata/units as a repo root."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = os.path.join(self.tmp, "repo")
        shutil.copytree(UNITS_FIXTURE, self.root)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def read(self, rel):
        with open(self.path(rel), encoding="utf-8") as f:
            return f.read()

    def write(self, rel, text):
        full = self.path(rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)

    def edit(self, rel, old, new):
        text = self.read(rel)
        self.assertIn(old, text)
        self.write(rel, text.replace(old, new, 1))


def which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


OLD_FIXTURE = os.path.join(HERE, "testdata", "old")


class OldRepoTest(unittest.TestCase):
    """Each test gets its own copy of testdata/old: headers and a defs.toml in the old format."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = os.path.join(self.tmp, "repo")
        shutil.copytree(OLD_FIXTURE, self.root)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def read(self, rel):
        with open(self.path(rel), encoding="utf-8") as f:
            return f.read()

    def write(self, rel, text):
        full = self.path(rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)

    def edit(self, rel, old, new):
        text = self.read(rel)
        self.assertIn(old, text)
        self.write(rel, text.replace(old, new, 1))

    def git(self, *args):
        import subprocess
        return subprocess.run(["git", "-C", self.root, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                               "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, text=True)
