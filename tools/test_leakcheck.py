#!/usr/bin/env python3
"""Tests for leakcheck.py: built-in patterns, private term sources, allow file, range mode, ci-check.

No test writes a real internal hostname: the forge host here is a placeholder, and the private
patterns are made-up words.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LEAK = os.path.join(HERE, "leakcheck.py")
CI = os.path.join(HERE, "defs", "ci-check")
FORGE_LINK = "https://forge.example.test/jamesb/chips/src/branch/main/docs/x.md"
DENYLIST = """
[[rules]]
id = "zz-domain"
regex = '''(?i)[a-z0-9._@-]*(zzprivhost)[a-z0-9._-]*'''
  [[rules.allowlists]]
  regexTarget = "match"
  regexes = ['''(?i)^ok@zzprivhost\\.test$''']
[[rules]]
id = "zz-net"
regex = '''(\\b10\\.77\\.0\\.|(?i)fdaa:bbcc)'''
"""


class LeakTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = os.path.join(self.tmp, "repo")
        os.makedirs(self.root)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("DENYLIST", "RE_LEAK_DENYLIST", "RE_LEAK_TERMS")}
        self.env.update(XDG_CONFIG_HOME=os.path.join(self.tmp, "xdg"), HOME=self.tmp,
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.test",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.test")
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        return subprocess.run(("git",) + args, cwd=self.root, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def write(self, rel, text, mode="w"):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, mode) as f:
            f.write(text)

    def commit(self, msg="change"):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def leak(self, *args, **env):
        e = dict(self.env, **env)
        return subprocess.run([sys.executable, "-I", LEAK, *args], cwd=self.root, env=e,
                              capture_output=True, text=True)


class BuiltinTest(LeakTest):
    def test_forge_link_fails_without_printing_the_host(self):
        self.write("docs/a.md", "see [page](%s)\n" % FORGE_LINK)
        self.commit()
        r = self.leak()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("docs/a.md:1: forge repository link", r.stdout)
        self.assertNotIn("forge.example.test", r.stdout + r.stderr)

    def test_other_forge_link_shapes_fail(self):
        for tail in ("raw/branch/main/x", "commit/abc123", "issues/4", "pulls/9"):
            with self.subTest(tail=tail):
                self.write("docs/a.md", "https://h.example.test/jamesb/odsy/%s\n" % tail)
                self.commit(tail)
                self.assertEqual(self.leak().returncode, 1)

    def test_plain_text_cross_reference_is_clean(self):
        self.write("docs/a.md", "see the kudzu repository, software/kernel/page.md page.\n"
                                "public: https://github.com/jamesbraid/odsy/blob/main/README.md\n")
        self.commit()
        r = self.leak()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_internal_paths_fail(self):
        for text in ("cache in /scratch/origami/x", "images at /storage/nvme/y",
                     "log /tmp/claude-1004/z", "run from /home/jamesb/src"):
            with self.subTest(text=text):
                self.write("n.md", text + "\n")
                self.commit(text)
                self.assertEqual(self.leak().returncode, 1)

    def test_public_web_paths_that_end_in_storage_are_not_paths(self):
        self.write("n.html", '<a href="/web/2001/http://www.sgi.com/products/storage/">x</a>\n')
        self.commit()
        self.assertEqual(self.leak().returncode, 0)

    def test_binary_file_is_skipped(self):
        self.write("blob.bin", b"\0\0 /scratch/x \0", mode="wb")
        self.commit()
        self.assertEqual(self.leak().returncode, 0)

    def test_head_message_is_checked(self):
        self.write("a.md", "fine\n")
        self.commit("docs: moved from /scratch/work")
        r = self.leak()
        self.assertEqual(r.returncode, 1)
        self.assertIn("message", r.stdout)

    def test_long_line_is_fast_and_still_found(self):
        self.write("a.md", "a" * 20000 + " /scratch/x\n")
        self.commit()
        t = time.time()
        r = self.leak(DENYLIST=DENYLIST)
        self.assertEqual(r.returncode, 1)
        self.assertLess(time.time() - t, 10)


class PrivateSourceTest(LeakTest):
    def test_denylist_env_hit_is_redacted(self):
        self.write("a.md", "box zzprivhost.lab is down\n")
        self.commit()
        r = self.leak(DENYLIST=DENYLIST)
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.md:1: denylist zz-domain: <", r.stdout)
        self.assertNotIn("zzprivhost", r.stdout + r.stderr)

    def test_denylist_inline_flag_in_the_middle_of_a_pattern(self):
        self.write("a.md", "net FDAA:BBCC::1\n")
        self.commit()
        self.assertEqual(self.leak(DENYLIST=DENYLIST).returncode, 1)

    def test_denylist_match_allowlist(self):
        self.write("a.md", "mail ok@zzprivhost.test\n")
        self.commit()
        self.assertEqual(self.leak(DENYLIST=DENYLIST).returncode, 0)

    def test_denylist_file(self):
        path = os.path.join(self.tmp, "deny.toml")
        with open(path, "w") as f:
            f.write(DENYLIST)
        self.write("a.md", "10.77.0.5\n")
        self.commit()
        self.assertEqual(self.leak(RE_LEAK_DENYLIST=path).returncode, 1)

    def test_ignored_term_file(self):
        self.write(".gitignore", ".re-leak-terms\n")
        self.write(".re-leak-terms", "# private\nzzprivhost\n")
        self.write("a.md", "ZZPRIVHOST\n")
        self.commit()
        r = self.leak()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("private term", r.stdout)

    def test_no_private_source_says_so_and_still_runs_builtins(self):
        self.write("a.md", "clean\n")
        self.commit()
        r = self.leak()
        self.assertEqual(r.returncode, 0)
        self.assertIn("built-in patterns only", r.stderr)

    def test_bad_denylist_is_a_tool_error(self):
        self.write("a.md", "clean\n")
        self.commit()
        self.assertEqual(self.leak(DENYLIST="[[rules]\n").returncode, 2)


class AllowTest(LeakTest):
    def test_allowed_string_is_removed_but_rest_of_line_checked(self):
        self.write("tools/config/leak-allow.txt", "/storage/nvme/golden\tdocumented fixture path\n")
        self.write("a.md", "see /storage/nvme/golden\n")
        self.write("b.md", "see /storage/nvme/golden and /scratch/x\n")
        self.commit()
        r = self.leak()
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("a.md", r.stdout)
        self.assertIn("b.md:1", r.stdout)

    def test_old_layout_allow_file(self):
        self.write("scripts/leak-allow.txt", "/storage/old\treason\n")
        self.write("a.md", "/storage/old\n")
        self.commit()
        self.assertEqual(self.leak().returncode, 0)

    def test_allow_line_needs_a_reason(self):
        self.write("tools/config/leak-allow.txt", "/storage/x\n")
        self.write("a.md", "ok\n")
        self.commit()
        r = self.leak()
        self.assertEqual(r.returncode, 2)
        self.assertIn("needs a reason", r.stderr)

    def test_allow_file_itself_is_not_checked(self):
        self.write("tools/config/leak-allow.txt", "/storage/x\treason\n")
        self.commit()
        self.assertEqual(self.leak().returncode, 0)


class RangeTest(LeakTest):
    def test_history_only_line_is_found_by_range_not_by_tree(self):
        self.write("a.md", "base\n")
        base = self.commit("base")
        self.write("a.md", "base\nlink %s\n" % FORGE_LINK)
        bad = self.commit("add link")
        self.write("a.md", "base\n")
        self.commit("drop link")
        self.assertEqual(self.leak().returncode, 0)
        r = self.leak("--range", "%s..HEAD" % base)
        self.assertEqual(r.returncode, 1)
        self.assertIn("%s a.md: forge repository link" % bad[:12], r.stdout)
        self.assertEqual(self.leak("--range", "%s..%s" % (base, base)).returncode, 0)

    def test_range_checks_messages(self):
        self.write("a.md", "base\n")
        base = self.commit("base")
        self.write("a.md", "more\n")
        self.commit("note: ran in /scratch/x")
        r = self.leak("--range", "%s..HEAD" % base)
        self.assertEqual(r.returncode, 1)
        self.assertIn("message", r.stdout)

    def test_unchanged_lines_are_not_blamed_on_the_range(self):
        self.write("a.md", "old /scratch/x\n")
        base = self.commit("base")
        self.write("b.md", "fine\n")
        self.commit("add b")
        self.assertEqual(self.leak("--range", "%s..HEAD" % base).returncode, 0)


class CiCheckTest(LeakTest):
    def ci(self):
        return subprocess.run([sys.executable, CI], cwd=self.root, env=self.env,
                              capture_output=True, text=True)

    def test_ci_check_fails_on_a_forge_link_in_a_git_checkout(self):
        self.write("docs/a.md", "[x](%s)\n" % FORGE_LINK)
        self.commit()
        r = self.ci()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAIL internal host or path in a tracked file", r.stderr)

    def test_ci_check_passes_a_clean_checkout(self):
        self.write("docs/a.md", "[x](kudzu repository, docs page)\n")
        self.commit()
        r = self.ci()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("no decode headers", r.stdout)

    def test_ci_check_skips_a_tree_that_is_not_a_checkout(self):
        shutil.rmtree(os.path.join(self.root, ".git"))
        self.write("docs/a.md", "[x](%s)\n" % FORGE_LINK)
        r = self.ci()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
