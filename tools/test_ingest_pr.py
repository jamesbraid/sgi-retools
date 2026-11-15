#!/usr/bin/env python3
"""Tests for ingest-pr: fast-forward and rebase detection, the submodule-pin check, dry run and --push.

Everything runs on throwaway local repositories reached by file:// URLs; nothing touches the network.
The setup-clone and ci-check checks need a full workspace, so the tests replace run_checks.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("ingest_pr", os.path.join(HERE, "ingest-pr"))
_spec = importlib.util.spec_from_loader("ingest_pr", _loader)
ip = importlib.util.module_from_spec(_spec)
_loader.exec_module(ip)

GIT_ENV = dict(GIT_AUTHOR_NAME="Pat", GIT_AUTHOR_EMAIL="pat@example.test",
               GIT_COMMITTER_NAME="Pat", GIT_COMMITTER_EMAIL="pat@example.test",
               GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")


def git(cwd, *args):
    env = dict(os.environ, **GIT_ENV)
    p = subprocess.run(("git",) + args, cwd=cwd, env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise AssertionError("git %s: %s" % (" ".join(args), p.stderr))
    return p.stdout.strip()


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for k, v in GIT_ENV.items():
            old = os.environ.get(k)
            os.environ[k] = v
            self.addCleanup(lambda k=k, old=old: os.environ.pop(k, None) if old is None
                            else os.environ.__setitem__(k, old))
        self.forge = self.mk_bare("forge.git")
        self.github = self.mk_bare("github.git")
        self.ws = os.path.join(self.tmp, "ws")
        git(self.tmp, "clone", "-q", self.forge, self.ws)
        self.commit(self.ws, "base.txt", "base\n", "base")
        git(self.ws, "branch", "-M", "main")
        git(self.ws, "push", "-q", "origin", "main")
        git(self.ws, "push", "-q", self.github, "main")
        self.base = git(self.ws, "rev-parse", "HEAD")

    def mk_bare(self, name):
        path = os.path.join(self.tmp, name)
        git(self.tmp, "init", "-q", "--bare", "-b", "main", path)
        return path

    def commit(self, repo, name, text, msg):
        with open(os.path.join(repo, name), "w") as f:
            f.write(text)
        git(repo, "add", name)
        git(repo, "commit", "-q", "-m", msg)
        return git(repo, "rev-parse", "HEAD")

    def contributor(self):
        """A clone of the mirror to build a PR in; returns its path."""
        path = os.path.join(self.tmp, "contrib")
        if not os.path.isdir(path):
            git(self.tmp, "clone", "-q", self.github, path)
        return path

    def make_pr(self, number, name="pr.txt"):
        c = self.contributor()
        git(c, "checkout", "-q", "-B", "pr%d" % number, "origin/main")
        sha = self.commit(c, name, "from the PR\n", "add " + name)
        git(c, "push", "-q", self.github, "pr%d:refs/pull/%d/head" % (number, number))
        return sha

    def advance_forge(self):
        self.commit(self.ws, "other.txt", "moved\n", "forge moves on")
        git(self.ws, "push", "-q", "origin", "main")
        git(self.ws, "reset", "-q", "--hard", self.base)

    def run_tool(self, *argv, results=None):
        calls = []

        def fake(ws, base, origin, root):
            calls.append(root)
            return results if results is not None else [("fake check", True, "ok")]
        old = ip.run_checks
        ip.run_checks = fake
        self.addCleanup(setattr, ip, "run_checks", old)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ip.main(["--repo", self.ws, "--github", self.github] + list(argv))
        return rc, out.getvalue(), err.getvalue(), calls

    def forge_main(self):
        return git(self.forge, "rev-parse", "main")

    def test_fast_forward_keeps_hash_and_dry_run_does_not_push(self):
        sha = self.make_pr(1)
        rc, out, _, _ = self.run_tool("1")
        self.assertEqual(rc, 0, out)
        self.assertIn("yes, hashes are kept", out)
        self.assertIn("add pr.txt", out)
        self.assertIn("pr.txt", out)
        self.assertIn("Nothing. The PR head", out)
        self.assertEqual(git(self.ws, "rev-parse", "ingest/pr-1"), sha)
        self.assertEqual(self.forge_main(), self.base)

    def test_rebase_needed_changes_hash_keeps_author(self):
        sha = self.make_pr(2)
        self.advance_forge()
        rc, out, _, _ = self.run_tool("2")
        self.assertEqual(rc, 0, out)
        self.assertIn("no, origin/main has moved", out)
        self.assertIn("new hashes", out)
        self.assertIn("Close PR #2", out)
        new = git(self.ws, "rev-parse", "ingest/pr-2")
        self.assertNotEqual(new, sha)
        self.assertEqual(git(self.ws, "log", "-1", "--format=%an", new), "Pat")
        self.assertEqual(git(self.ws, "rev-parse", new + "~1"), git(self.ws, "rev-parse", "origin/main"))
        self.assertEqual(git(self.ws, "log", "-1", "--format=%at", new), git(self.ws, "log", "-1", "--format=%ct", new))

    def test_rebase_conflict_is_reported(self):
        self.make_pr(3, "other.txt")
        self.advance_forge()
        rc, out, _, _ = self.run_tool("3")
        self.assertEqual(rc, 1)
        self.assertIn("REBASE FAILED", out)

    def test_github_main_mode(self):
        c = self.contributor()
        sha = self.commit(c, "direct.txt", "merged on github\n", "merged directly")
        git(c, "push", "-q", "origin", "HEAD:main")
        rc, out, _, _ = self.run_tool("--github-main", "--push")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.forge_main(), sha)

    def test_already_ingested_is_a_no_op(self):
        self.make_pr(4)
        self.run_tool("4", "--push")
        rc, out, _, _ = self.run_tool("4")
        self.assertEqual(rc, 0)
        self.assertIn("Nothing to ingest", out)

    def test_push_refuses_failed_check_and_allow_failing_overrides(self):
        sha = self.make_pr(5)
        bad = [("leak check", False, "exit 1"), ("ci-check", True, "exit 0")]
        rc, out, _, _ = self.run_tool("5", "--push", results=bad)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL  leak check", out)
        self.assertIn("Refusing to push: leak check", out)
        self.assertEqual(self.forge_main(), self.base)
        rc, out, _, _ = self.run_tool("5", "--push", "--allow-failing", results=bad)
        self.assertEqual(rc, 0, out)
        self.assertIn("Pushing with failing check(s): leak check", out)
        self.assertEqual(self.forge_main(), sha)

    def test_push_passes_root_through_and_pushes_rebased(self):
        self.make_pr(6)
        self.advance_forge()
        rc, out, _, calls = self.run_tool("6", "--push", "--root", "/some/root")
        self.assertEqual(rc, 0, out)
        self.assertEqual(calls, ["/some/root"])
        self.assertEqual(self.forge_main(), git(self.ws, "rev-parse", "ingest/pr-6"))

    def test_cherry_equivalent_commit_is_already_present(self):
        self.make_pr(8, "pr.txt")
        self.advance_forge()
        # same patch landed on the forge under another hash
        git(self.ws, "fetch", "-q", "origin")
        git(self.ws, "reset", "-q", "--hard", "origin/main")
        git(self.ws, "fetch", "-q", self.github, "refs/pull/8/head")
        git(self.ws, "cherry-pick", "FETCH_HEAD")
        git(self.ws, "commit", "-q", "--amend", "-m", "add pr.txt (forge copy)")
        git(self.ws, "push", "-q", "origin", "HEAD:main")
        rc, out, _, calls = self.run_tool("8", "--push")
        self.assertEqual(rc, 0, out)
        self.assertIn("Already on origin/main (every commit has an equivalent patch", out)
        self.assertIn("Matching origin/main commit: " + git(self.ws, "rev-parse", "HEAD"), out)
        self.assertNotIn("Forge commits:", out)
        self.assertNotIn("forge.git/", out.split("On GitHub")[-1])
        self.assertEqual(calls, [])
        self.assertEqual(self.forge_main(), git(self.ws, "rev-parse", "HEAD"))

    def test_squash_merged_multi_commit_pr_is_already_present(self):
        c = self.contributor()
        git(c, "checkout", "-q", "-B", "pr9", "origin/main")
        self.commit(c, "a.txt", "one\n", "start a")
        self.commit(c, "a.txt", "one\ntwo\n", "finish a")
        self.commit(c, "b.txt", "b\n", "add b")
        git(c, "push", "-q", self.github, "pr9:refs/pull/9/head")
        self.advance_forge()
        # squash on the forge: one commit with the net effect and a different message
        git(self.ws, "fetch", "-q", "origin")
        git(self.ws, "reset", "-q", "--hard", "origin/main")
        git(self.ws, "fetch", "-q", self.github, "refs/pull/9/head")
        git(self.ws, "merge", "-q", "--squash", "FETCH_HEAD")
        git(self.ws, "commit", "-q", "-m", "add a and b (#9)")
        git(self.ws, "push", "-q", "origin", "HEAD:main")
        squash = git(self.ws, "rev-parse", "HEAD")
        rc, out, _, calls = self.run_tool("9", "--push")
        self.assertEqual(rc, 0, out)
        self.assertIn("identical there, as after a squash merge", out)
        self.assertIn("Matching origin/main commit: " + squash, out)
        self.assertIn("Close PR #9 as already merged", out)
        self.assertNotIn("Forge commits:", out)
        self.assertNotIn("forge.git/", out.split("On GitHub")[-1])
        self.assertEqual(calls, [])
        self.assertEqual(self.forge_main(), squash)

    def test_advice_links_the_github_mirror_never_the_forge(self):
        c = self.contributor()
        git(c, "checkout", "-q", "-B", "pr10", "origin/main")
        self.commit(c, "m.txt", "m\n", "add m")
        git(c, "push", "-q", self.github, "pr10:refs/pull/10/head")
        git(self.ws, "fetch", "-q", self.github, "refs/pull/10/head")
        git(self.ws, "cherry-pick", "FETCH_HEAD")
        git(self.ws, "commit", "-q", "--amend", "-m", "add m (forge copy)")
        git(self.ws, "push", "-q", "origin", "HEAD:main")
        sha = git(self.ws, "rev-parse", "HEAD")
        old = ip.mirror_commit_base
        ip.mirror_commit_base = lambda mirror: "https://github.com/o/r/commit/"
        self.addCleanup(setattr, ip, "mirror_commit_base", old)
        rc, out, _, _ = self.run_tool("10")
        self.assertEqual(rc, 0, out)
        self.assertIn("linking https://github.com/o/r/commit/" + sha, out)
        self.assertIn("appears on the mirror once the publication run has pushed", out)
        self.assertNotIn(self.forge, out.split("On GitHub")[-1])

    def test_dirty_tree_is_a_tool_error(self):
        self.make_pr(7)
        with open(os.path.join(self.ws, "base.txt"), "a") as f:
            f.write("edit\n")
        rc, _, err, _ = self.run_tool("7")
        self.assertEqual(rc, 2)
        self.assertIn("uncommitted", err)


class SubmoduleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for k, v in GIT_ENV.items():
            old = os.environ.get(k)
            os.environ[k] = v
            self.addCleanup(lambda k=k, old=old: os.environ.pop(k, None) if old is None
                            else os.environ.__setitem__(k, old))
        self.sub = os.path.join(self.tmp, "sub")
        git(self.tmp, "init", "-q", "-b", "main", self.sub)
        with open(os.path.join(self.sub, "f"), "w") as f:
            f.write("1\n")
        git(self.sub, "add", "f")
        git(self.sub, "commit", "-q", "-m", "one")
        self.good = git(self.sub, "rev-parse", "HEAD")
        self.ws = os.path.join(self.tmp, "ws")
        git(self.tmp, "init", "-q", "-b", "main", self.ws)
        git(self.ws, "remote", "add", "origin", "file://" + os.path.join(self.tmp, "forge.git"))
        with open(os.path.join(self.ws, "x"), "w") as f:
            f.write("x\n")
        git(self.ws, "add", "x")
        git(self.ws, "commit", "-q", "-m", "base")
        self.base = git(self.ws, "rev-parse", "HEAD")
        with open(os.path.join(self.ws, ".gitmodules"), "w") as f:
            f.write('[submodule "lib"]\n\tpath = deps/lib\n\turl = file://%s\n' % self.sub)
        git(self.ws, "add", ".gitmodules")

    def pin(self, sha):
        git(self.ws, "update-index", "--add", "--cacheinfo", "160000,%s,deps/lib" % sha)
        git(self.ws, "commit", "-q", "-m", "pin " + sha[:7])

    def origin(self):
        return ip.remote_url(self.ws, "origin")

    def test_reachable_pin_passes(self):
        self.pin(self.good)
        ok, detail = ip.check_submodules(self.ws, self.base, self.origin())
        self.assertTrue(ok, detail)
        self.assertIn("1 submodule pin", detail)

    def test_unreachable_pin_fails(self):
        self.pin("1234567890abcdef1234567890abcdef12345678")
        ok, detail = ip.check_submodules(self.ws, self.base, self.origin())
        self.assertFalse(ok)
        self.assertIn("deps/lib 1234567890ab is not fetchable", detail)

    def test_no_pin_change_passes(self):
        git(self.ws, "commit", "-q", "--allow-empty", "-m", "empty")
        ok, detail = ip.check_submodules(self.ws, self.base, self.origin())
        self.assertTrue(ok)
        self.assertIn("no submodule pin changed", detail)


class UrlTest(unittest.TestCase):
    def test_github_urls_become_https(self):
        self.assertEqual(ip.https_github("git@github.com:o/r.git"), "https://github.com/o/r.git")
        self.assertEqual(ip.https_github("https://github.com/o/r"), "https://github.com/o/r.git")
        self.assertEqual(ip.https_github("file:///tmp/x.git"), "file:///tmp/x.git")

    def test_mirror_commit_base(self):
        self.assertEqual(ip.mirror_commit_base("https://github.com/o/r.git"), "https://github.com/o/r/commit/")
        self.assertEqual(ip.mirror_commit_base("git@github.com:o/r.git"), "https://github.com/o/r/commit/")
        self.assertIsNone(ip.mirror_commit_base("file:///tmp/github.git"))


if __name__ == "__main__":
    unittest.main()
