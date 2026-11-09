"""Find the workspace a tool reads and writes.

The workspace is the repository holding root/, docs/ and scripts/inventory-config.json. Tools live
in the retools submodule, so their own path says nothing about it. In priority order: an explicit
directory (a tool's --repo), $ORIGAMI_RE_WORKSPACE, the top of the git work tree around the
current directory, the current directory itself.

A tool's own data and sibling scripts stay relative to its __file__; only the workspace comes from here.
tools/re-run does the same in shell and passes the result into the container.
"""
import os
import subprocess

ENV = 'ORIGAMI_RE_WORKSPACE'


def find_workspace(explicit=None):
    path = explicit or os.environ.get(ENV)
    if not path:
        try:
            r = subprocess.run(['git', '-C', '.', 'rev-parse', '--show-toplevel'],
                               capture_output=True, text=True, encoding='utf-8')
            if r.returncode == 0 and r.stdout.strip():
                path = r.stdout.strip()
        except OSError:
            pass
    return os.path.abspath(path or os.getcwd())


def repo_arg(argv):
    """The value of --repo in argv, for tools that need the workspace before argparse runs."""
    for i, a in enumerate(argv):
        if a == '--repo':
            return argv[i + 1] if i + 1 < len(argv) else None
        if a.startswith('--repo='):
            return a.split('=', 1)[1]
    return None
