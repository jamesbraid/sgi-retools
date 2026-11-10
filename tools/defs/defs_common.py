"""Shared helpers for the decode-header tools: config loading and reporting.

A repo describes its decode headers in one TOML file (conventionally
`defs.toml` at the repo root). Relative paths in it are relative to
`[project] root`, which itself defaults to the directory holding the file.
See README.md for the schema.
"""
import os
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.exit('error: Python 3.11 or newer is required (tomllib)')

GRADES = ('established', 'inferred', 'unknown')


class ConfigError(Exception):
    pass


def load_config(path):
    """Return (cfg, root) for a defs.toml path."""
    path = os.path.abspath(path)
    try:
        with open(path, 'rb') as f:
            cfg = tomllib.load(f)
    except OSError as e:
        raise ConfigError('cannot read %s: %s' % (path, e))
    except tomllib.TOMLDecodeError as e:
        raise ConfigError('%s: %s' % (path, e))
    proj = cfg.setdefault('project', {})
    if not proj.get('name'):
        raise ConfigError('%s: [project] name is required' % path)
    if not cfg.get('headers'):
        raise ConfigError('%s: at least one [[headers]] entry is required' % path)
    for h in cfg['headers']:
        if not h.get('file'):
            raise ConfigError('%s: a [[headers]] entry has no file' % path)
    root = os.path.normpath(os.path.join(os.path.dirname(path), proj.get('root', '.')))
    return cfg, root


class Report:
    """Collects failures. A silent report counts but does not print."""

    def __init__(self, silent=False):
        self.fails = []
        self.silent = silent

    def fail(self, where, msg):
        self.fails.append('%s: %s' % (where, msg))
        if not self.silent:
            print('FAIL %s: %s' % (where, msg))


def read_file(root, path):
    with open(os.path.join(root, path), encoding='utf-8') as f:
        return f.read()
