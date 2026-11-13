"""Structured hardware definitions: loader, model, checks and generators.

One TOML file per hardware block (devices/<unit>/registers.toml) is the source. Everything
else, the C, Rust, Python, JSON, genxml and documentation outputs, is generated
from the model this package builds. See ../README.md.
"""
import os
import sys

# tools/_layout.py, shared with every other tool that names a workspace path
_TOOLS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)
