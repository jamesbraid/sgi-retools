#!/usr/bin/env python3
"""Entry point: run the config-driven publish-safety check (see publish_check.py)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from publish_check import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
