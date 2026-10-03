#!/usr/bin/env python3
"""Repository-level entry point.

    python3 cryptoexp_cli.py analyze <file|dir|statement> [--json] [--solve] [--run]
    python3 cryptoexp_cli.py hypotheses <target>
    python3 cryptoexp_cli.py lab <target>
    python3 cryptoexp_cli.py list

The implementation lives in `src/cryptoexp/cli.py` so that the package can also be
installed (`pip install cryptoexp` → the `cryptoexp` console script) and imported
as a library. Running this file works from a bare clone, no installation needed.
"""

import os
import sys

# src layout: the importable package sits under src/, so a clone has to put that on
# the path. No installation, no site-packages writes.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "src"))

from cryptoexp.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
