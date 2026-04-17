"""Entry point shim — the package lives in tunnel_manager/.

Keeps `python main.py` working without requiring the package to be installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make sure the package directory is importable when running from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tunnel_manager.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
