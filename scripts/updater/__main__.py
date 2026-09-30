"""CLI execution entrypoint for scripts.updater."""

from __future__ import annotations

import sys

from scripts.updater.updater import main

if __name__ == "__main__":
    sys.exit(main())
