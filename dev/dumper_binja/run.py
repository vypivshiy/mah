"""
Bootstrap loader for the Binary Ninja packet dumper.

Usage in Binary Ninja (5+):
    1. Open the target .dll / .bndb
    2. Scripting console (Python) or Plugin Manager > Run Script...
    3. Select this file.

Or from BN headless CLI:
    $ python -c "import binaryninja; bv = binaryninja.BinaryViewType.get_view_of_file('core.dll'); ..." 
"""
import os
import sys
import logging
import importlib

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Force INFO-level console output regardless of BN's pre-existing logging config,
# so progress / completion messages are always visible. We raise the level rather
# than nuking existing handlers, to avoid silencing Binary Ninja's own log panel.
_root = logging.getLogger()
if _root.level == logging.NOTSET or _root.level > logging.INFO:
    _root.setLevel(logging.INFO)
if not any(isinstance(h, logging.StreamHandler) for h in _root.handlers):
    _root.addHandler(logging.StreamHandler())
for _mod in ("analyzer", "symbol_index", "binja_utils", "field_extractor"):
    logging.getLogger(_mod).setLevel(logging.INFO)

# Reload modules for iterative development
import binja_utils
import common
import template_parser
import type_parser
import field_extractor
import symbol_index
import analyzer
import PATCHES

importlib.reload(PATCHES)
importlib.reload(common)
importlib.reload(template_parser)
importlib.reload(type_parser)
importlib.reload(binja_utils)
importlib.reload(field_extractor)
importlib.reload(symbol_index)
importlib.reload(analyzer)

# Determine the BinaryView
try:
    bv  # noqa: F821 — provided by BN scripting environment
except NameError:
    try:
        from binaryninja import core
        active = core.active_view()
        if active is not None:
            bv = active
        else:
            raise RuntimeError("No active BinaryView found.")
    except Exception:
        raise RuntimeError(
            "No 'bv' available. Open a binary in Binary Ninja first, "
            "or pass bv explicitly."
        )

# Output path: same directory as the bndb, or script dir as fallback
try:
    _out_dir = os.path.dirname(bv.file.original_filename or bv.file.filename or "")
    if not _out_dir:
        _out_dir = ROOT
except Exception:
    _out_dir = ROOT

OUTPUT_PATH = os.path.join(_out_dir, "packets_binja.json")

if __name__ == "__main__":
    analyzer.main(bv, OUTPUT_PATH)
