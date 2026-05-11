"""
Bootstrap loader for the IDA packet dumper.

Usage in IDA:
    File > Script file... (or Alt+F7) and select this file.
"""
import os
import sys
import importlib

ROOT = os.path.dirname(__file__)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import field_extractor
import analyzer
import PATCHES
importlib.reload(PATCHES)
importlib.reload(field_extractor)
importlib.reload(analyzer)

analyzer.main()
