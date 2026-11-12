"""
conftest.py — pytest path setup for P15 HAL

Function:
    Puts the sibling P1, P2 and P4 repositories (../envelope-layer,
    ../sign-layer, ../ledger-layer) and this repository on sys.path,
    resolved relative to this file rather than the current working
    directory, so `pytest` works from any directory. v1 hal.py and
    test_hal.py resolve the paths against the CWD and are frozen; this
    file is the layer that fixes that without editing them.
"""

import os
import sys

# ---------------------------------------------------------------------------
# 1. Module-level path setup
#    Runs once when pytest loads this conftest, before test collection.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
for _name in ("ledger-layer", "sign-layer", "envelope-layer"):
    _path = os.path.normpath(os.path.join(_HERE, "..", _name))
    if _path not in sys.path:
        sys.path.insert(0, _path)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
