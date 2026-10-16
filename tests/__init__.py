"""CIPH test suite package: make BOTH the tests dir and the repo root importable."""
import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
