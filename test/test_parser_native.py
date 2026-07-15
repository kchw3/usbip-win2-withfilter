"""Compile and run the PRODUCTION descriptor parser on the host.

Phase 4 of VALIDATION_PLAN.md: rather than re-implementing the filter's parsing
in Python (which can drift from the driver), this compiles the exact header the
kernel driver uses (drivers/ude/device_filter_parser.h) via a small C++ driver
and runs its unit + fuzz cases. Requires a C++17 host compiler; skipped if none
is available (e.g. a minimal CI image).
Run: pytest test/test_parser_native.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
_SOURCE = _HERE / "native" / "parser_fuzz.cpp"


def _compiler() -> str | None:
    for candidate in (os.environ.get("CXX"), "c++", "g++", "clang++"):
        if candidate and shutil.which(candidate):
            return candidate
    return None


def test_production_parser_units_and_fuzz(tmp_path):
    cxx = _compiler()
    if cxx is None:
        pytest.skip("no C++17 host compiler (set $CXX or install g++/clang++)")

    binary = tmp_path / "parser_fuzz"
    compile_cmd = [cxx, "-std=c++17", "-O1", "-Wall", "-Wextra",
                   str(_SOURCE), "-o", str(binary)]
    compiled = subprocess.run(compile_cmd, capture_output=True, text=True)
    assert compiled.returncode == 0, (
        f"compiling the production parser failed:\n{compiled.stderr}")

    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
    sys.stdout.write(run.stdout)
    assert run.returncode == 0, (
        f"production parser checks failed:\n{run.stdout}\n{run.stderr}")
