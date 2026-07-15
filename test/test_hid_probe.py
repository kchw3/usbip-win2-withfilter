"""Pure unit tests for the HID endpoint-probe classifier.

Runs anywhere (no kernel, no gadget). Locks down the logic that decides whether
a HID injection failure is the known "endpoint never enabled" limitation (xfail)
or a real failure that must not be suppressed.
Run: pytest test/test_hid_probe.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "linux" / "payloads"))

import hid_type  # noqa: E402


def test_all_eshutdown_is_endpoint_disabled():
    assert hid_type.classify_endpoint_probe(
        ["eshutdown", "eshutdown", "eshutdown"]) == "endpoint_disabled"


def test_all_ok_is_live():
    assert hid_type.classify_endpoint_probe(["ok", "ok"]) == "live"


def test_ok_then_eagain_is_no_host_polling():
    assert hid_type.classify_endpoint_probe(["ok", "eagain", "eagain"]) == "no_host_polling"


def test_empty_is_unknown():
    assert hid_type.classify_endpoint_probe([]) == "unknown"


def test_mixed_with_eshutdown_is_unknown():
    # A transient ok followed by eshutdown is ambiguous; never claim disabled.
    assert hid_type.classify_endpoint_probe(["ok", "eshutdown"]) == "unknown"


def test_unexpected_errno_is_unknown():
    assert hid_type.classify_endpoint_probe(["errno_5"]) == "unknown"


def test_errno_token_mapping():
    import errno

    assert hid_type._errno_token(errno.ESHUTDOWN) == "eshutdown"
    assert hid_type._errno_token(errno.EAGAIN) == "eagain"
    assert hid_type._errno_token(errno.EIO) == f"errno_{errno.EIO}"
