"""Pure unit tests for the descriptor builders and the decision model.

These run anywhere (no lab, no kernel) so the harness logic itself is covered.
Run: pytest test/test_descriptors.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "linux" / "raw_gadget"))

import toctou as toctou_profile  # noqa: E402
import usb_descriptors as d  # noqa: E402
from _raw_gadget import GET_DESCRIPTOR, ControlRequest  # noqa: E402

from devices import DEVICES, expected_allow  # noqa: E402


def _iface_count(cfg: bytes) -> int:
    i, n = 0, 0
    while i + 2 <= len(cfg):
        blen, btype = cfg[i], cfg[i + 1]
        if blen == 0:
            break
        if btype == d.DT_INTERFACE:
            n += 1
        i += blen
    return n


def test_benign_config_has_one_mass_storage_interface():
    cfg = d.benign_mass_storage_config()
    assert cfg[1] == d.DT_CONFIG
    assert _iface_count(cfg) == 1


def test_malicious_config_adds_hid():
    cfg = d.malicious_ms_plus_hid_config()
    assert _iface_count(cfg) == 2
    # second interface should be HID
    assert d.CLASS_HID in cfg


def test_zero_interface_config_lies_about_count():
    cfg = d.zero_interface_config()
    # bNumInterfaces is byte index 4 of the config header
    assert cfg[4] == 1
    assert _iface_count(cfg) == 0


def test_lying_count_config():
    cfg = d.lying_num_interfaces_config()
    assert cfg[4] == 0          # claims zero
    assert _iface_count(cfg) == 1  # but has one


def _get_config_request(length: int) -> ControlRequest:
    return ControlRequest(
        bmRequestType=0x80,
        bRequest=GET_DESCRIPTOR,
        wValue=d.DT_CONFIG << 8,
        wIndex=0,
        wLength=length,
    )


def test_toctou_profile_changes_only_after_filter_snapshot():
    benign = d.benign_mass_storage_config()
    malicious = d.malicious_ms_plus_hid_config()
    toctou_profile._config_request_count = 0

    header = toctou_profile.on_control(_get_config_request(9))
    full = toctou_profile.on_control(_get_config_request(len(benign)))
    changed = toctou_profile.on_control(_get_config_request(len(malicious)))

    assert header is not None and header[:9] == benign[:9]
    assert full == benign
    assert changed == malicious


def test_decision_model_composite_requires_both():
    assert expected_allow("allow_ms", "composite_ms_hid") is False
    assert expected_allow("allow_hid", "composite_ms_hid") is False
    assert expected_allow("allow_hid_ms", "composite_ms_hid") is True


def test_decision_model_disabled_allows_all():
    for key in DEVICES:
        assert expected_allow("disabled", key) is True


def test_decision_model_deny_all_blocks_all():
    for key in DEVICES:
        assert expected_allow("deny_all", key) is False
