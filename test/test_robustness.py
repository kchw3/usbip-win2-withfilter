"""Integration: Tier B robustness cases (attacks #9 and #10) via raw_gadget.

These probe the parts of the filter most likely to be weak:
  - malformed / inconsistent descriptors must fail closed (deny),
  - descriptor TOCTOU must not let Windows enumerate an interface the filter
    never evaluated.

Skipped unless test/config.ini exists AND the server has raw_gadget set up.
Run: pytest test/test_robustness.py -v
"""

from __future__ import annotations

import time

import pytest

MALFORMED_PID = "03F1"
TOCTOU_PID = "03F0"
VID = "16C0"

MALFORMED_VARIANTS = ["zero_interface", "lying_count", "bad_total_length"]


@pytest.mark.parametrize("variant", MALFORMED_VARIANTS)
def test_malformed_descriptors_fail_closed(linux, win, variant):
    """Every malformed variant must be denied and never enumerated."""
    win.set_policy(deny_all=False, allow=["mass_storage", "hid"])  # generous policy
    linux.start_raw_gadget("malformed_descriptors", env={"VARIANT": variant})
    time.sleep(1)
    try:
        attached = win.attach(linux.busid)
        present = win.pnp_present(VID, MALFORMED_PID)
        assert not attached, f"variant={variant} unexpectedly attached"
        assert not present, f"variant={variant} unexpectedly enumerated"
    finally:
        log = linux.stop_raw_gadget("malformed_descriptors")
        print(f"[server log:{variant}]\n{log}")


def test_descriptor_toctou_no_bypass(linux, win):
    """Server lies: benign config to the filter's fetch, malicious to Windows.

    Policy allows ONLY mass_storage. The desired secure outcome is that no HID
    interface that the filter never saw ends up enumerated by Windows. We baseline
    the present HID devices, attach, then diff: any NEW HID device is a bypass.
    """
    win.set_policy(allow=["mass_storage"])
    baseline = win.hid_instance_ids()

    linux.start_raw_gadget("toctou")
    time.sleep(1)
    try:
        win.attach(linux.busid)
        time.sleep(2)  # let Windows enumerate
        after = win.hid_instance_ids()
        new_hid = after - baseline
        assert not new_hid, (
            "TOCTOU BYPASS: Windows enumerated HID interface(s) the filter never "
            f"evaluated: {sorted(new_hid)}")
    finally:
        log = linux.stop_raw_gadget("toctou")
        print(f"[server log:toctou]\n{log}")
