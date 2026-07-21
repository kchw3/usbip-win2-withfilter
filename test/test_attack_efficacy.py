"""Negative control: prove the simulations are REAL attacks when the filter is OFF.

Each test disables the filter, attaches the device, triggers its malicious effect,
and asserts the effect actually happened on the Windows client. Together with
test_matrix.py (same devices, filter ON -> blocked) this shows the filter is what
stops the attack, not some artifact of the simulation.

Skipped unless test/config.ini exists. These intentionally execute real payloads
(keystroke injection, storage read) on the client, so run only against a
disposable, isolated test VM.
Run: pytest test/test_attack_efficacy.py -v
"""

from __future__ import annotations

import time
import uuid

import pytest

from devices import DEVICES, VID

pytestmark = pytest.mark.efficacy


def _token() -> str:
    return uuid.uuid4().hex[:8]


def _wait(predicate, timeout: float = 20.0, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# Known limitation, but diagnosed rather than blanket-suppressed. Keystroke
# injection writes 8-byte boot-keyboard reports to the gadget's /dev/hidgN,
# which only works while the gadget's HID interrupt-IN endpoint is enabled. In
# this lab the endpoint is never enabled when the Windows client is the USB host
# (every write fails with ESHUTDOWN), even though the device reaches state
# 'configured'.
#
# Instead of decorating the whole test xfail -- which would also hide a broken
# node, a failed attach/enumeration, a storage regression, or a client that was
# actually fixed -- we run every precondition as a hard assertion, then probe the
# endpoint and xfail ONLY when the probe confirms the specific
# "endpoint_disabled" (ESHUTDOWN) condition. Any other probe result means the
# endpoint should work, so injection is then required to succeed (an XPASS if the
# client is fixed, a real failure otherwise).


def _require_injection_or_known_limitation(linux, win, token: str, hid_pid: str) -> None:
    assert _wait(lambda: win.keyboard_child_ready(VID, hid_pid), timeout=15.0), (
        "HID parent enumerated, but Windows never started the Keyboard child; "
        f"HID child status: {win.hid_child_status(VID, hid_pid)}")

    probe = linux.probe_hid_endpoint()
    classification = probe.get("classification")
    if classification == "endpoint_disabled":
        pytest.xfail(
            "confirmed client limitation: HID interrupt-IN endpoint never "
            f"enabled (probe={probe}); see VALIDATION_PLAN.md phase 2")

    # The endpoint is (or should be) usable; injection must therefore succeed.
    linux.fire_hid_marker(token)
    assert _wait(lambda: win.public_marker_present(token)), (
        f"HID endpoint probe classified as {classification!r} (probe={probe}) "
        f"but keystroke injection did not execute; HID child status: "
        f"{win.hid_child_status(VID, hid_pid)}")
    win.remove_public_marker(token)


def test_badusb_hid_keystrokes_execute(linux, win):
    """HID gadget injects keystrokes that run code (drops a marker file)."""
    dev = DEVICES["hid_keyboard"]
    token = _token()
    win.remove_public_marker(token)
    win.set_policy(disable=True)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
    assert win.attach(linux.busid), "device should attach with filter disabled"
    assert _wait(lambda: win.pnp_present(VID, dev.pid)), (
        f"device attached but Windows never enumerated VID_{VID}&PID_{dev.pid} -> "
        "attach only creates the USB/IP node; PnP enumeration + function-driver "
        "load happen asynchronously. If it never appears, check the class driver "
        "loaded for this device on the client.")

    time.sleep(3)  # let Windows finish loading the HID stack
    _require_injection_or_known_limitation(linux, win, token, dev.pid)


def test_mass_storage_payload_readable(linux, win):
    """Mass-storage gadget exposes a payload the client can read (exfil/drop)."""
    dev = DEVICES["mass_storage"]
    token = _token()
    win.set_policy(disable=True)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}",
                       extra_env={"PAYLOAD_TOKEN": token})
    assert win.attach(linux.busid), "device should attach with filter disabled"
    assert _wait(lambda: win.pnp_present(VID, dev.pid)), (
        f"device attached but Windows never enumerated VID_{VID}&PID_{dev.pid} -> "
        "attach only creates the USB/IP node; PnP enumeration + function-driver "
        "load happen asynchronously. If it never appears, check the class driver "
        "loaded for this device on the client.")

    fname = f"ub_{token}.txt"
    assert _wait(lambda: win.removable_marker(fname) is not None), (
        "mass-storage payload not readable on the client (no removable marker)")
    assert win.removable_marker(fname).strip() == token


def test_composite_both_channels_live(linux, win):
    """Composite gadget: the storage payload AND keystroke injection fire.

    The storage channel is asserted unconditionally (independent of the HID
    limitation), then the HID channel is subject to the same conditional
    diagnosis as test_badusb_hid_keystrokes_execute: it xfails only if the probe
    confirms the endpoint-disabled condition, and otherwise must succeed. This
    keeps storage coverage even when HID is a known xfail, and surfaces a real
    failure if storage regresses.
    """
    dev = DEVICES["composite_ms_hid"]
    token = _token()
    win.remove_public_marker(token)
    win.set_policy(disable=True)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}",
                       extra_env={"PAYLOAD_TOKEN": token})
    assert win.attach(linux.busid), "device should attach with filter disabled"
    assert _wait(lambda: win.pnp_present(VID, dev.pid)), (
        f"device attached but Windows never enumerated VID_{VID}&PID_{dev.pid} -> "
        "attach only creates the USB/IP node; PnP enumeration + function-driver "
        "load happen asynchronously. If it never appears, check the class driver "
        "loaded for this device on the client.")

    # Storage channel: independent hard assertion (no HID dependency).
    fname = f"ub_{token}.txt"
    assert _wait(lambda: win.removable_marker(fname) is not None), (
        "composite storage channel not live")

    time.sleep(3)  # let Windows finish loading the HID stack
    _require_injection_or_known_limitation(linux, win, token, dev.pid)


def test_rogue_nic_appears(linux, win):
    """Rogue USB NIC actually presents a VID/PID-matched network child."""
    dev = DEVICES["cdc_nic"]
    win.set_policy(disable=True)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
    assert win.attach(linux.busid), "device should attach with filter disabled"

    assert _wait(lambda: win.net_child_ready(VID, dev.pid)), (
        "no VID/PID-matched network adapter appeared -> rogue NIC simulation "
        f"not live; Net child status: {win.net_child_status(VID, dev.pid)}")
