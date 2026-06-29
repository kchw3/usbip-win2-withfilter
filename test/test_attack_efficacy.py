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


# Known limitation (see test/README.md "Known design limits"). Keystroke
# injection works by writing 8-byte boot-keyboard reports to the gadget's
# /dev/hidgN, which only succeeds while the gadget's HID interrupt-IN endpoint
# is enabled. When the Windows usbip2_ude client is the USB host -- over EITHER
# usbip-vudc OR dummy_hcd + usbip-host -- that endpoint never becomes writable:
# every write fails with ESHUTDOWN, even though the device reaches state
# 'configured'. The identical gadget works when a native Linux host drives it,
# so this is a property of how the client handles the HID interrupt-IN endpoint,
# not of the gadget or this harness. The HID *enumeration* (allow/deny) behaviour
# is still fully covered by test_matrix.py; only the live *injection* channel is
# affected. Marked xfail (non-strict) so the suite stays green and flips to
# XPASS if/when the client enables the endpoint.
_HID_INJECTION_XFAIL = pytest.mark.xfail(
    reason="usbip2_ude client does not enable the gadget HID interrupt-IN "
           "endpoint; /dev/hidgN writes fail with ESHUTDOWN (see test/README.md)",
    strict=False)


@_HID_INJECTION_XFAIL
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
    linux.fire_hid_marker(token)

    assert _wait(lambda: win.public_marker_present(token)), (
        "BadUSB keystrokes did not execute (marker file never appeared) -> "
        "the HID simulation may not be wired up; check /dev/hidg0 and layout")
    win.remove_public_marker(token)


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


@_HID_INJECTION_XFAIL  # the HID keystroke channel can't fire through this client
def test_composite_both_channels_live(linux, win):
    """Composite gadget: BOTH the storage payload AND keystroke injection fire.

    NOTE: xfail'd for the same reason as test_badusb_hid_keystrokes_execute --
    the HID injection channel cannot fire through the usbip2_ude client. The
    storage channel is independently covered by test_mass_storage_payload_readable,
    so xfail'ing this whole test does not lose storage coverage.
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

    fname = f"ub_{token}.txt"
    assert _wait(lambda: win.removable_marker(fname) is not None), (
        "composite storage channel not live")

    time.sleep(3)
    linux.fire_hid_marker(token)
    assert _wait(lambda: win.public_marker_present(token)), (
        "composite HID channel not live (keystrokes did not execute)")
    win.remove_public_marker(token)


def test_rogue_nic_appears(linux, win):
    """Rogue USB NIC actually presents a new network adapter on the client."""
    dev = DEVICES["cdc_nic"]
    win.set_policy(disable=True)
    baseline = win.net_adapter_names()

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
    assert win.attach(linux.busid), "device should attach with filter disabled"

    assert _wait(lambda: bool(win.net_adapter_names() - baseline)), (
        "no new network adapter appeared -> rogue NIC simulation not live")
