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


def test_badusb_hid_keystrokes_execute(linux, win):
    """HID gadget injects keystrokes that run code (drops a marker file)."""
    dev = DEVICES["hid_keyboard"]
    token = _token()
    win.remove_public_marker(token)
    win.set_policy(disable=True)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
    assert win.attach(linux.busid), "device should attach with filter disabled"
    assert win.pnp_present(VID, dev.pid)

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
    assert win.pnp_present(VID, dev.pid)

    fname = f"ub_{token}.txt"
    assert _wait(lambda: win.removable_marker(fname) is not None), (
        "mass-storage payload not readable on the client (no removable marker)")
    assert win.removable_marker(fname).strip() == token


def test_composite_both_channels_live(linux, win):
    """Composite gadget: BOTH the storage payload AND keystroke injection fire."""
    dev = DEVICES["composite_ms_hid"]
    token = _token()
    win.remove_public_marker(token)
    win.set_policy(disable=True)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}",
                       extra_env={"PAYLOAD_TOKEN": token})
    assert win.attach(linux.busid), "device should attach with filter disabled"
    assert win.pnp_present(VID, dev.pid)

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
