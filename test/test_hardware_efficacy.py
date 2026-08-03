"""Opt-in physical USB hardware efficacy lane."""

from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.hardware


def test_hardware_profiles_are_explicitly_configured(hardware_profiles):
    assert hardware_profiles, "--run-hardware requires at least one safe profile"


def _wait(predicate, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.5)
    return False


def test_hardware_benign_attach_restore_canary(hardware_profiles, hardware_export, win):
    """Exercise one configured physical device through export and Windows attach."""
    name, profile = next(iter(hardware_profiles.items()))
    export = hardware_export(name)
    win.set_policy(allow=profile.allow_categories)
    result = win.attach_result(export.busid)

    assert result.ok, f"hardware attach failed: {result}"
    assert _wait(lambda: win.pnp_exposure(profile.vid, profile.pid)), (
        f"hardware attach produced no matching PnP node; usbip={win.usbip_port_snapshot()}"
    )
