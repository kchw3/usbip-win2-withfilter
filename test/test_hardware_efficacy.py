"""Opt-in physical USB hardware efficacy lane."""

from __future__ import annotations

import time
import uuid

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


def _wait_for_rejection(win, cursor, profile, busid):
    return _wait(
        lambda: win.rejection_event_after(cursor, profile.vid, profile.pid, busid),
        timeout=profile.deny_watch_seconds,
    )


def _absent_for(win, profile):
    deadline = time.time() + profile.deny_watch_seconds
    while time.time() < deadline:
        exposure = win.pnp_exposure(profile.vid, profile.pid)
        if exposure:
            return False
        time.sleep(0.5)
    return True


def _allow_oracle(win, profile):
    if profile.kind == "keyboard":
        return win.keyboard_child_ready(profile.vid, profile.pid)
    if profile.kind == "storage":
        # The dedicated storage-marker oracle is added with the programmable
        # efficacy profiles. Compatibility still requires a started device.
        return win.pnp_present(profile.vid, profile.pid)
    if profile.kind == "network":
        return win.net_child_ready(profile.vid, profile.pid)
    raise AssertionError(f"unsupported compatibility profile kind: {profile.kind}")


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


@pytest.mark.parametrize("kind", ("keyboard", "storage", "network"))
def test_physical_profile_deny_then_allow(kind, hardware_profiles, hardware_export, win):
    """Require correlated denial before proving the configured allow path."""
    profiles = [profile for profile in hardware_profiles.values() if profile.kind == kind]
    if not profiles:
        pytest.skip(f"no configured physical {kind} profile")

    for profile in profiles:
        export = hardware_export(profile.name)

        win.set_policy(deny_all=True)
        cursor = win.event_cursor()
        denied = win.attach_result(export.busid)
        assert _absent_for(win, profile), f"denied physical {profile.name} exposed a PnP node"
        rejection = _wait_for_rejection(win, cursor, profile, export.busid)
        assert rejection, (
            f"no fresh correlated rejection for {profile.name}; "
            f"attach={denied}; usbip={win.usbip_port_snapshot()}"
        )

        win.hardware_cleanup(profile.vid, profile.pid)
        win.set_policy(allow=profile.allow_categories)
        allowed = win.attach_result(export.busid)
        assert allowed.ok, f"allowed physical attach failed for {profile.name}: {allowed}"
        assert _wait(
            lambda: _allow_oracle(win, profile),
        ), f"allow oracle failed for physical {profile.name}"


def test_programmable_hid_marker_denied_then_allowed(
    hardware_profiles, hardware_export, linux, win,
):
    """A programmable HID effect must be impossible while its class is denied."""
    profiles = [
        profile for profile in hardware_profiles.values()
        if profile.kind in {"programmable_hid", "composite"}
        and "hid_marker" in profile.oracles
    ]
    if not profiles:
        pytest.skip("no configured programmable HID/composite marker profile")

    for profile in profiles:
        export = hardware_export(profile.name)
        run_id = uuid.uuid4().hex
        token = uuid.uuid4().hex
        win.remove_public_marker(token)
        linux.hardware_prepare(profile, run_id=run_id, token=token, busid=export.busid)
        try:
            win.set_policy(deny_all=True)
            cursor = win.event_cursor()
            denied = win.attach_result(export.busid)
            assert _absent_for(win, profile), (
                f"denied programmable profile {profile.name} exposed a PnP node"
            )
            assert _wait_for_rejection(win, cursor, profile, export.busid), (
                f"no fresh rejection for programmable profile {profile.name}; "
                f"attach={denied}"
            )
            linux.hardware_trigger(profile, run_id=run_id, token=token, busid=export.busid)
            assert not _wait(lambda: win.public_marker_present(token), timeout=3), (
                f"denied programmable profile {profile.name} produced marker {token}"
            )

            win.hardware_cleanup(profile.vid, profile.pid)
            win.set_policy(allow=profile.allow_categories)
            allowed = win.attach_result(export.busid)
            assert allowed.ok, f"allowed programmable attach failed: {allowed}"
            assert _wait(lambda: win.pnp_exposure(profile.vid, profile.pid)), (
                f"allowed programmable profile {profile.name} did not expose PnP"
            )
            linux.hardware_trigger(profile, run_id=run_id, token=token, busid=export.busid)
            assert _wait(lambda: win.public_marker_present(token)), (
                f"allowed programmable profile {profile.name} produced no marker {token}"
            )
        finally:
            if win.public_marker_present(token):
                win.remove_public_marker(token)
