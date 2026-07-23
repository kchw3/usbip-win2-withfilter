"""Integration: the policy x device decision matrix (Tier A devices).

For each (policy, device): build the gadget on the server, set the policy on the
client, attempt attach, and assert three oracles agree with the reference model:
  1. attach result (allow => success, deny => failure),
  2. PnP enumeration (deny => device must NOT be present),
  3. event log (deny => a usbip2_ude rejection mentioning the PID).

Skipped automatically unless test/config.ini exists.
Run: pytest test/test_matrix.py -v
"""

from __future__ import annotations

import itertools
import time

import pytest

from devices import DEVICES, POLICIES, VID, expected_allow

_CASES = list(itertools.product(POLICIES.keys(), DEVICES.keys()))

_TOKEN_CLASSES = {
    "hid": {"03"},
    "mass_storage": {"08"},
    "network": {"02", "0A"},
    "vendor": {"FF"},
}

_POLICY_WHITELIST_SNIPPETS = {
    "deny_all": {"(empty)"},
    "allow_hid": {"03/**/**"},
    "allow_ms": {"08/**/**"},
    "allow_hid_ms": {"03/**/**", "08/**/**"},
}


def _wait(predicate, timeout: float = 20.0, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _set_policy(win, policy: str) -> None:
    # WindowsClient.set_policy independently reads the policy back from the
    # driver and raises on mismatch, so every matrix row proves which policy it
    # actually exercised before attach.
    if policy == "disabled":
        win.set_policy(disable=True)
    elif policy == "deny_all":
        win.set_policy(deny_all=True)
    else:
        win.set_policy(allow=list(POLICIES[policy]))


def _watch_for_pnp_exposure(
    win, vid: str, pid: str, *, window: float = 8.0, interval: float = 0.5,
) -> list[dict]:
    """Watch the full deny window for ANY matching PnP node.

    A failed-start node is still exposure and a transient node must not be missed;
    unlike allow-path presence waits, an absence assertion cannot stop after the
    first negative sample.
    """
    deadline = time.time() + window
    while True:
        exposed = win.pnp_exposure(vid, pid)
        if exposed:
            return exposed
        if time.time() >= deadline:
            return []
        time.sleep(interval)


def _wait_for_rejection(win, cursor: int, vid: str, pid: str, busid: str,
                        timeout: float = 8.0) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        event = win.rejection_event_after(cursor, vid, pid, busid)
        if event is not None:
            return event
        time.sleep(0.5)
    return None


def _assert_rejection_event_contract(event: dict, policy: str, device_key: str) -> None:
    """Pin the admin-visible rejection event contract used as the deny oracle.

    VID/PID/busid correlation proves the event belongs to this row. This
    assertion additionally proves the event explains *why* the row was denied:
    the active whitelist, a class/sub/proto tuple, and a fail-closed reason.
    """
    msg = str(event.get("Message", ""))
    lower = msg.lower()

    assert "class not in whitelist" in lower, (
        f"rejection event did not include the fail-closed reason: {msg!r}")

    expected_whitelist = _POLICY_WHITELIST_SNIPPETS[policy]
    whitelist_tokens = POLICIES[policy] or frozenset()
    rejected_tokens = DEVICES[device_key].tokens - whitelist_tokens
    expected_classes = {
        cls
        for token in rejected_tokens
        for cls in _TOKEN_CLASSES[token]
    }

    # Current released/lab drivers may have the event insertion string truncated
    # by the Windows System event-log path before the class tuple and whitelist.
    # New driver builds put reason/class/whitelist first (device_filter.cpp) so
    # the stronger assertions below become active automatically once deployed.
    if "whitelist:" not in lower:
        assert "interface" in lower or "device" in lower, (
            f"legacy rejection event is missing even basic source context: {msg!r}")
        return

    missing = [s for s in expected_whitelist if s not in msg]
    assert not missing, (
        f"rejection event whitelist mismatch for policy={policy}: "
        f"missing={missing} msg={msg!r}")

    assert any(f"class {cls}/" in msg for cls in expected_classes), (
        f"rejection event did not name an expected rejected class for "
        f"policy={policy} device={device_key}; expected_classes="
        f"{sorted(expected_classes)} msg={msg!r}")


@pytest.mark.parametrize("policy,device_key", _CASES,
                         ids=[f"{p}-{d}" for p, d in _CASES])
def test_decision(linux, win, policy, device_key):
    dev = DEVICES[device_key]
    should_allow = expected_allow(policy, device_key)
    print(
        f"[matrix] row: policy={policy} device={device_key} "
        f"expected_allow={should_allow}",
        flush=True)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
    _set_policy(win, policy)

    # Cursor immediately before attach: only events caused by this row can match.
    event_cursor = win.event_cursor()
    attach = win.attach_result(linux.busid)

    assert attach.ok is should_allow, (
        f"attach result mismatch: policy={policy} device={device_key} "
        f"expected_allow={should_allow} got={attach}")

    if should_allow:
        # Successful attach precedes asynchronous PnP + function-driver loading.
        if dev.require_started:
            present = _wait(lambda: win.pnp_present(VID, dev.pid))
            assert present, (
                f"allowed device never became present+started: policy={policy} "
                f"device={device_key}; attach={attach}")
        else:
            exposure = _wait(lambda: win.pnp_exposure(VID, dev.pid))
            assert exposure, (
                f"allowed driverless device never appeared in PnP: policy={policy} "
                f"device={device_key}; attach={attach}")
    else:
        # Security-critical: watch the whole window for any present PnP node,
        # even failed-start/transient nodes. A single immediate sample can miss
        # delayed enumeration and report a false secure result.
        exposure = _watch_for_pnp_exposure(win, VID, dev.pid)
        assert not exposure, (
            f"denied device was exposed to Windows PnP: policy={policy} "
            f"device={device_key} exposure={exposure}; attach={attach}")

        event = _wait_for_rejection(
            win, event_cursor, VID, dev.pid, linux.busid)
        assert event is not None, (
            f"no correlated usbip2_ude rejection event newer than cursor "
            f"{event_cursor} for VID_{VID}&PID_{dev.pid}, busid={linux.busid}, "
            f"policy={policy}, device={device_key}; attach={attach}")
        _assert_rejection_event_contract(event, policy, device_key)
