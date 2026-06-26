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


def _wait(predicate, timeout: float = 20.0, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _set_policy(win, policy: str) -> None:
    if policy == "disabled":
        win.set_policy(disable=True)
    elif policy == "deny_all":
        win.set_policy(deny_all=True)
    else:
        win.set_policy(allow=list(POLICIES[policy]))


@pytest.mark.parametrize("policy,device_key", _CASES,
                         ids=[f"{p}-{d}" for p, d in _CASES])
def test_decision(linux, win, policy, device_key):
    dev = DEVICES[device_key]
    should_allow = expected_allow(policy, device_key)

    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
    _set_policy(win, policy)

    attached = win.attach(linux.busid)

    # Allow: a successful attach only creates the USB/IP node; Windows PnP
    # enumeration + function-driver load happen asynchronously after that, so
    # retry rather than racing the stack. Deny: the attach itself fails, so no
    # device node is ever created -- an immediate absence check is correct (and
    # the security-critical assertion: a denied device must never enumerate).
    if should_allow:
        present = _wait(lambda: win.pnp_present(VID, dev.pid))
    else:
        present = win.pnp_present(VID, dev.pid)

    assert attached is should_allow, (
        f"attach result mismatch: policy={policy} device={device_key} "
        f"expected_allow={should_allow} got_attached={attached}")

    # Security-critical: a denied device must never be enumerated by Windows.
    assert present is should_allow, (
        f"PnP presence mismatch: policy={policy} device={device_key} "
        f"expected_present={should_allow} got_present={present}")

    if not should_allow:
        assert win.rejection_logged(dev.pid), (
            f"no usbip2_ude rejection event mentioning PID {dev.pid} "
            f"for policy={policy} device={device_key}")
