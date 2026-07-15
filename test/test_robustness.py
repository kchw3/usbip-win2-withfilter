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

# The Raw Gadget transport, readiness protocol, and transcript oracles are now
# implemented (linux/raw_gadget/_raw_gadget.py, _runner.py; conftest
# start_raw_gadget). They still require one-time lab bring-up and validation on a
# real kernel + Windows client -- in particular confirming the raw_gadget UDC
# names for the server's kernel and that the fault-injection canaries go red --
# before they can be trusted as security gates. Keep them skipped until that
# bring-up is signed off (VALIDATION_PLAN.md phase 1). Enabling them prematurely
# risks interpreting infra failures as security passes.
pytestmark = pytest.mark.skip(
    reason="Tier B pending lab bring-up/validation on real kernel + client; "
           "see VALIDATION_PLAN.md phase 1",
)

MALFORMED_PID = "03F1"
TOCTOU_PID = "03F0"
VID = "16C0"

MALFORMED_VARIANTS = ["zero_interface", "lying_count", "bad_total_length"]

# How long to watch for a (wrongly) enumerated HID interface after attach, and
# how often to sample. This guards an *absence* assertion, so unlike the
# allow-path waits elsewhere it must not stop at the first negative sample: a
# TOCTOU bypass may enumerate an HID interface only briefly before the device
# tears it down, so we keep sampling for the whole window and fail closed on the
# first sighting.
_TOCTOU_WATCH_SECS = 8.0
_TOCTOU_SAMPLE_SECS = 0.5


def _watch_for_new_hid(win, baseline: set[str],
                       window: float = _TOCTOU_WATCH_SECS,
                       interval: float = _TOCTOU_SAMPLE_SECS) -> set[str]:
    """Poll for the FIRST appearance of any HID device not in ``baseline``.

    Returns the new HID instance ids the moment one is observed, or an empty set
    if none appear within ``window``. A single check after a fixed sleep can
    miss a HID interface that enumerates only transiently during a TOCTOU
    bypass; polling and returning on first sighting catches that race.
    """
    deadline = time.time() + window
    while True:
        new_hid = win.hid_instance_ids() - baseline
        if new_hid:
            return new_hid
        if time.time() >= deadline:
            return set()
        time.sleep(interval)


def _served_config(transcript: list[dict]) -> bool:
    """True if the producer actually transferred a CONFIGURATION descriptor.

    Guards against a false-green pass: a deny is only meaningful if the malformed
    descriptor really reached the filter.
    """
    for rec in transcript:
        if rec.get("event") != "control":
            continue
        req = rec.get("request", {})
        resp = rec.get("response", {})
        if (req.get("bRequest") == 0x06 and req.get("descriptor_type") == 0x02
                and resp.get("action") == "write" and resp.get("transferred", 0) > 0):
            return True
    return False


@pytest.mark.parametrize("variant", MALFORMED_VARIANTS)
def test_malformed_descriptors_fail_closed(linux, win, variant):
    """Every malformed variant must be denied and never enumerated.

    start_raw_gadget proves the producer is live and exported before we attach,
    so a deny cannot be an artifact of a producer that never ran.
    """
    win.set_policy(deny_all=False, allow=["mass_storage", "hid"])  # generous policy
    run = linux.start_raw_gadget(
        "malformed_descriptors", expected_vid=VID, expected_pid=MALFORMED_PID,
        env={"VARIANT": variant})
    try:
        attached = win.attach(linux.busid)
        present = win.pnp_present(VID, MALFORMED_PID)
        assert not attached, f"variant={variant} unexpectedly attached"
        assert not present, f"variant={variant} unexpectedly enumerated"

        transcript = linux.read_raw_transcript(run)
        assert _served_config(transcript), (
            f"variant={variant}: producer never served a config descriptor, so a "
            "deny does not prove fail-closed behaviour (infra failure)")
    finally:
        log = linux.stop_raw_gadget(run)
        print(f"[server log:{variant}]\n{log}")


def test_descriptor_toctou_no_bypass(linux, win):
    """Server lies: benign config to the filter's fetch, malicious to Windows.

    Policy allows ONLY mass_storage. The desired secure outcome is that no HID
    interface that the filter never saw ends up enumerated by Windows. We baseline
    the present HID devices, attach, then watch for any NEW HID device.

    We poll for the whole watch window and fail on the first new HID device seen,
    rather than checking once after a fixed sleep: a bypass may enumerate the HID
    interface only briefly before the device tears it down, and a single late
    check could miss that transient appearance (a false pass on a security check).
    """
    win.set_policy(allow=["mass_storage"])
    baseline = win.hid_instance_ids()

    run = linux.start_raw_gadget("toctou", expected_vid=VID, expected_pid=TOCTOU_PID)
    try:
        win.attach(linux.busid)
        new_hid = _watch_for_new_hid(win, baseline)

        # Primary oracle: the transcript must show the filter's two benign
        # fetches, and any later malicious descriptor delivery is itself a
        # bypass -- we do not depend solely on HID interface enumeration, which
        # this EP0-only producer cannot fully drive.
        transcript = linux.read_raw_transcript(run)
        assert not _served_malicious_after_snapshot(transcript), (
            "TOCTOU BYPASS: a changed (malicious) configuration descriptor was "
            "delivered to the client after the filter's benign snapshot")
        assert not new_hid, (
            "TOCTOU BYPASS: Windows enumerated HID interface(s) the filter never "
            f"evaluated: {sorted(new_hid)}")
    finally:
        log = linux.stop_raw_gadget(run)
        print(f"[server log:toctou]\n{log}")


def _served_malicious_after_snapshot(transcript: list[dict]) -> bool:
    """True if a CONFIGURATION descriptor differing from the filter's first
    snapshot was later transferred to the client (the TOCTOU condition itself).
    """
    snapshot: str | None = None
    for rec in transcript:
        if rec.get("event") != "control":
            continue
        req = rec.get("request", {})
        resp = rec.get("response", {})
        if not (req.get("bRequest") == 0x06 and req.get("descriptor_type") == 0x02):
            continue
        served = resp.get("planned_hex")
        if resp.get("action") != "write" or not served:
            continue
        if snapshot is None:
            snapshot = served
        elif served != snapshot:
            return True
    return False
