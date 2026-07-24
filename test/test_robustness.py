"""Integration: Tier B robustness cases (attacks #9 and #10) via raw_gadget.

These probe the parts of the filter most likely to be weak:
  - malformed / inconsistent descriptors must fail closed (deny),
  - descriptor TOCTOU must not let Windows enumerate an interface the filter
    never evaluated.

Requires test/config.ini and a server with raw_gadget set up.
Run: pytest test/test_robustness.py -v
"""

from __future__ import annotations

import queue
import threading
import time

import pytest

from conftest import WindowsClient
from devices import DEVICES

MALFORMED_PID = "03F1"
TOCTOU_PID = "03F0"
TRANSPORT_INTERRUPT_PID = "03F3"
VID = "16C0"
TOCTOU_BENIGN_CONFIG_RESPONSES = 4

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


def _handler_error_on_config(transcript: list[dict]) -> bool:
    for rec in transcript:
        if rec.get("event") != "control":
            continue
        req = rec.get("request", {})
        resp = rec.get("response", {})
        if (req.get("bRequest") == 0x06 and req.get("descriptor_type") == 0x02
                and resp.get("action") == "handler_error"):
            return True
    return False


def test_policy_update_reconnect_after_denied_attach(linux, win):
    """A denied attach must not poison a later attach after policy update.

    This is a deterministic lifetime/reconnect regression check around
    load/store + attach: first prove the exported HID is rejected under
    deny-all with no PnP exposure, then update policy to allow HID and require a
    fresh attach to succeed against the same exported device.
    """
    dev = DEVICES["hid_keyboard"]
    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")

    win.set_policy(deny_all=True)
    denied = win.attach_result(linux.busid)
    assert not denied.ok, f"deny-all unexpectedly attached HID: {denied}"
    assert not win.pnp_exposure(VID, dev.pid), (
        "deny-all rejected attach but still exposed a VID/PID PnP node")

    win.set_policy(allow=["hid"])
    allowed = win.attach_result(linux.busid)
    assert allowed.ok, (
        "HID attach did not recover after denied attach and policy update: "
        f"denied={denied}; allowed={allowed}")
    deadline = time.time() + 15.0
    while time.time() < deadline and not win.pnp_present(VID, dev.pid):
        time.sleep(1.0)
    assert win.pnp_present(VID, dev.pid), (
        "HID attach succeeded after policy update but did not enumerate")


def test_concurrent_policy_update_attach_stress(config, linux, win):
    """Policy load/store must tolerate attach attempts racing policy updates.

    This is intentionally a stress/lifetime oracle rather than a row-by-row
    allow/deny oracle: when attach and policy mutation overlap, either attach
    result can be legitimate depending on which policy snapshot the driver
    loaded. The deterministic assertions are that all operations stay bounded,
    policy readbacks remain coherent, both policy modes are exercised, and the
    attach path returns structured results instead of hanging or crashing.
    """
    dev = DEVICES["hid_keyboard"]
    linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
    win.set_policy(deny_all=True)

    errors: "queue.Queue[str]" = queue.Queue()
    stop = threading.Event()
    policy_states = []
    attach_results = []

    def policy_worker() -> None:
        client = WindowsClient(config)
        try:
            for i in range(10):
                if i % 2:
                    policy_states.append(client.set_policy(allow=["hid"]))
                else:
                    policy_states.append(client.set_policy(deny_all=True))
                time.sleep(0.2)
        except BaseException as exc:  # noqa: BLE001 - report thread failures
            errors.put(f"policy worker failed: {type(exc).__name__}: {exc}")
        finally:
            stop.set()

    def attach_worker() -> None:
        client = WindowsClient(config)
        deadline = time.time() + 20.0
        try:
            while not stop.is_set() and time.time() < deadline:
                attach_results.append(client.attach_result(linux.busid))
                time.sleep(0.25)
        except BaseException as exc:  # noqa: BLE001
            errors.put(f"attach worker failed: {type(exc).__name__}: {exc}")
            stop.set()

    threads = [
        threading.Thread(target=policy_worker, name="policy-update-stress"),
        threading.Thread(target=attach_worker, name="attach-stress"),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30.0)

    stop.set()
    stuck = [thread.name for thread in threads if thread.is_alive()]
    assert not stuck, f"concurrent policy/attach worker(s) hung: {stuck}"
    assert errors.empty(), "\n".join(list(errors.queue))
    assert len(policy_states) == 10, f"policy worker did not complete: {policy_states}"
    assert {state.mode for state in policy_states} == {"whitelist"}, policy_states
    assert any(not state.categories for state in policy_states), policy_states
    assert any(state.categories == ("hid",) for state in policy_states), policy_states
    assert attach_results, "attach worker never executed an attach attempt"
    assert all(isinstance(result.exit_code, int) for result in attach_results), (
        f"attach worker returned malformed result(s): {attach_results}")

    win.set_policy(deny_all=True)


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

    run = linux.start_raw_gadget(
        "toctou",
        expected_vid=VID,
        expected_pid=TOCTOU_PID,
        env={"BENIGN_CONFIG_RESPONSES": str(TOCTOU_BENIGN_CONFIG_RESPONSES)},
    )
    try:
        attach = win.attach_result(linux.busid)
        assert attach.ok, (
            "TOCTOU stimulus never crossed the filter-to-Windows boundary: the "
            f"benign snapshot should be allowed, but attach failed: {attach}")
        new_hid = _watch_for_new_hid(win, baseline)

        # Primary oracle: prove dummy_hcd's local pre-export enumeration and the
        # filter's two-request snapshot both consumed the same benign descriptor,
        # then require that no later changed descriptor was delivered to Windows.
        # UdeCx should serve the immutable registered snapshot internally, so no
        # later remote config request is expected at all.
        transcript = linux.read_raw_transcript(run)
        configs = _configuration_responses(transcript)
        benign = configs[:TOCTOU_BENIGN_CONFIG_RESPONSES]
        assert (len(benign) == TOCTOU_BENIGN_CONFIG_RESPONSES and
                len(set(benign)) == 1), (
            "TOCTOU infrastructure failure: expected local pre-export "
            "enumeration and filter snapshot fetches to receive identical "
            f"benign configuration responses, got {configs}")
        assert not _served_malicious_after_snapshot(transcript), (
            "TOCTOU BYPASS: a changed (malicious) configuration descriptor was "
            "delivered to the client after the filter's benign snapshot")
        assert not new_hid, (
            "TOCTOU BYPASS: Windows enumerated HID interface(s) the filter never "
            f"evaluated: {sorted(new_hid)}")
    finally:
        log = linux.stop_raw_gadget(run)
        print(f"[server log:toctou]\n{log}")


def test_transport_interruption_fails_closed(linux, win):
    """A producer drop during descriptor fetch must fail closed.

    The profile serves the device descriptor and then crashes on the first
    configuration descriptor request. That models a USB/IP transport/server
    interruption after import identity is visible but before the filter has a
    complete configuration snapshot.
    """
    win.set_policy(allow=["hid", "mass_storage", "network", "vendor"])
    run = linux.start_raw_gadget(
        "transport_interrupt",
        expected_vid=VID,
        expected_pid=TRANSPORT_INTERRUPT_PID,
        env={"CONFIG_REQUESTS_BEFORE_DROP": "2"},
    )
    try:
        attach = win.attach_result(linux.busid)
        assert not attach.ok, (
            "transport interruption unexpectedly attached; filter must fail "
            f"closed before PnP exposure: {attach}")
        assert not win.pnp_exposure(VID, TRANSPORT_INTERRUPT_PID), (
            "transport interruption exposed a VID/PID PnP node")

        transcript = linux.read_raw_transcript(run)
        assert _handler_error_on_config(transcript), (
            "transport interruption stimulus did not reach the configuration "
            f"descriptor request; transcript={transcript}")
    finally:
        log = linux.stop_raw_gadget(run)
        print(f"[server log:transport_interrupt]\n{log}")


def _configuration_responses(transcript: list[dict]) -> list[str]:
    responses = []
    for rec in transcript:
        if rec.get("event") != "control":
            continue
        req = rec.get("request", {})
        resp = rec.get("response", {})
        if (req.get("bRequest") == 0x06 and req.get("descriptor_type") == 0x02
                and resp.get("action") == "write" and resp.get("planned_hex")):
            responses.append(resp["planned_hex"])
    return responses


def _served_malicious_after_snapshot(transcript: list[dict]) -> bool:
    """True if a CONFIGURATION descriptor differing from the filter's first
    snapshot was later transferred to the client (the TOCTOU condition itself).
    """
    responses = _configuration_responses(transcript)
    if len(responses) <= TOCTOU_BENIGN_CONFIG_RESPONSES:
        return False
    benign = responses[0]
    return any(
        response != benign
        for response in responses[TOCTOU_BENIGN_CONFIG_RESPONSES:]
    )
