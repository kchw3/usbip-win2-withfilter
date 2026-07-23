"""Opt-in Raw Gadget lab bring-up canaries.

These tests are the gate before unskipping Tier B robustness tests. They prove
the Raw Gadget stimulus path is live and that common infrastructure breakages go
red instead of becoming false security passes.
Run explicitly: pytest test/test_tierb_canaries.py --run-tierb-canaries -v
"""

from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.tierb_canary

VID = "16C0"
BENIGN_PID = "03F2"


def _wait(predicate, timeout: float = 20.0, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _served_config(transcript: list[dict]) -> bool:
    for rec in transcript:
        if rec.get("event") != "control":
            continue
        req = rec.get("request", {})
        resp = rec.get("response", {})
        if (req.get("bRequest") == 0x06 and req.get("descriptor_type") == 0x02
                and resp.get("action") == "write" and resp.get("transferred", 0) > 0):
            return True
    return False


def test_raw_udc_names_match_lab_kernel(linux):
    driver, device = linux._raw_udc_names()
    out = linux.run(
        "test -e /dev/raw-gadget && "
        f"test -d /sys/bus/platform/drivers/{driver} && "
        f"test -e /sys/bus/platform/devices/{device} && "
        f"test -e /sys/class/udc/{device} && echo RAW-UDC-OK",
        check=False)
    assert "RAW-UDC-OK" in out, (
        f"Raw Gadget UDC names not valid for this lab: "
        f"driver={driver!r} device={device!r}\n{out}")


def test_raw_gadget_dead_producer_goes_red(linux):
    with pytest.raises(RuntimeError, match="died before ready"):
        linux.start_raw_gadget(
            "canary_die_before_ready",
            expected_vid=VID,
            expected_pid=BENIGN_PID,
            timeout=5.0)


def test_raw_gadget_wrong_udc_names_go_red(linux):
    with pytest.raises(RuntimeError, match="raw_gadget producer error"):
        linux.start_raw_gadget(
            "benign_mass_storage",
            expected_vid=VID,
            expected_pid=BENIGN_PID,
            env={"UDC_DRIVER": "not_a_udc_driver", "UDC_DEVICE": "not_a_udc_device"},
            timeout=5.0)


def test_raw_gadget_suppressed_export_goes_red(linux):
    run = linux.start_raw_gadget(
        "benign_mass_storage",
        expected_vid=VID,
        expected_pid=BENIGN_PID,
        timeout=10.0,
        export=False)
    try:
        with pytest.raises(RuntimeError, match="exported device not visible"):
            linux.verify_raw_export_visible(VID, BENIGN_PID, timeout=3.0)
    finally:
        linux.stop_raw_gadget(run)


def test_raw_gadget_wrong_busid_goes_red(linux):
    run = linux.start_raw_gadget(
        "benign_mass_storage",
        expected_vid=VID,
        expected_pid=BENIGN_PID,
        timeout=15.0)
    try:
        with pytest.raises(RuntimeError, match="exported device not visible"):
            linux.verify_raw_export_visible(
                VID, BENIGN_PID, timeout=3.0, busid="999-999")
    finally:
        linux.stop_raw_gadget(run)


def test_raw_gadget_omitted_config_response_is_detected(linux):
    run = linux.start_raw_gadget(
        "benign_mass_storage",
        expected_vid=VID,
        expected_pid=BENIGN_PID,
        env={"OMIT_CONFIG": "1"},
        timeout=15.0,
        export=False)
    try:
        time.sleep(2)
        transcript = linux.read_raw_transcript(run)
        assert not _served_config(transcript), (
            "OMIT_CONFIG canary unexpectedly served a configuration descriptor")
    finally:
        linux.stop_raw_gadget(run)


def test_benign_raw_gadget_reaches_windows(linux, win):
    win.set_policy(disable=True)
    run = linux.start_raw_gadget(
        "benign_mass_storage",
        expected_vid=VID,
        expected_pid=BENIGN_PID,
        timeout=15.0)
    try:
        attach = win.attach_result(linux.busid)
        assert attach.ok, f"benign Raw Gadget canary did not attach: {attach}"
        assert _wait(lambda: win.pnp_exposure(VID, BENIGN_PID)), (
            f"benign Raw Gadget canary attached but Windows did not expose "
            f"VID_{VID}&PID_{BENIGN_PID}")
        transcript = linux.read_raw_transcript(run)
        assert _served_config(transcript), (
            "benign Raw Gadget canary attached without proving a configuration "
            "descriptor was served")
    finally:
        linux.stop_raw_gadget(run)
