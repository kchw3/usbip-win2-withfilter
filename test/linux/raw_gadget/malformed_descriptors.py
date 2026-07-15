#!/usr/bin/env python3
"""Attack #9: malformed / inconsistent configuration descriptors.

Pick a variant via the VARIANT env var:

  zero_interface   - declares bNumInterfaces=1 but contains no interface
                     descriptors (probes the vacuous-pass risk).
  lying_count      - one real HID interface but bNumInterfaces=0.
  bad_total_length - wTotalLength shorter than the actual descriptor body.

For every variant the filter is expected to FAIL CLOSED (deny). Run on the
server, export the UDC, attach from Windows with deny-all (or any policy) and
assert the attach fails AND nothing enumerates.
"""

from __future__ import annotations

import os

import usb_descriptors as d
from _raw_gadget import GET_DESCRIPTOR, ControlRequest
from _runner import run_profile

VID, PID = 0x16C0, 0x03F1
VARIANT = os.environ.get("VARIANT", "zero_interface")


def _config_bytes() -> bytes:
    if VARIANT == "zero_interface":
        return d.zero_interface_config()
    if VARIANT == "lying_count":
        return d.lying_num_interfaces_config()
    if VARIANT == "bad_total_length":
        return d.config_descriptor(
            [d.interface_descriptor(number=0, b_interface_class=d.CLASS_HID)],
            total_length_override=9,  # claims only the header; body is longer
        )
    raise SystemExit(f"unknown VARIANT={VARIANT!r}")


def on_control(req: ControlRequest) -> bytes | None:
    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_DEVICE:
        return d.device_descriptor(vid=VID, pid=PID, b_device_class=0x00)
    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_CONFIG:
        return _config_bytes()
    return None


if __name__ == "__main__":
    run_profile(f"malformed:{VARIANT}", on_control, vid=VID, pid=PID)
