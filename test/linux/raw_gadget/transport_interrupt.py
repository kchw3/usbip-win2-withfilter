#!/usr/bin/env python3
"""Transport-interruption profile.

Serve valid descriptors for local pre-export enumeration, then intentionally
terminate during a later configuration descriptor request. The harness uses this
to prove that a dropped or crashing USB/IP producer fails closed: attach must
fail and Windows must not expose a VID/PID node.
"""

from __future__ import annotations

import os

import usb_descriptors as d
from _raw_gadget import GET_DESCRIPTOR, ControlRequest
from _runner import run_profile

VID, PID = 0x16C0, 0x03F3
CONFIG_REQUESTS_BEFORE_DROP = int(os.environ.get("CONFIG_REQUESTS_BEFORE_DROP", "2"))
_config_requests = 0


def on_control(req: ControlRequest) -> bytes | None:
    global _config_requests

    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_DEVICE:
        return d.device_descriptor(vid=VID, pid=PID, b_device_class=0x00)
    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_CONFIG:
        _config_requests += 1
        if _config_requests > CONFIG_REQUESTS_BEFORE_DROP:
            raise RuntimeError("intentional transport interruption before config descriptor")
        return d.benign_mass_storage_config()
    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_STRING:
        return d.string_descriptor(req.descriptor_index)
    return None


if __name__ == "__main__":
    run_profile("transport_interrupt", on_control, vid=VID, pid=PID)
