#!/usr/bin/env python3
"""Benign Raw Gadget canary: mass-storage-class descriptor path.

This profile is intentionally EP0-only. It proves that the Raw Gadget producer,
UDC binding, USB/IP export, Windows attach, and VID/PID PnP exposure path is
alive before Tier B adversarial profiles are trusted as security gates.

Set OMIT_CONFIG=1 to intentionally stall configuration-descriptor requests; the
canary suite uses that as a false-green guard for transcript oracles.
"""

from __future__ import annotations

import os

import usb_descriptors as d
from _raw_gadget import GET_DESCRIPTOR, ControlRequest
from _runner import run_profile

VID, PID = 0x16C0, 0x03F2


def on_control(req: ControlRequest) -> bytes | None:
    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_DEVICE:
        return d.device_descriptor(vid=VID, pid=PID, b_device_class=0x00)
    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_CONFIG:
        if os.environ.get("OMIT_CONFIG") == "1":
            return None
        return d.benign_mass_storage_config()
    if req.bRequest == GET_DESCRIPTOR and req.descriptor_type == d.DT_STRING:
        return d.string_descriptor(req.descriptor_index)
    return None


if __name__ == "__main__":
    run_profile("benign_mass_storage", on_control, vid=VID, pid=PID)
