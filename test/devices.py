"""Shared description of the Tier A test devices and the expected-decision model.

Keep VID/PID in sync with linux/gadgets/*.sh so the Windows PnP oracle can match.
"""

from __future__ import annotations

from dataclasses import dataclass

VID = "16C0"


@dataclass(frozen=True)
class Device:
    gadget: str           # gadgets/<gadget>.sh
    pid: str              # hex, uppercase, no 0x
    tokens: frozenset[str]  # category tokens this device exposes


# Category tokens match the userspace category ids in libusbip/src/vhci.cpp.
DEVICES = {
    "hid_keyboard":        Device("hid_keyboard",        "03E8", frozenset({"hid"})),
    "mass_storage":        Device("mass_storage",        "03E9", frozenset({"mass_storage"})),
    "composite_ms_hid":    Device("composite_ms_hid",    "03EA", frozenset({"hid", "mass_storage"})),
    "cdc_nic":             Device("cdc_nic",             "03EB", frozenset({"network"})),
    "rndis_nic":           Device("rndis_nic",           "03EC", frozenset({"network", "vendor"})),
    "vendor_ff":           Device("vendor_ff",           "03ED", frozenset({"vendor"})),
    "multicfg_hidden_hid": Device("multicfg_hidden_hid", "03EE", frozenset({"hid", "mass_storage"})),
}


# Policies expressed as (kind, whitelist-set). "disabled" allows everything.
POLICIES = {
    "deny_all":     frozenset(),
    "allow_hid":    frozenset({"hid"}),
    "allow_ms":     frozenset({"mass_storage"}),
    "allow_hid_ms": frozenset({"hid", "mass_storage"}),
    "disabled":     None,  # sentinel: filtering off
}


def expected_allow(policy: str, device_key: str) -> bool:
    """Reference decision = the model the filter is supposed to implement."""
    whitelist = POLICIES[policy]
    if whitelist is None:
        return True  # disabled
    dev = DEVICES[device_key]
    return dev.tokens.issubset(whitelist)
