from __future__ import annotations

import configparser

import pytest

from hardware import ACK_TEXT, HardwareConfigError, load_hardware_profiles


def _config(text: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser()
    cp.read_string(text)
    return cp


BASE = f"""
[hardware]
profiles = keyboard, storage, nic
artifact_dir = artifacts/hardware
capture_traffic = false
deny_watch_seconds = 15

[hardware:keyboard]
kind = keyboard
busid = 1-2
vid = 0x1234
pid = 0001
serial = LAB-KBD-01
allow_categories = hid
oracles = keyboard_ready
confirm_physical_unbind = {ACK_TEXT}

[hardware:storage]
kind = storage
busid = 1-3
vid = 1234
pid = 0002
serial = LAB-STORAGE-01
allow_categories = storage
oracles = storage_marker
confirm_physical_unbind = {ACK_TEXT}

[hardware:nic]
kind = network
busid = 1-4
vid = 1234
pid = 0003
serial = LAB-NIC-01
allow_categories = network
oracles = network_peer
windows_ipv4 = 192.0.2.10
prefix_length = 24
peer_ipv4 = 192.0.2.20
peer_tcp_port = 9000
confirm_physical_unbind = {ACK_TEXT}
"""


def test_loads_and_normalizes_profiles():
    profiles = load_hardware_profiles(_config(BASE))

    assert tuple(profiles) == ("keyboard", "storage", "nic")
    assert profiles["keyboard"].vid == "1234"
    assert profiles["keyboard"].pid == "0001"
    assert profiles["storage"].allow_categories == ("mass_storage",)
    assert profiles["storage"].oracles == ("storage_marker",)
    assert profiles["nic"].windows_ipv4 == "192.0.2.10"
    assert profiles["nic"].prefix_length == 24
    assert profiles["nic"].peer_tcp_port == 9000


def test_selection_and_artifact_override_are_run_scoped():
    profiles = load_hardware_profiles(
        _config(BASE),
        selected=("storage",),
        artifact_dir="/tmp/hw-artifacts",
        capture_traffic=True,
    )

    assert tuple(profiles) == ("storage",)
    assert profiles["storage"].artifact_dir.as_posix() == "/tmp/hw-artifacts"
    assert profiles["storage"].capture_traffic is True


def test_config_enabled_capture_cannot_be_weakened_by_cli_defaults():
    text = BASE.replace("capture_traffic = false", "capture_traffic = true")

    profiles = load_hardware_profiles(_config(text), capture_traffic=False)

    assert all(profile.capture_traffic for profile in profiles.values())


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        (f"confirm_physical_unbind = {ACK_TEXT}", "confirm_physical_unbind = no",
         "confirm_physical_unbind"),
        ("busid = 1-2", "busid = auto", "wildcards/auto"),
        ("busid = 1-2", "busid = 1-*", "wildcards/auto"),
        ("vid = 0x1234", "vid = xyz", "vid"),
        ("serial = LAB-KBD-01", "serial = *", "serial"),
        ("allow_categories = hid", "allow_categories =", "allow_categories"),
        ("oracles = keyboard_ready", "oracles = network_peer", "missing oracle-required"),
    ],
)
def test_rejects_unsafe_profile_fields(old: str, new: str, match: str):
    with pytest.raises(HardwareConfigError, match=match):
        load_hardware_profiles(_config(BASE.replace(old, new)), selected=("keyboard",))


def test_rejects_duplicate_physical_busids():
    text = BASE.replace("busid = 1-3", "busid = 1-2")

    with pytest.raises(HardwareConfigError, match="already used"):
        load_hardware_profiles(_config(text))


def test_unknown_profile_selection_is_explicit_error():
    with pytest.raises(HardwareConfigError, match="unknown --hardware-profile"):
        load_hardware_profiles(_config(BASE), selected=("missing",))


def test_network_peer_requires_bounded_peer_fields():
    text = BASE.replace("peer_tcp_port = 9000", "peer_tcp_port = 70000")

    with pytest.raises(HardwareConfigError, match="peer_tcp_port"):
        load_hardware_profiles(_config(text), selected=("nic",))


def test_programmable_hid_marker_requires_trigger_hook():
    text = f"""
[hardware]
profiles = programmable_hid

[hardware:programmable_hid]
kind = programmable_hid
busid = 2-1
vid = 1209
pid = 0001
allow_categories = hid
oracles = hid_marker
confirm_physical_unbind = {ACK_TEXT}
"""

    with pytest.raises(HardwareConfigError, match="trigger_hook"):
        load_hardware_profiles(_config(text))


def test_composite_profile_requires_explicit_independent_oracles():
    text = f"""
[hardware]
profiles = combo

[hardware:combo]
kind = composite
busid = 2-1
vid = 1209
pid = 0002
allow_categories = hid, storage
confirm_physical_unbind = {ACK_TEXT}
"""

    with pytest.raises(HardwareConfigError, match="composite profiles must list oracles"):
        load_hardware_profiles(_config(text))
