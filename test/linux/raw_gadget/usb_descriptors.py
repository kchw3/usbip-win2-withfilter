"""Exact USB descriptor builders shared by the raw_gadget test profiles.

These are plain `bytes` builders with no kernel dependency, so they can be unit
tested on any machine. The raw_gadget event loops import them to answer
GET_DESCRIPTOR requests with crafted (including malformed) bytes.
"""

from __future__ import annotations

import struct

# bDescriptorType values
DT_DEVICE = 0x01
DT_CONFIG = 0x02
DT_STRING = 0x03
DT_INTERFACE = 0x04
DT_ENDPOINT = 0x05

# Well-known class codes used by the filter test matrix.
CLASS_HID = 0x03
CLASS_MASS_STORAGE = 0x08
CLASS_CDC = 0x02
CLASS_VENDOR = 0xFF
CLASS_MISC = 0xEF  # composite "glue", skipped at device level by the filter


def device_descriptor(
    *,
    vid: int,
    pid: int,
    b_device_class: int = 0x00,
    b_device_subclass: int = 0x00,
    b_device_protocol: int = 0x00,
    num_configurations: int = 1,
) -> bytes:
    return struct.pack(
        "<BBHBBBBHHHBBBB",
        18,            # bLength
        DT_DEVICE,     # bDescriptorType
        0x0200,        # bcdUSB
        b_device_class,
        b_device_subclass,
        b_device_protocol,
        64,            # bMaxPacketSize0
        vid,
        pid,
        0x0100,        # bcdDevice
        1, 2, 3,       # iManufacturer, iProduct, iSerialNumber
        num_configurations,
    )


def string_descriptor(index: int) -> bytes:
    """Minimal string descriptor table for Raw Gadget canaries/profiles."""
    if index == 0:
        return b"\x04" + bytes([DT_STRING]) + b"\x09\x04"  # en-US
    values = {
        1: "usbip-test",
        2: "raw-gadget-test",
        3: "0001",
    }
    text = values.get(index)
    if text is None:
        return b""
    body = text.encode("utf-16le")
    return bytes([2 + len(body), DT_STRING]) + body


def interface_descriptor(
    *,
    number: int,
    alt: int = 0,
    num_endpoints: int = 0,
    b_interface_class: int,
    b_interface_subclass: int = 0,
    b_interface_protocol: int = 0,
) -> bytes:
    return struct.pack(
        "<BBBBBBBBB",
        9,             # bLength
        DT_INTERFACE,
        number,
        alt,
        num_endpoints,
        b_interface_class,
        b_interface_subclass,
        b_interface_protocol,
        0,             # iInterface
    )


def endpoint_descriptor(
    *,
    address: int,
    attributes: int = 0x02,  # bulk
    max_packet_size: int = 512,
    interval: int = 0,
) -> bytes:
    return struct.pack(
        "<BBBBHB",
        7,             # bLength
        DT_ENDPOINT,
        address,
        attributes,
        max_packet_size,
        interval,
    )


def config_descriptor(
    interfaces: list[bytes],
    *,
    num_interfaces: int | None = None,
    config_value: int = 1,
    total_length_override: int | None = None,
) -> bytes:
    """Build a CONFIGURATION descriptor followed by the given interface blobs.

    `num_interfaces` lets you LIE about bNumInterfaces (attack #9). If None it is
    set to the true count. `total_length_override` lets you truncate/inflate
    wTotalLength to probe the filter's bounds checks.
    """
    body = b"".join(interfaces)
    true_count = sum(1 for i in interfaces if len(i) >= 2 and i[1] == DT_INTERFACE)
    b_num_interfaces = true_count if num_interfaces is None else num_interfaces
    total = 9 + len(body) if total_length_override is None else total_length_override
    head = struct.pack(
        "<BBHBBBBB",
        9,             # bLength
        DT_CONFIG,
        total,         # wTotalLength
        b_num_interfaces,
        config_value,
        0,             # iConfiguration
        0x80,          # bmAttributes (bus powered)
        50,            # bMaxPower (100mA)
    )
    return head + body


# --- convenience presets -----------------------------------------------------

def benign_mass_storage_config() -> bytes:
    return config_descriptor([
        interface_descriptor(number=0, num_endpoints=2,
                             b_interface_class=CLASS_MASS_STORAGE,
                             b_interface_subclass=0x06, b_interface_protocol=0x50),
        endpoint_descriptor(address=0x81),
        endpoint_descriptor(address=0x02),
    ])


def malicious_ms_plus_hid_config() -> bytes:
    return config_descriptor([
        interface_descriptor(number=0, b_interface_class=CLASS_MASS_STORAGE,
                             b_interface_subclass=0x06, b_interface_protocol=0x50),
        interface_descriptor(number=1, b_interface_class=CLASS_HID,
                             b_interface_subclass=0x01, b_interface_protocol=0x01),
    ])


def zero_interface_config() -> bytes:
    """A configuration that declares one interface but contains none.

    Probes the vacuous-pass risk: the filter's interface loop has nothing to
    reject, so a naive implementation could ALLOW it. Desired result: deny."""
    return config_descriptor([], num_interfaces=1)


def lying_num_interfaces_config() -> bytes:
    """Real HID interface present but bNumInterfaces claims 0."""
    return config_descriptor([
        interface_descriptor(number=0, b_interface_class=CLASS_HID,
                             b_interface_subclass=0x01, b_interface_protocol=0x01),
    ], num_interfaces=0)
