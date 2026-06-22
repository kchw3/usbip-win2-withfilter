"""Minimal raw_gadget event-loop scaffold.

This wraps just enough of /dev/raw-gadget to: init+run a gadget on a UDC, receive
control events, and reply with EP0 data/stall. The descriptor bytes come from the
profile (toctou.py / malformed_descriptors.py).

IMPORTANT: the ioctl numbers and event struct layout below MUST be validated
against the running kernel's <uapi/linux/usb/raw_gadget.h>. They are kept in one
place here so a single edit fixes all profiles. See tools/usb/raw-gadget in the
kernel tree for a reference C implementation.
"""

from __future__ import annotations

import ctypes
import fcntl
import os
from dataclasses import dataclass
from typing import Callable

# --- TODO: validate against <uapi/linux/usb/raw_gadget.h> on the target kernel.
USB_RAW_IOCTL_INIT = 0  # _IOW('U', 0, struct usb_raw_init)
USB_RAW_IOCTL_RUN = 1   # _IO('U', 1)
USB_RAW_IOCTL_EVENT_FETCH = 2  # _IOR('U', 2, struct usb_raw_event)
USB_RAW_IOCTL_EP0_WRITE = 3    # _IOW('U', 3, struct usb_raw_ep_io)
USB_RAW_IOCTL_EP0_READ = 4     # _IOWR('U', 4, struct usb_raw_ep_io)
USB_RAW_IOCTL_EP0_STALL = 6    # _IO('U', 6)

USB_RAW_EVENT_CONNECT = 1
USB_RAW_EVENT_CONTROL = 2

# bmRequestType / bRequest of interest
GET_DESCRIPTOR = 0x06


@dataclass
class ControlRequest:
    bmRequestType: int
    bRequest: int
    wValue: int
    wIndex: int
    wLength: int

    @property
    def descriptor_type(self) -> int:
        return (self.wValue >> 8) & 0xFF

    @property
    def descriptor_index(self) -> int:
        return self.wValue & 0xFF


class RawGadget:
    """Open /dev/raw-gadget, bind to a UDC, dispatch control requests."""

    def __init__(self, driver: str = "dummy_udc.0", device: str = "dummy_udc",
                 speed: int = 2):
        self.driver = driver.encode()
        self.device = device.encode()
        self.speed = speed
        self.fd = os.open("/dev/raw-gadget", os.O_RDWR)

    def init(self) -> None:
        # TODO: pack struct usb_raw_init { __u8 driver_name[...]; __u8 device_name[...]; __u8 speed; }
        # and fcntl.ioctl(self.fd, USB_RAW_IOCTL_INIT, buf). Layout per kernel header.
        raise NotImplementedError("pack struct usb_raw_init per target kernel header")

    def run(self) -> None:
        fcntl.ioctl(self.fd, USB_RAW_IOCTL_RUN, 0)

    def fetch_control(self) -> ControlRequest | None:
        # TODO: fetch struct usb_raw_event; if type==CONTROL parse the 8-byte
        # usb_ctrlrequest from event.data. Return None for non-control events.
        raise NotImplementedError("fetch+parse struct usb_raw_event per kernel header")

    def ep0_write(self, data: bytes) -> None:
        # TODO: pack struct usb_raw_ep_io { __u16 ep; __u16 flags; __u32 length; __u8 data[]; }
        raise NotImplementedError("pack struct usb_raw_ep_io per kernel header")

    def ep0_stall(self) -> None:
        fcntl.ioctl(self.fd, USB_RAW_IOCTL_EP0_STALL, 0)

    def serve(self, on_control: Callable[[ControlRequest], bytes | None]) -> None:
        """Event loop. `on_control` returns reply bytes, or None to STALL."""
        self.init()
        self.run()
        while True:
            req = self.fetch_control()
            if req is None:
                continue
            reply = on_control(req)
            if reply is None:
                self.ep0_stall()
            else:
                # respect wLength
                self.ep0_write(reply[: req.wLength])
