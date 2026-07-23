"""Minimal, validated raw_gadget event loop for the Tier B filter tests.

This wraps just enough of ``/dev/raw-gadget`` to init+run a gadget on a UDC,
answer EP0 control requests with profile-supplied bytes, drive the gadget into
the configured state, and record a machine-readable transcript of every control
request/response so the harness can *prove* the crafted exchange actually
reached the client instead of inferring it from an attach failure.

Design notes
------------
* The ioctl numbers are computed at runtime from the kernel ``_IOC`` encoding
  and the exact struct sizes in ``<uapi/linux/usb/raw_gadget.h>`` rather than
  being hardcoded, so a header/ABI mismatch surfaces as a clear error instead of
  silent corruption.
* The module is import-safe: nothing touches ``/dev/raw-gadget`` until
  :meth:`RawGadget.open` is called, so the pure encoding/packing/dispatch logic
  is unit-testable on any machine (see ``test_raw_gadget.py``).
* This responder handles EP0 (control) only. That is sufficient to drive
  enumeration and the descriptor fetches the filter and Windows perform. Live
  data-endpoint traffic (e.g. HID reports) is out of scope here; the Tier A
  configfs gadgets and the hardware-backed lane cover that.

References: Documentation/usb/raw-gadget.rst and tools/usb/raw-gadget in the
kernel tree; https://github.com/xairy/raw-gadget.
"""

from __future__ import annotations

import fcntl
import json
import os
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass

# --- kernel _IOC encoding (asm-generic; x86_64 / arm64) ----------------------
_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _ioc(direction: int, type_: int, nr: int, size: int) -> int:
    return (
        (direction << _IOC_DIRSHIFT)
        | (type_ << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


_UDC_NAME_LENGTH_MAX = 128

# struct usb_raw_init { u8 driver_name[128]; u8 device_name[128]; u8 speed; }
_INIT_SIZE = _UDC_NAME_LENGTH_MAX * 2 + 1
# struct usb_raw_event { u32 type; u32 length; u8 data[]; }
_EVENT_HEADER_SIZE = 8
# struct usb_raw_ep_io { u16 ep; u16 flags; u32 length; u8 data[]; }
_EP_IO_HEADER_SIZE = 8

_U = ord("U")

USB_RAW_IOCTL_INIT = _ioc(_IOC_WRITE, _U, 0, _INIT_SIZE)
USB_RAW_IOCTL_RUN = _ioc(_IOC_NONE, _U, 1, 0)
USB_RAW_IOCTL_EVENT_FETCH = _ioc(_IOC_READ, _U, 2, _EVENT_HEADER_SIZE)
USB_RAW_IOCTL_EP0_WRITE = _ioc(_IOC_WRITE, _U, 3, _EP_IO_HEADER_SIZE)
USB_RAW_IOCTL_EP0_READ = _ioc(_IOC_READ | _IOC_WRITE, _U, 4, _EP_IO_HEADER_SIZE)
USB_RAW_IOCTL_CONFIGURE = _ioc(_IOC_NONE, _U, 9, 0)
USB_RAW_IOCTL_EP0_STALL = _ioc(_IOC_NONE, _U, 12, 0)

# usb_device_speed values (uapi/linux/usb/ch9.h)
USB_SPEED_FULL = 2
USB_SPEED_HIGH = 3

# usb_raw_event_type
USB_RAW_EVENT_INVALID = 0
USB_RAW_EVENT_CONNECT = 1
USB_RAW_EVENT_CONTROL = 2
USB_RAW_EVENT_SUSPEND = 3
USB_RAW_EVENT_RESUME = 4
USB_RAW_EVENT_RESET = 5
USB_RAW_EVENT_DISCONNECT = 6

_EVENT_NAMES = {
    USB_RAW_EVENT_INVALID: "invalid",
    USB_RAW_EVENT_CONNECT: "connect",
    USB_RAW_EVENT_CONTROL: "control",
    USB_RAW_EVENT_SUSPEND: "suspend",
    USB_RAW_EVENT_RESUME: "resume",
    USB_RAW_EVENT_RESET: "reset",
    USB_RAW_EVENT_DISCONNECT: "disconnect",
}

# bRequest values of interest (uapi/linux/usb/ch9.h)
GET_DESCRIPTOR = 0x06
SET_CONFIGURATION = 0x09

# bmRequestType direction bit.
_DIR_IN = 0x80

# usb_ctrlrequest: bmRequestType, bRequest, wValue, wIndex, wLength (8 bytes).
_CTRLREQUEST = struct.Struct("<BBHHH")


class RawGadgetError(RuntimeError):
    """Any raw_gadget setup/transport failure (infrastructure, not a security
    result)."""


@dataclass(frozen=True)
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

    @property
    def is_in(self) -> bool:
        return bool(self.bmRequestType & _DIR_IN)

    @classmethod
    def unpack(cls, data: bytes) -> "ControlRequest":
        if len(data) < _CTRLREQUEST.size:
            raise RawGadgetError(
                f"control payload too short: {len(data)} < {_CTRLREQUEST.size}")
        bm, br, wv, wi, wl = _CTRLREQUEST.unpack_from(data)
        return cls(bmRequestType=bm, bRequest=br, wValue=wv, wIndex=wi, wLength=wl)


def pack_init(*, driver_name: str, device_name: str, speed: int) -> bytes:
    """Pack struct usb_raw_init; each name is NUL-padded to 128 bytes."""
    for name in (driver_name, device_name):
        if len(name.encode()) >= _UDC_NAME_LENGTH_MAX:
            raise RawGadgetError(f"UDC name too long: {name!r}")
    return (
        driver_name.encode().ljust(_UDC_NAME_LENGTH_MAX, b"\x00")
        + device_name.encode().ljust(_UDC_NAME_LENGTH_MAX, b"\x00")
        + struct.pack("<B", speed)
    )


def pack_ep_io(data: bytes, *, ep: int = 0, flags: int = 0) -> bytearray:
    """Pack struct usb_raw_ep_io header + data into a mutable buffer."""
    return bytearray(struct.pack("<HHI", ep, flags, len(data))) + bytearray(data)


def pack_event_buffer(data_capacity: int) -> bytearray:
    """Buffer for USB_RAW_IOCTL_EVENT_FETCH: header + room for event data.

    ``length`` must be preset to the data capacity; the driver overwrites it
    with the actual event-data length.
    """
    return bytearray(struct.pack("<II", 0, data_capacity)) + bytearray(data_capacity)


def parse_event_buffer(buf: bytes) -> tuple[int, bytes]:
    event_type, length = struct.unpack_from("<II", buf, 0)
    data = bytes(buf[_EVENT_HEADER_SIZE:_EVENT_HEADER_SIZE + length])
    return event_type, data


# Result of on_control: response bytes to return on an IN request, or None to
# STALL. A profile may also return b"" to ACK a zero-length status stage.
ControlHandler = Callable[[ControlRequest], "bytes | None"]


class Transcript:
    """Append-only JSONL record of the control exchange, flushed per line."""

    def __init__(self, path: str | None, *, run_id: str = ""):
        self._path = path
        self._run_id = run_id
        self._seq = 0
        self._fh = open(path, "w") if path else None

    def record(self, event: str, **fields) -> None:
        self._seq += 1
        rec = {
            "run_id": self._run_id,
            "seq": self._seq,
            "monotonic_ns": time.monotonic_ns(),
            "event": event,
            **fields,
        }
        if self._fh:
            self._fh.write(json.dumps(rec) + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class RawGadget:
    """Open /dev/raw-gadget, bind to a UDC, and dispatch EP0 control requests.

    ``driver_name``/``device_name`` follow the UAPI. For Dummy UDC they are
    "dummy_udc" and "dummy_udc.0"; for the Pi Zero dwc2 both are the same
    platform-device name. Do NOT swap them.
    """

    def __init__(
        self,
        *,
        driver_name: str = "dummy_udc",
        device_name: str = "dummy_udc.0",
        speed: int = USB_SPEED_HIGH,
        event_data_capacity: int = 256,
    ):
        self.driver_name = driver_name
        self.device_name = device_name
        self.speed = speed
        self.event_data_capacity = event_data_capacity
        self.fd = -1

    # --- low-level lifecycle -------------------------------------------------
    def open(self) -> None:
        self.fd = os.open("/dev/raw-gadget", os.O_RDWR)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _ioctl(self, request: int, arg) -> int:
        try:
            return fcntl.ioctl(self.fd, request, arg)
        except OSError as e:
            raise RawGadgetError(
                f"ioctl {request:#010x} failed: {os.strerror(e.errno)} "
                f"(errno {e.errno})") from e

    def init(self) -> None:
        buf = pack_init(driver_name=self.driver_name,
                        device_name=self.device_name, speed=self.speed)
        self._ioctl(USB_RAW_IOCTL_INIT, bytearray(buf))

    def run(self) -> None:
        self._ioctl(USB_RAW_IOCTL_RUN, 0)

    def configure(self) -> None:
        self._ioctl(USB_RAW_IOCTL_CONFIGURE, 0)

    def ep0_stall(self) -> None:
        self._ioctl(USB_RAW_IOCTL_EP0_STALL, 0)

    def ep0_write(self, data: bytes) -> int:
        buf = pack_ep_io(data)
        return self._ioctl(USB_RAW_IOCTL_EP0_WRITE, buf)

    def ep0_read(self, length: int = 0) -> int:
        buf = pack_ep_io(bytes(length))
        return self._ioctl(USB_RAW_IOCTL_EP0_READ, buf)

    def fetch_event(self) -> tuple[int, "ControlRequest | None"]:
        buf = pack_event_buffer(self.event_data_capacity)
        self._ioctl(USB_RAW_IOCTL_EVENT_FETCH, buf)
        event_type, data = parse_event_buffer(buf)
        if event_type == USB_RAW_EVENT_CONTROL:
            return event_type, ControlRequest.unpack(data)
        return event_type, None

    # --- high-level serve loop ----------------------------------------------
    def serve(
        self,
        on_control: ControlHandler,
        *,
        transcript: Transcript | None = None,
        status_cb: Callable[[str], None] | None = None,
    ) -> None:
        """Event loop: drive enumeration and answer EP0 control requests.

        ``on_control`` returns response bytes for an IN request, an empty
        ``bytes`` to ACK a no-data status stage, or ``None`` to STALL. A
        SET_CONFIGURATION request that the profile does not handle is turned into
        a real ``USB_RAW_IOCTL_CONFIGURE`` so the gadget reaches the configured
        state and Windows enumeration proceeds.
        """
        tx = transcript or Transcript(None)

        def note(state: str) -> None:
            tx.record("state", state=state)
            if status_cb:
                status_cb(state)

        self.init()
        note("init_ok")
        self.run()
        note("run_ok")

        while True:
            event_type, req = self.fetch_event()
            name = _EVENT_NAMES.get(event_type, f"unknown({event_type})")

            if event_type == USB_RAW_EVENT_CONNECT:
                tx.record("connect")
                note("connect")
                continue

            if event_type in (USB_RAW_EVENT_RESET, USB_RAW_EVENT_DISCONNECT,
                              USB_RAW_EVENT_SUSPEND, USB_RAW_EVENT_RESUME):
                tx.record("bus", kind=name)
                continue

            if event_type != USB_RAW_EVENT_CONTROL or req is None:
                tx.record("ignored", kind=name)
                continue

            self._handle_control(req, on_control, tx)

    def _handle_control(
        self, req: ControlRequest, on_control: ControlHandler, tx: Transcript,
    ) -> None:
        reply = on_control(req)

        if reply is None and not req.is_in and req.bRequest == SET_CONFIGURATION:
            # Default handling so the gadget reaches the configured state.
            #
            # SET_CONFIGURATION is an OUT/no-data control request, so the
            # completion primitive is EP0_READ, not EP0_WRITE. The latter
            # fails with EBUSY on the lab dummy_hcd/raw_gadget stack and leaves
            # the host-side configuration attempt to time out.
            self.configure()
            transferred = self.ep0_read(0)
            tx.record(
                "control",
                request=self._req_dict(req),
                response={"action": "configure", "transferred": transferred},
            )
            return

        if reply is None:
            self.ep0_stall()
            tx.record(
                "control", request=self._req_dict(req),
                response={"action": "stall"})
            return

        clipped = reply[: req.wLength] if req.is_in else reply
        transferred = self.ep0_write(clipped)
        tx.record(
            "control",
            request=self._req_dict(req),
            response={
                "action": "write",
                "planned_len": len(reply),
                "sent_len": len(clipped),
                "transferred": transferred,
                "planned_hex": reply.hex(),
            },
        )

    @staticmethod
    def _req_dict(req: ControlRequest) -> dict:
        return {
            "bmRequestType": req.bmRequestType,
            "bRequest": req.bRequest,
            "wValue": req.wValue,
            "wIndex": req.wIndex,
            "wLength": req.wLength,
            "descriptor_type": req.descriptor_type,
            "descriptor_index": req.descriptor_index,
        }
