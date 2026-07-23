"""Pure unit tests for the raw_gadget transport encoding and serve dispatch.

These run anywhere (no kernel, no /dev/raw-gadget). They lock down the ioctl
encodings, struct packing, and the EP0 control-dispatch decisions -- the logic
most likely to be silently wrong and to turn a broken producer into a
false-green security result.
Run: pytest test/test_raw_gadget.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "linux" / "raw_gadget"))

import _raw_gadget as rg  # noqa: E402


# --- ioctl encoding ----------------------------------------------------------

def _decode(nr_encoded: int) -> tuple[int, int, int, int]:
    direction = (nr_encoded >> rg._IOC_DIRSHIFT) & 0x3
    size = (nr_encoded >> rg._IOC_SIZESHIFT) & ((1 << rg._IOC_SIZEBITS) - 1)
    type_ = (nr_encoded >> rg._IOC_TYPESHIFT) & 0xFF
    nr = (nr_encoded >> rg._IOC_NRSHIFT) & 0xFF
    return direction, type_, nr, size


def test_ioctl_init_encoding():
    direction, type_, nr, size = _decode(rg.USB_RAW_IOCTL_INIT)
    assert direction == rg._IOC_WRITE
    assert type_ == ord("U")
    assert nr == 0
    assert size == 257  # 128 + 128 + 1


def test_ioctl_numbers_match_kernel_uapi():
    # Values from <uapi/linux/usb/raw_gadget.h> on x86_64/arm64.
    assert rg.USB_RAW_IOCTL_INIT == 0x41015500
    assert rg.USB_RAW_IOCTL_RUN == 0x00005501
    assert rg.USB_RAW_IOCTL_EVENT_FETCH == 0x80085502
    assert rg.USB_RAW_IOCTL_EP0_WRITE == 0x40085503
    assert rg.USB_RAW_IOCTL_EP0_READ == 0xC0085504
    assert rg.USB_RAW_IOCTL_CONFIGURE == 0x00005509
    assert rg.USB_RAW_IOCTL_EP0_STALL == 0x0000550C


# --- struct packing ----------------------------------------------------------

def test_pack_init_layout():
    buf = rg.pack_init(driver_name="dummy_udc", device_name="dummy_udc.0",
                       speed=rg.USB_SPEED_HIGH)
    assert len(buf) == 257
    assert buf[:9] == b"dummy_udc"
    assert buf[9] == 0  # NUL padding
    assert buf[128:139] == b"dummy_udc.0"
    assert buf[-1] == rg.USB_SPEED_HIGH


def test_pack_ep_io_header():
    buf = rg.pack_ep_io(b"\x01\x02\x03")
    # ep(u16)=0, flags(u16)=0, length(u32)=3, then data
    assert bytes(buf[:8]) == b"\x00\x00\x00\x00\x03\x00\x00\x00"
    assert bytes(buf[8:]) == b"\x01\x02\x03"


def test_control_request_roundtrip():
    raw = rg._CTRLREQUEST.pack(0x80, rg.GET_DESCRIPTOR, 0x0200, 0, 9)
    req = rg.ControlRequest.unpack(raw)
    assert req.is_in
    assert req.descriptor_type == 0x02
    assert req.descriptor_index == 0
    assert req.wLength == 9


# --- serve dispatch ----------------------------------------------------------

class _StopServe(Exception):
    pass


class _FakeGadget(rg.RawGadget):
    """RawGadget with the /dev-touching calls stubbed and events scripted."""

    def __init__(self, events):
        super().__init__()
        self._events = list(events)
        self.actions: list[tuple] = []

    def init(self):
        self.actions.append(("init",))

    def run(self):
        self.actions.append(("run",))

    def configure(self):
        self.actions.append(("configure",))

    def ep0_stall(self):
        self.actions.append(("stall",))

    def ep0_write(self, data):
        self.actions.append(("write", bytes(data)))
        return len(data)

    def ep0_read(self, length=0):
        self.actions.append(("read", length))
        return length

    def fetch_event(self):
        if not self._events:
            raise _StopServe
        return self._events.pop(0)


def _ctrl(bm, br, wv=0, wi=0, wl=0):
    return (rg.USB_RAW_EVENT_CONTROL,
            rg.ControlRequest(bmRequestType=bm, bRequest=br, wValue=wv,
                              wIndex=wi, wLength=wl))


def _serve(gadget, on_control, transcript=None):
    try:
        gadget.serve(on_control, transcript=transcript)
    except _StopServe:
        pass


def test_in_reply_is_clipped_to_wlength():
    # Host asks for 9 bytes; profile returns a longer buffer.
    events = [_ctrl(0x80, rg.GET_DESCRIPTOR, wv=0x0200, wl=9)]
    gadget = _FakeGadget(events)
    payload = bytes(range(32))
    _serve(gadget, lambda req: payload)
    assert ("write", payload[:9]) in gadget.actions
    assert ("write", payload) not in gadget.actions


def test_set_configuration_default_configures_and_acks():
    # OUT SET_CONFIGURATION, profile returns None -> serve must configure and
    # complete the OUT/no-data status stage via EP0_READ.
    events = [_ctrl(0x00, rg.SET_CONFIGURATION, wv=1)]
    gadget = _FakeGadget(events)
    _serve(gadget, lambda req: None)
    assert ("configure",) in gadget.actions
    assert ("read", 0) in gadget.actions
    assert ("write", b"") not in gadget.actions
    assert ("stall",) not in gadget.actions


def test_unhandled_in_request_stalls():
    events = [_ctrl(0x80, 0xFF, wl=8)]  # unknown IN request
    gadget = _FakeGadget(events)
    _serve(gadget, lambda req: None)
    assert ("stall",) in gadget.actions


def test_transcript_records_transferred_lengths(tmp_path):
    events = [_ctrl(0x80, rg.GET_DESCRIPTOR, wv=0x0200, wl=4)]
    gadget = _FakeGadget(events)
    tx = rg.Transcript(str(tmp_path / "t.jsonl"), run_id="unit")
    _serve(gadget, lambda req: b"\xaa\xbb\xcc\xdd\xee", transcript=tx)
    tx.close()

    lines = (tmp_path / "t.jsonl").read_text().splitlines()
    controls = [__import__("json").loads(ln) for ln in lines
                if __import__("json").loads(ln)["event"] == "control"]
    assert len(controls) == 1
    resp = controls[0]["response"]
    assert resp["planned_len"] == 5
    assert resp["sent_len"] == 4
    assert resp["transferred"] == 4
