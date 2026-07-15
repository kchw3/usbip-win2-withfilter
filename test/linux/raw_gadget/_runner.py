"""Shared entry point for raw_gadget Tier B profiles.

A profile supplies an ``on_control`` handler and its VID/PID; this runner owns
the process lifecycle and, crucially, the *evidence* the harness relies on:

* ``status.json`` in ``RUN_DIR`` records the current lifecycle state and the
  ``run_id``, so the harness can confirm the producer actually reached a live,
  configured state (and is not a stale process from a previous run).
* ``transcript.jsonl`` records every control request/response so the harness can
  assert the crafted exchange really happened.

Any failure writes an ``error`` status and exits non-zero, so the harness treats
it as an infrastructure failure rather than a security "fail closed" pass.

Environment:
  RUN_DIR      directory for status.json / transcript.jsonl (required)
  RUN_ID       unique per-run token the harness also knows (required)
  UDC_DRIVER   raw_gadget driver_name (default: dummy_udc)
  UDC_DEVICE   raw_gadget device_name (default: dummy_udc.0)
  SPEED        'full' or 'high' (default: high)
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

from _raw_gadget import (
    USB_SPEED_FULL,
    USB_SPEED_HIGH,
    ControlHandler,
    RawGadget,
    Transcript,
)


def _speed_from_env() -> int:
    return {"full": USB_SPEED_FULL, "high": USB_SPEED_HIGH}[
        os.environ.get("SPEED", "high").lower()
    ]


class _StatusFile:
    def __init__(self, path: Path, *, run_id: str, vid: int, pid: int):
        self._path = path
        self._run_id = run_id
        self._vid = vid
        self._pid = pid

    def write(self, state: str, *, error: str | None = None) -> None:
        payload = {
            "run_id": self._run_id,
            "pid": os.getpid(),
            "state": state,
            "vid": f"{self._vid:04X}",
            "product_id": f"{self._pid:04X}",
        }
        if error is not None:
            payload["error"] = error
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload))
        tmp.replace(self._path)  # atomic


def run_profile(name: str, on_control: ControlHandler, *, vid: int, pid: int) -> None:
    run_dir = Path(os.environ["RUN_DIR"])
    run_id = os.environ["RUN_ID"]
    run_dir.mkdir(parents=True, exist_ok=True)

    status = _StatusFile(run_dir / "status.json", run_id=run_id, vid=vid, pid=pid)
    transcript = Transcript(str(run_dir / "transcript.jsonl"), run_id=run_id)
    status.write("started")

    gadget = RawGadget(
        driver_name=os.environ.get("UDC_DRIVER", "dummy_udc"),
        device_name=os.environ.get("UDC_DEVICE", "dummy_udc.0"),
        speed=_speed_from_env(),
    )
    try:
        gadget.open()
        gadget.serve(on_control, transcript=transcript, status_cb=status.write)
    except BaseException as e:  # noqa: BLE001 - record everything for the harness
        status.write("error", error=f"{type(e).__name__}: {e}")
        transcript.record("error", message=str(e), traceback=traceback.format_exc())
        transcript.close()
        gadget.close()
        print(f"[{name}] raw_gadget error: {e}", file=sys.stderr)
        raise SystemExit(1) from e
    finally:
        transcript.close()
        gadget.close()
