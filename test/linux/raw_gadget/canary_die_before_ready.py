#!/usr/bin/env python3
"""Raw Gadget canary profile that dies before reaching run_ok/connect."""

from __future__ import annotations

import json
import os
from pathlib import Path

run_dir = Path(os.environ["RUN_DIR"])
run_dir.mkdir(parents=True, exist_ok=True)
(run_dir / "status.json").write_text(json.dumps({
    "run_id": os.environ["RUN_ID"],
    "pid": os.getpid(),
    "state": "started",
    "vid": "16C0",
    "product_id": "03F2",
}))
raise SystemExit(42)
