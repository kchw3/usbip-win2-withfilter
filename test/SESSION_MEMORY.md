# USB/IP Filter Test Session Memory

Last updated: 2026-07-22

## Current state

Branch: `master`
Remote target: `origin/master`
User preference in this thread: commit and push directly to `master`.

The active investigation is pytest hanging during `pytest -s` when the run reaches
`test/test_matrix.py`. Earlier hangs looked like Windows cleanup, but the latest
instrumentation showed cleanup now completes:

```text
[cleanup] starting Windows cleanup (timeout=60s, step_timeout=20s, detach=skip)
[cleanup] skipping USB/IP detach by request
[cleanup] skipping filter reset by request
[cleanup] phase: enumerate stale VID_16C0 PnP nodes (timeout=20s)
[cleanup] no stale VID_16C0 PnP nodes found
[cleanup] phase: verify no stale VID_16C0 PnP nodes remain (timeout=20s)
[cleanup] Windows cleanup completed
```

Because no `[policy]` line appeared afterward, the hang is after fixture cleanup
and before the matrix policy call. In `test/test_matrix.py`, that maps to:

```python
linux.build_gadget(dev.gadget, vid=f"0x{VID}", pid=f"0x{dev.pid}")
```

The latest patch adds Linux-side phase logging and SSH command timeouts so the
next run identifies whether the stuck remote process is vUDC preflight, gadget
build, or `usbip_export`.

Expected new output near the next hang:

```text
[matrix] row: policy=deny_all device=hid_keyboard expected_allow=False
[linux] phase: preflight vudc usbip-vudc.0 (timeout=60s)
[linux] phase: build gadget hid_keyboard VID=0x16C0 PID=0x03E8 (timeout=60s)
[linux] phase: export gadget busid=usbip-vudc.0 (timeout=60s)
[policy] phase: filter --deny-all
[windows] phase: read usbip2_ude event cursor
[windows] phase: usbip.exe attach busid=usbip-vudc.0
```

Whichever phase is the last printed line is the next process/function to inspect.
If a Linux phase times out, the exception includes the exact SSH command plus
captured stdout/stderr.

## Important deployment note

The pytest harness loads Windows helpers from the Windows path configured in
`test/config.ini` under `[windows] helpers`. If `test/windows/helpers.ps1` changes,
copy it to that Windows path before relying on helper changes. The connectivity
check verifies this hash:

```bash
pytest test/test_connectivity.py::test_windows_artifacts_identified_and_helpers_in_sync -v
```

## Config knobs added during this session

Windows section in `test/config.ini`:

```ini
cleanup_detach = skip          # default; other values: closeonly, full
cleanup_reset_policy = false   # default; avoids cleanup-time filter --disable wedge
cleanup_step_timeout = 20      # per cleanup WinRM step
cleanup_timeout = 60           # legacy whole cleanup timeout
winrm_step_timeout = 30        # policy/event/attach WinRM operations
```

Linux section in `test/config.ini`:

```ini
command_timeout = 60           # SSH command timeout for labelled Linux phases
```

## Recent commits and purpose

- `5f58faa7 Wait for VID-matched NIC child`
  - Rogue NIC efficacy now waits for a present/OK VID/PID-matched `Net` child.
  - README documents which tests require function-child readiness.

- `dcf459a6 Bound Windows cleanup native calls`
  - Added bounded native Windows helper calls around `detach`, `attach`, `filter`,
    and `pnputil`.

- `3e4b398a Avoid cleanup timeout output hang`
  - Changed native output capture to async to avoid blocking after timeout.
  - Added helper marker `async-v2`.

- `19062e80 Bound Windows cleanup WinRM call`
  - Wrapped the whole cleanup WinRM call in a Python timeout.

- `c8b27509 Default cleanup to closeonly detach`
  - Added `cleanup_detach` modes and changed cleanup detach behavior.

- `69ac963d Split Windows cleanup phases`
  - Split cleanup into detach and filter/PnP phases for clearer diagnostics.

- `0f8ebd38 Skip USBIP detach during cleanup by default`
  - Defaulted cleanup detach to `skip` because even closeonly could wedge.

- `7964fbbb Pinpoint Windows cleanup stalls`
  - Split cleanup into line-level WinRM phases: filter reset, stale node enum,
    per-node removal, and verify.

- `002be9f8 Skip cleanup policy reset by default`
  - Defaulted cleanup policy reset to false because cleanup was wedging in
    `usbip.exe filter --disable`.
  - Tests still set their intended policy before attach.

## Latest diagnostic patch

Files:

- `test/conftest.py`
- `test/test_matrix.py`
- `test/README.md`
- `test/SESSION_MEMORY.md`

Changes:

- `LinuxServer.run()` now polls Paramiko channels with a timeout instead of
  waiting forever in `recv_exit_status()`.
- Labelled Linux phases print only for important operations:
  - `preflight vudc ...`
  - `build gadget ...`
  - `export gadget ...`
  - `export raw gadget ...`
  - `teardown gadget`
- `test_matrix.py` prints the active matrix row before building the gadget.
- Windows `event_cursor()` and `attach_result()` now print phase labels and use
  `winrm_step_timeout`.
- README documents `[linux] command_timeout`.

Validation before commit:

```bash
python3 -m py_compile test/conftest.py test/test_matrix.py
git diff --check
```

Both passed locally.

## Suggested next run

After pulling latest `master` in the lab checkout:

```bash
pytest -s test/test_matrix.py::test_decision[deny_all-hid_keyboard]
```

If that passes, run the full matrix:

```bash
pytest -s test/test_matrix.py
```

If the full suite is needed:

```bash
pytest -s
```

If the hang is now in a Linux phase, inspect the corresponding server-side
command. For vUDC gadget tests the usual suspects are:

```bash
pgrep -af usbipd
usbip list -r 127.0.0.1
cat /sys/kernel/config/usb_gadget/usbiptest/UDC
ls /sys/class/udc
```

For a stuck gadget teardown/build, also check whether the previous gadget is
still bound to the UDC and whether configfs removal is blocked.
