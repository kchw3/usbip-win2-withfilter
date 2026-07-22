# USB/IP Filter Test Session Memory

Last updated: 2026-07-22

## Current state

Branch: `master`
Remote target: `origin/master`
User preference in this thread: commit and push directly to `master`.

The pytest hang was reproduced and attributed to a kernel crash in the Linux
`usbip_vudc` backend. Tier A configfs gadget tests have now been migrated to
`dummy_hcd`/`dummy_udc.0` with dynamic USB/IP bus-id discovery. Do not resume the
matrix on vUDC except for explicit compatibility validation.

Latest dummy_hcd validation:

- local unit/syntax checks passed:
  - `python3 -m py_compile test/conftest.py test/test_connectivity.py`
  - `bash -n test/linux/gadget_lib.sh test/linux/gadgets/teardown.sh`
  - `git diff --check`
  - `pytest -q test/test_descriptors.py test/test_hid_probe.py test/test_raw_gadget.py test/test_parser_native.py`
- `test/config.ini` was switched to `udc_name = dummy_udc.0`, `busid = auto`
  (ignored local lab config).
- `test/linux/` was deployed to `/opt/usbip-filter-test/linux/`.
- Connectivity on dummy_hcd passed: `12 passed, 1 skipped`.
- Targeted rows passed:
  - `deny_all-hid_keyboard`
  - `allow_hid-hid_keyboard`
  - `allow_ms-mass_storage`
- Full Tier A matrix passed on dummy_hcd:
  - `35 passed in 548.17s (0:09:08)`
- Full suite passed on dummy_hcd:
  - `72 passed, 9 skipped in 523.97s (0:08:43)`
  - expected skips: efficacy tests remain opt-in, the vUDC-only connectivity
    mode check is skipped for `dummy_udc.0`, and Tier B Raw Gadget tests remain
    skipped pending lab bring-up validation.

Implementation notes:

- `usbip_export auto` now resolves the enumerated dummy_hcd busid by VID/PID
  (for example `5-1`), unbinds local Linux host interface drivers, loads
  `usbip_host`, binds the device with `usbip bind`, and returns the resolved
  busid to the Python harness.
- The Python harness updates `linux.busid` after export so Windows attach and
  rejection-event correlation use the actual busid instead of the configured
  placeholder.
- Teardown receives the resolved busid via `BUSID=...` before unbinding and
  removing the configfs gadget.
- `vendor_ff` is marked as driverless for allow-path matrix oracles: successful
  attach plus matching PnP exposure is sufficient because the SourceSink
  vendor-specific gadget has no Windows in-box function driver and may not reach
  `Status=OK`.

## Confirmed root cause and backend decision

The apparent pytest freeze was reproduced and traced to a repeatable Linux kernel
crash in the `usbip_vudc` backend. An allowed mass-storage matrix row triggers a
NULL dereference while the file-storage function dequeues an endpoint:

```text
BUG: kernel NULL pointer dereference, address: 0000000000000398
Comm: file-storage
RIP: 0010:vep_dequeue+0x27/0x120 [usbip_vudc]
usb_ep_dequeue+0x22/0x80 [udc_core]
fsg_main_thread+0x3f0/0x1d90 [usb_f_mass_storage]
note: file-storage[...] exited with irqs disabled
```

After the oops, gadget builders and teardown processes remain permanently in
uninterruptible `D` state in `gadget_dev_desc_UDC_store` or `fsg_unbind`. Even
reading the configfs gadget `UDC` attribute can block. SSH timeouts make pytest
report the failure, but only rebooting the Linux host recovers the kernel state.

Decision: migrate Tier A configfs gadget tests from `usbip-vudc` to
`dummy_hcd`/`dummy_udc.0`. The gadget will bind to `dummy_udc.0`, enumerate on
the synthetic Linux USB host, and be exported using host-mode `usbipd` plus
`usbip bind`. Keep `usbip-vudc` only as an optional compatibility backend; do
not rely on it for mass-storage or composite mass-storage tests.

The dummy_hcd migration must add dynamic Linux USB bus-id discovery (for
example `5-1`), unbind any Linux host driver that claims the synthetic device,
export that bus-id, expose the resolved bus-id to Windows attach/event
correlation, and unexport it before gadget teardown. Raw-gadget UDC naming must
remain backend-specific.

## Worktree changes from the investigation

Uncommitted fixes currently present:

- `test/conftest.py`, `test/test_connectivity.py`, and
  `test/linux/gadget_lib.sh` inspect only real processes named `usbipd` via
  `ps -C usbipd -o args=`. The former `pgrep -af usbipd` check matched its own
  diagnostic shell and falsely reported device mode after reboot.
- `test/windows/helpers.ps1` uses `ReadToEndAsync()` tasks instead of
  PowerShell `DataReceivedEventHandler` scriptblocks. The callbacks ran on
  worker threads without a WinRM runspace and terminated policy calls with a
  truncated `#< CLIXML` error. Revision marker is now `task-v4`.
- Windows cleanup uses `${id}` correctly in its PowerShell error string; the
  former `$id:` form was a parser error.
- `test/README.md` documents the new `task-v4` helper marker.

The corrected Linux `gadget_lib.sh` was deployed to
`/opt/usbip-filter-test/linux`. The configured protected Windows helper path
could not be overwritten by the WinRM account, so the corrected helper was
uploaded temporarily to:

```text
C:\Users\User1\AppData\Local\Temp\usbip-filter-test-helpers.ps1
```

The ignored local `test/config.ini` currently points `[windows] helpers` at
that temporary file. Connectivity helper-hash validation passed with it.

## Resume after Linux reboot

1. Run the connectivity suite with the existing virtual environment and
   auto-fix enabled so required modules load and a backend-appropriate usbipd
   starts.
2. Implement the dummy_hcd backend migration before running another allowed
   mass-storage row; running it on usbip-vudc will likely crash the kernel again.
3. Deploy the changed `test/linux/` tree and verify
   `test_linux_deploy_in_sync` plus the Windows helper hash check.
4. Validate one deny and one allow case on dummy_hcd, then the allowed
   mass-storage case, the complete matrix, and finally `pytest -s`.
5. Keep destructive efficacy tests opt-in.

Validation achieved before the second reproduced kernel crash:

- all 13 connectivity/deployment checks passed;
- `deny_all-hid_keyboard` passed end-to-end in 16.8 seconds;
- the matrix passed 16 rows before `allow_ms-mass_storage` reproduced the
  `usbip_vudc::vep_dequeue` oops during cleanup/teardown.

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
