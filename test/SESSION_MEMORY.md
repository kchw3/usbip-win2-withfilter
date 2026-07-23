# USB/IP Filter Test Session Memory

Last updated: 2026-07-23

## Current state

- Branch/remote target: `master` / `origin/master`.
- User preference: commit and push directly to `master` after validation.
- Active Tier A backend: `dummy_hcd` with `[linux] udc_name = dummy_udc.0` and `busid = auto`.
- Do not run Tier A mass-storage or composite mass-storage rows on `usbip-vudc`; the lab kernel reproduced a `usbip_vudc::vep_dequeue` crash during teardown.
- `test/config.ini` is ignored and lab-local. The Windows helper path currently points to:
  `C:\Users\User1\AppData\Local\Temp\usbip-filter-test-helpers.ps1`.
- If `test/windows/helpers.ps1` changes, copy it to the configured Windows helper path before relying on helper behavior. Connectivity verifies the helper hash.

## Latest validated baseline

- Linux `test/linux/` deployed to `/opt/usbip-filter-test/linux/`.
- Connectivity on dummy_hcd: `13 passed, 1 skipped`.
- Linux manifest recorded by connectivity:
  - kernel: `6.19.14`
  - kernel_full: `Linux kali 6.19.14 #7 SMP PREEMPT_DYNAMIC Tue Jun 23 02:43:23 EDT 2026 x86_64 GNU/Linux`
  - usbip_version: `usbip (usbip-utils 2.0)`
  - backend: `host-auto-busid`
  - configured_udc/configured_busid: `dummy_udc.0` / `auto`
  - usbipd_args/mode: `usbipd -D` / `host`
  - modules loaded: `libcomposite`, `dummy_hcd`, `usbip_host`, `usbip_vudc`, `raw_gadget`
- Full Tier A matrix: `35 passed in 548.17s (0:09:08)`.
- Full suite without efficacy: `72 passed, 9 skipped in 523.97s (0:08:43)`.
- Tier B Raw Gadget canaries:
  - command: `pytest -q test/test_tierb_canaries.py --run-tierb-canaries --maxfail=1`
  - result: `7 passed in 24.22s`
  - proves UDC naming, dead producer detection, wrong UDC failure, suppressed
    export failure, wrong busid failure, omitted config-response detection, and
    benign Raw Gadget attach/PnP exposure through Windows.
- Tier B Raw Gadget robustness:
  - command: `pytest -q test/test_robustness.py --maxfail=1 -ra`
  - result: `4 passed in 41.15s`
  - malformed descriptor rows are now active security gates; TOCTOU accounts for
    dummy_hcd's two pre-export configuration fetches plus the filter's two
    snapshot fetches before switching to the malicious descriptor.
- Full suite with efficacy:
  - command: `pytest -q test --run-efficacy -ra --maxfail=1`
  - result: `81 passed, 8 skipped in 734.70s (0:12:14)`
  - no failures, errors, or xfails.

## Expected skips and xfail

- Skipped under dummy_hcd:
  - `test/test_connectivity.py::test_linux_usbipd_device_mode`
    (`udc_name='dummy_udc.0' is not a vudc; device-mode check N/A`)
- Tier B canaries:
  - `test/test_tierb_canaries.py` has 7 tests skipped by default unless
    `--run-tierb-canaries` is supplied.
- Expected xfails: none on the current dummy_hcd baseline after `rndis_os_nic`
  resolved rogue-NIC efficacy.

## Implemented harness behavior

- `usbip_export auto` resolves the enumerated dummy_hcd busid by VID/PID, unbinds local Linux host interface drivers, loads `usbip_host`, binds with `usbip bind`, and returns the resolved busid.
- The Python harness updates `linux.busid` after export so Windows attach and rejection-event correlation use the actual busid.
- Teardown receives `BUSID=...` before unbinding and removing the configfs gadget.
- `vendor_ff` allow-path matrix checks require successful attach plus matching PnP exposure, not `Status=OK`, because SourceSink has no Windows in-box function driver.
- HID efficacy currently passes on the dummy_hcd lane. If it regresses to the
  previous endpoint-disabled condition, the xfail includes Linux/Windows
  transport diagnostics.
- Rogue NIC efficacy now tries CDC ECM, plain RNDIS, and RNDIS with Microsoft OS
  descriptors. Plain CDC/RNDIS still fail Windows driver binding with Problem 28,
  but `rndis_os_nic` starts a VID/PID-matched `Net` child and satisfies the
  negative control.
- Matrix deny rows now validate the rejection-event contract beyond VID/PID/busid:
  current deployed drivers must include the fail-closed reason and source
  context; new driver builds put reason/class/whitelist first in the event
  insertion string so the test also asserts the rejected class tuple and active
  whitelist text when available.
- Raw Gadget SET_CONFIGURATION handling uses `USB_RAW_IOCTL_CONFIGURE` followed
  by zero-length `EP0_READ`, matching OUT/no-data control completion. Using
  `EP0_WRITE` left dummy_hcd stuck at `can't set config #1, error -110` and
  caused usbip-host/Windows descriptor fetch failures.

## Next work

See `test/NEXT_STEPS_PLAN.md`. Current implementation target completed: Tier B
Raw Gadget robustness tests are active and validated, and HID efficacy currently
passes with diagnostic fallback for endpoint-disabled regressions. Rogue-NIC
efficacy now passes via the OS-descriptor-backed RNDIS lane. Rejection-event
oracle hardening is in progress. Next target: expand network/vendor allow cases
or parser fuzz coverage per `NEXT_STEPS_PLAN.md`.

## Config knobs

Recommended lab config:

```ini
[linux]
udc_name = dummy_udc.0
busid = auto
command_timeout = 60

[windows]
cleanup_detach = skip
cleanup_reset_policy = false
cleanup_step_timeout = 20
cleanup_timeout = 60
winrm_step_timeout = 30
```
