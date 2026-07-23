# USB/IP Filter Test Session Memory

Last updated: 2026-07-22

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
- Full suite with efficacy:
  - command: `pytest -q test --run-efficacy -ra --maxfail=1`
  - result: `76 passed, 5 skipped, 1 xfailed in 667.41s (0:11:07)`
  - no failures or errors.

## Expected skips and xfail

- Skipped under dummy_hcd:
  - `test/test_connectivity.py::test_linux_usbipd_device_mode`
    (`udc_name='dummy_udc.0' is not a vudc; device-mode check N/A`)
  - `test/test_robustness.py::test_malformed_descriptors_fail_closed[zero_interface]`
  - `test/test_robustness.py::test_malformed_descriptors_fail_closed[lying_count]`
  - `test/test_robustness.py::test_malformed_descriptors_fail_closed[bad_total_length]`
  - `test/test_robustness.py::test_descriptor_toctou_no_bypass`
- Tier B robustness skips remain intentional until Raw Gadget lab bring-up proves the stimulus path and failure canaries.
- Xfail:
  - `test/test_attack_efficacy.py::test_rogue_nic_appears`
  - attach and VID/PID PnP exposure succeed for CDC ECM, but this Windows client does not start a VID/PID-matched `Net` child.

## Implemented harness behavior

- `usbip_export auto` resolves the enumerated dummy_hcd busid by VID/PID, unbinds local Linux host interface drivers, loads `usbip_host`, binds with `usbip bind`, and returns the resolved busid.
- The Python harness updates `linux.busid` after export so Windows attach and rejection-event correlation use the actual busid.
- Teardown receives `BUSID=...` before unbinding and removing the configfs gadget.
- `vendor_ff` allow-path matrix checks require successful attach plus matching PnP exposure, not `Status=OK`, because SourceSink has no Windows in-box function driver.
- HID and CDC ECM efficacy limitations are precise xfails only after hard preconditions pass.

## Next work

See `test/NEXT_STEPS_PLAN.md`. Current implementation target completed: Linux kernel / USB-IP / UDC / backend manifest output is now recorded by connectivity. Next target: Tier B Raw Gadget bring-up canaries before unskipping robustness tests.

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
