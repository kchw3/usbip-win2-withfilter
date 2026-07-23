# USB/IP Filter Validation Next Steps

Last updated: 2026-07-22

## Current baseline

- Active Tier A backend: `dummy_hcd` with `[linux] udc_name = dummy_udc.0` and `busid = auto`.
- Do not use `usbip-vudc` for Tier A mass-storage or composite mass-storage rows; the lab kernel reproduced a `usbip_vudc::vep_dequeue` crash during teardown.
- Latest validation:
  - Connectivity: `13 passed, 1 skipped`.
  - Full Tier A matrix: `35 passed`.
  - Full suite: `72 passed, 9 skipped`.
  - Full suite with efficacy: `76 passed, 5 skipped, 1 xfailed`.
- Phase 0 Linux attribution is implemented: connectivity records kernel, USB/IP tool, module, configured UDC/busid, backend, and daemon mode.
- Expected skip/xfail state:
  - vUDC device-mode connectivity check skips under `dummy_udc.0`.
  - Tier B Raw Gadget robustness tests remain skipped pending lab bring-up.
  - `test_rogue_nic_appears` xfails because CDC ECM attaches and exposes VID/PID, but this Windows client does not start a VID/PID-matched `Net` child.

## Ordered implementation plan

1. Bring up Tier B Raw Gadget canaries before unskipping robustness tests:
   - confirm `raw_udc_driver` / `raw_udc_device`;
   - prove killed producer, suppressed export, wrong busid, and omitted crafted response all fail red;
   - prove one benign Raw Gadget profile enumerates through the same UDC/USB-IP path.
2. Diagnose HID efficacy xfail with TCP/3240, Linux gadget/UDC traces, and Windows WPP to identify the first missing transaction.
3. Resolve or narrow the CDC ECM NIC xfail, preferably with an alternate RNDIS or hardware-backed NIC path if this Windows image lacks a CDC ECM network driver.
4. Harden remaining oracles:
   - assert rejection reason/class/active whitelist once the event message contract is pinned;
   - expand network/vendor allow cases;
   - keep efficacy checks VID/PID-correlated.
5. Extend native parser fuzz coverage for multi-configuration/indexed descriptors, IAD, class-specific descriptors, excessive counts/lengths, and subclass/protocol edge cases.
6. Validate descriptor snapshots with a WDK `/WX` build and lab run.
7. Add an opt-in hardware-backed efficacy lane through `usbip-host`.

## Validation checklist

- Static checks:
  - `python3 -m py_compile test/conftest.py test/test_connectivity.py test/test_attack_efficacy.py`
  - `bash -n test/linux/gadget_lib.sh test/linux/gadgets/teardown.sh`
  - `git diff --check`
- Lab checks:
  - `pytest -q test/test_connectivity.py --maxfail=1`
  - `pytest -q test/test_matrix.py --maxfail=1`
  - `pytest -q test --run-efficacy -ra --maxfail=1`

## Implementation defaults

- Keep destructive efficacy tests opt-in via `--run-efficacy`.
- Keep Tier B skipped until Raw Gadget canaries prove the stimulus path.
- Do not commit ignored `test/config.ini`.
- Commit and push validated changes to `master`.
