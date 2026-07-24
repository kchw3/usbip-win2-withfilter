# USB/IP Filter Validation Next Steps

Last updated: 2026-07-23

## Current baseline

- Active Tier A backend: `dummy_hcd` with `[linux] udc_name = dummy_udc.0` and `busid = auto`.
- Do not use `usbip-vudc` for Tier A mass-storage or composite mass-storage rows; the lab kernel reproduced a `usbip_vudc::vep_dequeue` crash during teardown.
- Latest validation:
  - Connectivity: `13 passed, 1 skipped`.
  - Full Tier A matrix: `56 passed`.
  - Full suite: `72 passed, 9 skipped`.
  - Full suite with efficacy: `107 passed, 8 skipped`.
  - Tier B Raw Gadget canaries: `7 passed`.
  - Tier B Raw Gadget robustness: `6 passed`.
- Phase 0 Linux attribution is implemented: connectivity records kernel, USB/IP tool, module, configured UDC/busid, backend, and daemon mode.
- Tier B Raw Gadget bring-up canaries are implemented and opt-in via
  `--run-tierb-canaries`. They now prove UDC naming, dead producer detection,
  wrong UDC failure, suppressed export failure, wrong busid failure, omitted
  config-response detection, and one benign Raw Gadget Windows attach path.
- Expected skip/xfail state:
  - vUDC device-mode connectivity check skips under `dummy_udc.0`.
  - Tier B Raw Gadget canaries skip by default unless `--run-tierb-canaries` is
    supplied.
  - No expected xfails on the dummy_hcd baseline after `rndis_os_nic` resolved
    the rogue-NIC negative-control lane.

## Ordered implementation plan

1. Completed: bring up Tier B Raw Gadget canaries before unskipping robustness tests:
   - confirm `raw_udc_driver` / `raw_udc_device`;
   - prove killed producer, suppressed export, wrong busid, and omitted crafted response all fail red;
   - prove one benign Raw Gadget profile enumerates through the same UDC/USB-IP path.
2. Completed: convert Tier B robustness tests from unconditional skips to gated Raw Gadget security rows now that the canary path is proven.
3. Completed: diagnose HID efficacy path. The dummy_hcd baseline now passes HID
   keystroke injection; if endpoint-disabled regresses, the xfail includes a
   Linux/Windows transport snapshot.
4. Completed: narrow the CDC ECM NIC xfail by trying both CDC ECM and RNDIS and
   recording per-shape PnP/driver diagnostics. Both shapes attach but fail
   Windows network driver binding on this image.
5. Completed: add an OS-descriptor-backed RNDIS network efficacy lane
   (`rndis_os_nic`) so the rogue-NIC negative control proves a live
   VID/PID-matched `Net` child on this client.
6. Harden remaining oracles:
   - completed: rejection events now assert fail-closed reason and source
     context on the current deployed driver; the driver source event contract now
     puts reason/class/whitelist first so full class + whitelist assertions
     activate once that build is deployed.
   - completed: expanded network/vendor allow cases (`allow_network`,
     `allow_vendor`, `allow_network_vendor`) and aligned the RNDIS decision
     model with the production parser's network-class view.
   - keep efficacy checks VID/PID-correlated.
7. Completed: extend native parser fuzz coverage for IAD/class-specific
   descriptors, non-contiguous and high-count interface numbers, long unknown
   descriptors, inflated lengths, and subclass/protocol predicates.
8. Completed: add deterministic native coverage for registry policy corruption
   and limits. The production load/store sanitizer now has native coverage for
   wrong type/short length fail-closed behavior, count clamping by value length
   and capacity, and unknown-mode normalization to whitelist.
9. Completed: add reconnect and transport-interruption coverage. A denied attach
   must not poison a later allowed attach after policy update, and a Raw Gadget
   producer drop during configuration descriptor fetch must fail closed without
   PnP exposure. True concurrent update/attach stress remains pending for a
   deterministic lab hook.
10. Validate descriptor snapshots with a WDK `/WX` build and lab run.
11. Add an opt-in hardware-backed efficacy lane through `usbip-host`.

## Validation checklist

- Static checks:
  - `python3 -m py_compile test/conftest.py test/test_connectivity.py test/test_attack_efficacy.py`
  - `bash -n test/linux/gadget_lib.sh test/linux/gadgets/teardown.sh`
  - `git diff --check`
- Lab checks:
  - `pytest -q test/test_connectivity.py --maxfail=1`
  - `pytest -q test/test_matrix.py --maxfail=1`
  - `pytest -q test/test_tierb_canaries.py --run-tierb-canaries --maxfail=1`
  - `pytest -q test --run-efficacy -ra --maxfail=1`

## Implementation defaults

- Keep destructive efficacy tests opt-in via `--run-efficacy`.
- Keep Tier B canaries opt-in via `--run-tierb-canaries`.
- Do not commit ignored `test/config.ini`.
- Commit and push validated changes to `master`.
