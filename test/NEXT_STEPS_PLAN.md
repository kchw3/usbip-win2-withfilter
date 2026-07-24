# USB/IP Filter Validation Next Steps

Last updated: 2026-07-24

## Current baseline

- Planning snapshot: `master` at `f6ea4dc7` (2026-07-24).
- Active Tier A backend: `dummy_hcd` with `[linux] udc_name = dummy_udc.0` and `busid = auto`.
- Do not use `usbip-vudc` for Tier A mass-storage or composite mass-storage rows; the lab kernel reproduced a `usbip_vudc::vep_dequeue` crash during teardown.
- Latest validation:
  - Connectivity: `13 passed, 1 skipped`.
  - Full Tier A matrix: `56 passed`.
  - Full suite: `72 passed, 9 skipped`.
  - Full suite with efficacy: `111 passed, 8 skipped`.
  - Tier B Raw Gadget canaries: `7 passed`.
  - Tier B Raw Gadget robustness: `7 passed`.
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
6. Completed: harden remaining oracles:
   - completed: rejection events now assert fail-closed reason and source
     context on the current deployed driver; the driver source event contract now
     puts reason/class/whitelist first so full class + whitelist assertions
     activate once that build is deployed.
   - completed: expanded network/vendor allow cases (`allow_network`,
     `allow_vendor`, `allow_network_vendor`) and aligned the RNDIS decision
     model with the production parser's network-class view.
   - efficacy checks remain VID/PID-correlated.
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
   PnP exposure.
10. Completed: add deterministic concurrent update/attach stress coverage. A
   bounded stress row races policy load/store readbacks against repeated attach
   attempts and asserts no worker hangs/errors or malformed attach results.
11. Completed: validate descriptor snapshots with a WDK `/WX` build and lab
   run. The WDK-built snapshot passed the full Tier A matrix, full efficacy
   suite, and descriptor TOCTOU security test.
12. Add an opt-in hardware-backed efficacy lane through `usbip-host`.

## Item 12 detailed plan: hardware-backed efficacy lane

### Goal and security rationale

The software lanes remain the primary regression gates: Tier A covers the normal
policy/device matrix, Tier B covers malformed and changing protocol responses,
and the efficacy suite proves software HID/storage/network payloads work when
their classes are permitted. Hardware is an opt-in compatibility and efficacy
lane, not a prerequisite for ordinary CI.

The remaining gap is independent evidence through a physical USB controller and
representative production hardware. The hardware lane must prove that:

1. physical HID, storage, and NIC devices enumerate and carry endpoint traffic
   through the WDK-built client when their classes are allowed;
2. the same devices are rejected before Windows PnP exposure when denied;
3. programmable HID/composite hardware can deliver a real effect when allowed
   but not when denied;
4. physical-controller behavior does not invalidate snapshotting, cleanup, or
   pre-enumeration enforcement; and
5. failures are attributed to the device, export path, transport, driver,
   filter decision, or payload oracle.

A normal keyboard is compatibility evidence, not an automated BadUSB efficacy
test. HID efficacy requires programmable hardware with an external trigger.
Likewise, NIC efficacy requires traffic through the VID/PID-correlated adapter,
not merely global adapter-name churn.

### Scope and non-goals

Minimum profiles:

- **Physical HID compatibility:** require a started VID/PID-correlated Keyboard
  child on allow and no matching PnP exposure on deny.
- **Physical mass-storage efficacy:** use a dedicated disposable device seeded
  with a unique per-run marker; require the exact marker on allow and no PnP
  exposure on deny.
- **Physical NIC efficacy:** use a dedicated adapter and isolated peer; require
  a VID/PID-correlated `Net` child plus a bounded network probe on allow and no
  PnP exposure on deny.
- **Programmable HID/composite efficacy:** use an external trigger to produce a
  unique marker, optionally alongside storage; require every advertised class.

Descriptor mutation over physical hardware is optional follow-up evidence and
does not replace the Tier B Raw Gadget TOCTOU gate. WHQL/HLK certification,
arbitrary consumer-device support, USB power attacks, and continuous hardware
CI are out of scope.

### Lab topology and prerequisites

```text
controller (pytest)
  | SSH                                  | WinRM
  v                                      v
Kali USB/IP server ---- isolated TCP/3240 ---- Windows client VM
  |
  +-- dedicated physical HID / flash / NIC
  +-- optional Pi gadget or Cynthion/Facedancer
```

Required safeguards:

- Kali must have root access, `usbip-host`, host-mode `usbipd -D`, stable
  physical busids, and permission to unbind/reprobe only selected interfaces.
- Windows must use the WDK-built snapshot and matching artifacts on an isolated,
  disposable VM with no identity collision.
- Storage must be expendable, unmounted, non-root, non-swap, and never formatted.
- NIC testing must not disrupt Kali's default route, SSH route, controller route,
  or Windows route; its cable must connect only to an isolated peer.
- Programmable profiles must use fixed lab hooks and pass the run token through
  environment variables, never embedded credentials.
- Every profile requires an explicit acknowledgement that a physical USB device
  will be temporarily unbound.

Record kernel/tool versions, artifact hashes, VID/PID, hashed serial, bus
topology, firmware where available, and peer configuration in redacted run
artifacts. Never commit serials, credentials, private addresses, or config.ini.

### Configuration model

Add physical identities to ignored lab configuration, not `devices.py`:

```ini
[hardware]
profiles = keyboard, storage, nic, programmable_hid
artifact_dir = artifacts/hardware
capture_traffic = false
deny_watch_seconds = 15

[hardware:nic]
kind = network
busid = 1-4
vid = 1234
pid = 0003
serial = LAB-NIC-01
allow_categories = network
oracles = network_peer
windows_ipv4 = 192.0.2.10
prefix_length = 24
peer_ipv4 = 192.0.2.20
peer_tcp_port = 9000
confirm_physical_unbind = I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE
```

Implement a `HardwareProfile` parser that normalizes VID/PID, validates unique
non-wildcard busids, serial rules, supported kinds/oracles, required
oracle-specific fields, bounded deny windows, and the acknowledgement. Support
composite profiles with multiple independent oracles. CLI profile selection and
artifact/capture overrides must not weaken configuration-enabled capture.

Configured hooks are trusted lab executables, but receive only fixed variables:
`USBIP_TEST_RUN_ID`, `USBIP_TEST_TOKEN`, `USBIP_TEST_BUSID`, `USBIP_TEST_VID`,
and `USBIP_TEST_PID`.

### Pytest entry point and collection behavior

Add a `hardware` marker and dedicated `--run-hardware` option. Hardware tests
must remain skipped unless explicitly enabled; `--run-efficacy` alone must not
run them. Add repeatable `--hardware-profile NAME` selection and an artifact
directory option. Missing configuration must produce an explicit skip.

Planned command:

```bash
pytest -q test/test_hardware_efficacy.py --run-hardware \
  --hardware-profile storage --hardware-artifact-dir artifacts/hardware \
  -ra --maxfail=1
```

### Safe physical-device lifecycle

Add `test/linux/hardware_device.sh` with explicit `preflight`, `export`,
`restore`, and `status` operations. Serialize all physical mutations with a
global lock under `/run/usbip-filter-hardware`. Preflight must be read-only and:

1. resolve exactly the configured sysfs busid and reject hubs;
2. verify busid, VID, PID, and serial;
3. record every interface and bound driver;
4. reject existing USB/IP exports and unsafe storage mounts;
5. reject NICs owning default, SSH, controller, or Windows routes; and
6. verify host-mode USB/IP prerequisites without mutation.

Export must rerun identity checks, persist state, unbind only recorded
interfaces, bind the exact busid, and verify the matching USB/IP listing.
Restore must be idempotent, reprobe recorded drivers, verify identity and
non-exported state, and print an exact recovery command if automatic restore
fails. It must never format, power-cycle, deauthorize, or blindly rebind an
unrecorded interface.

### Harness, Windows helpers, and oracles

Add dedicated hardware fixtures rather than reusing configfs teardown or
synthetic VID-wide cleanup. Provide a `HardwareExport` handle, hardware
preflight/export/prepare/trigger/status/restore methods, targeted PnP cleanup,
USB/IP port resolution, and optional bounded usbmon/TCP capture.

The deny path must set/read back policy, capture an event cursor, require a
structured rejection, watch the entire deny window for matching transient or
failed-start PnP nodes, require a fresh correlated rejection event, and prove
the profile effect did not occur.

The allow path must set/read back the exact allowed classes, attach, require the
matching parent and function child, then run the profile oracle:

- `keyboard_ready`: started Keyboard child;
- `hid_marker`: external trigger and unique marker;
- `storage_marker`: exact per-run storage token;
- `network_peer`: VID/PID-correlated Net child and bounded isolated TCP probe;
- composite: every declared channel independently.

Always retain a redacted JSON bundle containing run identity, artifact hashes,
policy readback, attach result, USB/IP listings, PnP/function-child state,
oracle results, and cleanup status. Captures are diagnostic only.

### Implementation sequence

1. **Profile/config gate:** add the profile parser, ignored config examples,
   marker/options, collection skips, and parser unit tests.
2. **Linux safety gate:** add the shell lifecycle helper and fake-sysfs tests for
   identity mismatch, unsafe mounts/routes, export failure, and idempotent restore.
3. **Fixture/cleanup gate:** add hardware fixtures, targeted Windows helpers,
   command-construction tests, and one benign attach/restore canary.
4. **Physical compatibility profiles:** implement one-at-a-time HID, storage,
   and NIC deny/allow rows with manual restoration confirmation.
5. **Programmable efficacy profile:** integrate prepare/trigger hooks and require
   run-token and composite channel oracles.
6. **Documentation/final validation:** record exact bench setup and results,
   keep secrets in ignored artifacts, and mark item 12 complete only after all
   acceptance criteria pass.

### Validation checklist

Static/unit checks:

```bash
python3 -m py_compile test/conftest.py test/hardware.py \
  test/test_hardware_profiles.py test/test_hardware_script.py \
  test/test_hardware_efficacy.py
bash -n test/linux/hardware_device.sh test/linux/gadget_lib.sh \
  test/linux/gadgets/teardown.sh
pytest -q test/test_hardware_profiles.py test/test_hardware_script.py \
  test/test_wdk_snapshot_contract.py
```

Regression without hardware must remain green with hardware rows skipped:

```bash
pytest -q test --run-efficacy -ra --maxfail=1
```

Run each configured hardware profile separately with `--run-hardware`, then
rerun connectivity, Tier A, Tier B, and software efficacy to confirm the
validated baseline is unchanged.

### Acceptance criteria

Item 12 is complete only when hardware tests are independently opt-in, skip
cleanly without lab configuration, preflight refuses unsafe states before
unbind, and every failure path restores Linux drivers, USB/IP state, Windows
PnP state, policy, markers, and temporary NIC configuration.

At least one physical HID, mass-storage, and NIC profile must pass deny and
allowed-functional paths through the WDK-built client. HID must include a
programmable run-token marker; storage must read the exact token without
formatting; NIC traffic must use the VID/PID-correlated adapter and isolated
peer. Denials must show no transient PnP exposure and a fresh correlated
rejection event. Results must include redacted artifacts and attributable
failure categories, while the existing non-hardware suite remains green.

## Remaining conditional follow-ups

These do not block item 12 unless hardware results show the current security
boundary is insufficient:

- compare software-gadget, physical-device, and programmable-hardware traces;
- extend immutable snapshots to BOS, string, and class-specific descriptors if
  required by the threat model; and
- capture deeper HID/TCP tracing if the endpoint-disabled regression returns.

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

- Keep destructive software efficacy tests opt-in via `--run-efficacy`.
- Keep Tier B canaries opt-in via `--run-tierb-canaries`.
- Keep hardware tests separately opt-in via `--run-hardware`.
- Never mutate physical hardware unless identity and safety preflight succeed
  and the explicit acknowledgement is present.
- Do not commit ignored `test/config.ini`, bench serials, credentials, private
  addresses, or packet captures.
- Commit and push validated changes to `master` only when explicitly requested.
