# USB/IP device-filter validation plan

## Purpose

This plan guides development of the automated validation for the `usbip2_ude`
USB-class whitelist. It separates filter correctness from USB-device efficacy so
that a failure identifies the filter, the emulated device, the USB/IP transport,
or the test environment rather than conflating them.

The threat model is a malicious or malformed USB/IP device/server. The server can
control import metadata, descriptors, transfer responses, timing, reconnects, and
whether descriptor contents change between requests.

## Security properties

The validation must demonstrate that:

1. **Classification is correct.** The policy is evaluated against the device
   class and every interface in every advertised configuration.
2. **Enforcement precedes enumeration.** A denied device is never exposed as a
   Windows PnP node, including transient or failed-start nodes.
3. **Failures are closed.** Malformed, inconsistent, truncated, unavailable, or
   excessively large descriptor sets are denied.
4. **The evaluated descriptors are authoritative.** Windows cannot enumerate a
   descriptor set different from the one accepted by the filter.
5. **Allowed devices remain usable.** Representative permitted HID, storage,
   network, composite, and vendor-specific devices enumerate and transfer data.
6. **Results are attributable.** Every result distinguishes policy rejection
   from lab setup, device-emulator, USB/IP transport, driver, and oracle errors.

The filter is class-based. It does not distinguish a benign keyboard from a
BadUSB keyboard once HID is allowed. Payload-efficacy tests therefore demonstrate
that a test device is realistic; they do not extend the filter's security claim
beyond its configured class policy.

## Current assessment

### Useful foundations

- `configfs`/`libcomposite` with `usbip-vudc` is appropriate for well-formed
  software gadgets.
- The policy/device matrix, composite and multi-configuration cases, opt-in
  efficacy tests, connectivity checks, and deployment-freshness check are useful.
- Positive PnP waits, transient-HID polling, live `hidgN` resolution, and phantom
  node cleanup address real sources of test flakiness.

### Blocking reliability gaps

1. `linux/raw_gadget/_raw_gadget.py` is a scaffold: initialization, event parsing,
   and EP0 writes are unimplemented, and its ioctl constants are placeholders.
2. `start_raw_gadget()` does not prove that the process is alive, the UDC is
   ready, the device was exported, or the expected requests were served.
   Robustness tests can therefore pass because no device existed.
3. The TOCTOU profile changes the configuration after the first request, but the
   filter itself performs at least two configuration requests: header and full
   body. The current profile does not exercise filter-to-Windows TOCTOU.
4. HID `ESHUTDOWN` establishes that the gadget endpoint is disabled, but does not
   establish whether the cause is missing `SET_CONFIGURATION`, endpoint setup,
   class-driver loading, host polling, USB/IP transport, or `usbip2_ude`.
5. Broad, non-strict HID `xfail` markers can hide unrelated failures and do not
   make an unexpected success actionable.
6. PnP and event-log oracles are not fully time/run-correlated. Policy changes and
   deployed Windows artifacts are not read back or attested.
7. Python descriptor tests validate the builders/reference table, not the C++
   parser used by the driver.
8. The driver evaluates one descriptor snapshot but permits Windows to request
   descriptors again later, leaving a structural descriptor-TOCTOU risk.

## Work plan

### Phase 0: Establish a trustworthy baseline

- [x] Record the Windows driver binaries, `usbip.exe`, and helper-script paths +
      SHA256 in test output, with optional hash pins.
      (`helpers.ps1` `Get-WindowsArtifactManifest`;
      `test_connectivity.py::test_windows_artifacts_identified_and_helpers_in_sync`)
- [x] Run connectivity checks before integration tests and fail on stale Linux
      (`test_linux_deploy_in_sync`) or Windows (`helpers.ps1` hash) deployment.
- [x] Verify policy mutation by reading the policy back after every change.
      (`Get-FilterPolicyState`; `WindowsClient.set_policy` raises on mismatch)
- [x] Assert that cleanup completed and that no test VID PnP nodes remain.
      (`Clear-UsbipState` now verifies and throws; `WindowsClient.cleanup`)
- [x] Classify tests explicitly as unit, Tier A integration, Tier B adversarial,
      efficacy, or hardware-backed. (README + pytest markers/skips)
- [ ] Also record the Linux kernel / USB-IP tool versions in run output
      (server-side manifest, still to add).

**Exit criterion:** an infrastructure failure cannot be reported as a filter pass
or expected filter failure.

### Phase 1: Make Tier B self-proving

- [x] Until Raw Gadget is validated, skip Tier B tests with an explicit reason
      rather than treating attach failure as success. (`test_robustness.py`)
- [x] Replace the handwritten placeholder ioctl layer with encodings computed
      from the kernel `_IOC` macro and pinned to `raw_gadget.h`, plus a serve
      loop and profile runner. (`linux/raw_gadget/_raw_gadget.py`, `_runner.py`)
- [x] Add a readiness protocol: process alive, status reaches `run_ok`/`connect`,
      run_id matches, USB/IP export visible with expected busid + VID/PID.
      (`conftest.py` `start_raw_gadget` / `_await_raw_ready` / `_export_verified`)
- [x] Capture a per-run control-request transcript (`transcript.jsonl`) recording
      completed transfer lengths, and read it back in the harness.
- [x] Require the transcript to show the malformed config descriptor was actually
      served before accepting a deny. (`test_robustness.py` `_served_config`)
- [x] Correct TOCTOU sequencing so both filter requests (header and full body)
      receive one benign snapshot, while later requests receive a changed one;
      treat any post-snapshot change delivery as a bypass. (`toctou.py`,
      `test_robustness.py` `_served_malicious_after_snapshot`)
- [x] Give every run a unique run_id, per-run directory, logs, and PID-scoped
      teardown. (`RawGadgetRun`)
- [ ] Unit-test the encoding/packing/dispatch without a kernel. (done:
      `test/test_raw_gadget.py`)
- [ ] **Lab bring-up (blocking to un-skip):** confirm `raw_udc_driver` /
      `raw_udc_device` for the server kernel; run fault-injection canaries
      (kill producer, suppress export, wrong busid, omit crafted response) and
      confirm each goes RED; add a benign Raw Gadget canary that enumerates
      through the same UDC/USB-IP path; then remove the skip.

**Exit criterion:** deliberately breaking Raw Gadget startup or export fails the
test as infrastructure failure, while a valid adversarial exchange reaches the
Windows filter and produces an attributable decision.

### Phase 2: Diagnose the HID path

- [ ] Verify the selected `/dev/hidgN` node's major/minor against the intended
      bound gadget, not merely the first bound HID function.
- [ ] Use nonblocking report probes to distinguish:
      - immediate `ESHUTDOWN`: endpoint disabled or reset;
      - first success followed by `EAGAIN`: endpoint enabled but no completed host
        IN polling;
      - repeated success: endpoint and polling are live.
- [ ] Capture TCP/3240 and confirm EP0 `SET_CONFIGURATION 1`, its completion, and
      interrupt-IN `CMD_SUBMIT` traffic.
- [ ] Capture Linux gadget/UDC traces around `set_config`, `hidg_set_alt`,
      `usb_ep_enable`, reset, and disable.
- [ ] Capture Windows WPP traces proving the `usbip2_filter` select-configuration
      notification reaches `usbip2_ude` and that the interrupt endpoint starts.
- [ ] Verify `usbip2_filter` is attached to the expected emulated hub/device stack.
- [ ] Verify the HID child PnP node, service, problem code, and `hidusb`/`kbdhid`
      loading rather than checking only the VID/PID parent.
- [ ] Compare four paths:
      1. software gadget -> Linux USB/IP client;
      2. software gadget -> Windows `usbip2_ude`;
      3. physical HID -> Kali `usbip-host` -> Windows;
      4. hardware-backed programmable gadget -> Kali -> Windows.
- [x] Replace broad decorators with a precise conditional `pytest.xfail()` only
      after all preconditions pass and the known endpoint condition is observed.
      (`hid_type.py` `--probe` / `classify_endpoint_probe`, `test_attack_efficacy.py`
      `_require_injection_or_known_limitation`, unit-tested in `test_hid_probe.py`)
- [x] Add a Windows HID child-stack oracle (status/problem/service), not just the
      VID/PID parent. (`helpers.ps1` `Get-HidChildStatus`; `conftest.hid_child_status`)
- [ ] **Lab step:** capture TCP/3240, Linux gadget traces, and Windows WPP to
      confirm the missing transaction (SET_CONFIGURATION vs interrupt-IN vs
      filter notification). The non-blocking probe classifies the *symptom*; the
      captures localize the *cause*.

**Exit criterion:** the first missing or incorrect transaction is identified, and
“HID client limitation” is either supported by captures or replaced by a narrower
root cause.

### Phase 3: Harden integration oracles

- [x] For deny cases, watch throughout a bounded interval for any matching PnP
      node, regardless of `Status`. (`Get-PnpExposure`,
      `test_matrix._watch_for_pnp_exposure`)
- [x] Correlate rejection events using a pre-attach `RecordId` cursor plus VID,
      PID, and busid. (`Get-FilterEventCursor` / `Find-FilterRejectionAfter`;
      `test_matrix._wait_for_rejection`)
- [x] Distinguish filter rejection from network, import, port exhaustion, and
      emulator failures using the attach exit code and structured result.
      (`AttachResult`, `Invoke-Attach` JSON)
- [x] Keep efficacy assertions independent: the composite storage assertion is
      not hidden by an expected HID failure. (done in Phase 2)
- [x] Correlate HID/NIC child devices to the test VID/PID. (HID: Phase 2
      `Get-HidChildStatus`.)
- [ ] Assert the rejection reason/class and active whitelist text, not only that
      VID/PID/busid appear. (Driver currently logs VID/PID/iface/class; add once
      the message contract is pinned.)
- [ ] Expand filtered allow cases to network/vendor and the other supported
      policy categories in `devices.py`/`test_matrix.py`.
- [ ] Correlate the NIC efficacy check to the test VID/PID adapter rather than a
      global adapter-name baseline diff.

**Exit criterion:** stale events, unrelated device churn, failed cleanup, or wrong
policy/deployment cannot satisfy a test oracle.

### Phase 4: Test the parser directly

- [ ] Extract descriptor parsing/policy evaluation into logic testable without
      WDF, sockets, or live devices.
- [ ] Run the actual production parser against byte-level fixtures, not a separate
      Python interpretation.
- [ ] Add generated/property/fuzz cases for:
      - `bNumInterfaces` mismatch and zero-interface configurations;
      - duplicate interfaces and alternate settings;
      - invalid, zero, partial, or overflowing descriptor lengths;
      - short header/full responses and changing `wTotalLength`;
      - all configurations and configuration indexes;
      - IAD and class-specific descriptors;
      - excessive configuration counts/lengths and allocation pressure;
      - unknown classes, subclasses, protocols, and policy match flags.
- [ ] Add registry/policy corruption, limits, concurrent update/attach, reconnect,
      and transport-interruption tests.

**Exit criterion:** malformed-input coverage runs quickly and deterministically in
CI, while integration tests cover only kernel/transport/enforcement wiring.

### Phase 5: Prevent descriptor TOCTOU by design

- [ ] Evaluate serving Windows the exact descriptor snapshot accepted by the
      filter, for example through UDE descriptor initialization APIs.
- [ ] Alternatively intercept later descriptor requests and guarantee they return
      the validated cached bytes.
- [ ] Bind the snapshot to device identity/session and discard it on reconnect,
      reset, or re-import.
- [ ] Make a changed descriptor response fail closed and produce a distinct log.
- [ ] Use a deterministic userspace USB/IP responder for protocol-level mutation
      tests if Raw Gadget cannot precisely control the required request sequence.

**Exit criterion:** the malicious server cannot make Windows observe classes or
interfaces absent from the descriptor snapshot that passed the filter.

### Phase 6: Hardware-backed efficacy lane

- [ ] Keep `usbip-vudc` for ordinary Tier A coverage.
- [ ] Use representative physical HID/storage/NIC devices exported through
      Kali's `usbip-host` as compatibility controls.
- [ ] For programmable composite and dynamic behavior, evaluate a Pi gadget or
      Cynthion/Facedancer connected physically to Kali and exported over USB/IP.
- [ ] Keep this lane opt-in and isolated; do not make payload efficacy a prerequisite
      for parser/filter unit coverage.

**Exit criterion:** at least one real or hardware-backed example per important
class proves that allowed endpoint traffic works through the production client.

## Evidence retained per integration run

Each run should retain:

- pytest/JUnit result with run ID;
- local and remote source/artifact hashes;
- effective policy readback;
- USB/IP device listing and attach structured result;
- descriptor/request transcript;
- Windows PnP snapshots and correlated event entries;
- Kali `usbmon`/kernel log and TCP/3240 capture when diagnostics are enabled;
- Windows WPP trace when diagnostics are enabled;
- cleanup result.

Secrets from `config.ini`, WinRM credentials, or unrelated device identifiers must
not be copied into artifacts.

## Immediate implementation order

1. Prevent Tier B false-green results and add explicit readiness checks.
2. Correct the TOCTOU request-state model.
3. Narrow the HID `xfail` and add configuration/endpoint diagnostics.
4. Correlate PnP, events, policy, cleanup, and deployed artifacts.
5. Extract and fuzz the descriptor parser.
6. Implement descriptor snapshot consistency.
7. Add the hardware-backed compatibility lane.

## Definition of done

The validation is suitable as a security regression suite when:

- every test stimulus proves it reached the production driver;
- every allow/deny result is associated with the effective policy and exact
  descriptor snapshot;
- infrastructure and expected-security failures are distinct;
- malformed and changing descriptors cannot false-pass;
- denied devices never produce any Windows PnP exposure;
- allowed representative devices remain functional; and
- the suite is reproducible from a documented lab image/configuration.
