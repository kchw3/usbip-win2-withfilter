# Device-type filter test harness

Validates the `usbip2_ude` device-type (USB class) filter against known USB
attacks, with emphasis on composite devices.

Because this is a **USB/IP client** filter, the "device" arrives over TCP from a
USB/IP server. So nearly every attack is simulated in software on the Linux
server side; no Flipper Zero / ESP32 is required to exercise the filter.

## Layout

```
test/
  devices.py            # Tier A device table + reference decision model
  conftest.py           # pytest fixtures (SSH to Linux, WinRM to Windows)
  config.example.ini    # copy to config.ini (gitignored) and fill in
  test_descriptors.py   # pure unit tests (run anywhere, no lab)
  test_connectivity.py  # sanity-checks the config.ini wiring (SSH/WinRM/UDC/port)
  test_matrix.py        # integration: policy x device decision matrix (filter ON)
  test_robustness.py    # integration: attacks #9 (malformed) and #10 (TOCTOU)
  test_attack_efficacy.py # negative control: attacks really work (filter OFF)
  linux/
    gadget_lib.sh       # configfs/libcomposite helpers + usbip export + payload seed
    gadgets/*.sh        # Tier A device builders (hid, ms, composite, cdc, ...)
    payloads/           # live attack payloads (HID keystroke injection, ...)
    raw_gadget/         # Tier B: malformed descriptors + descriptor TOCTOU
  windows/helpers.ps1   # oracle helpers: attach, PnP presence, event log, payloads
```

## Prerequisites

Controller (your workstation):
```
pip install -r test/requirements.txt
```

Linux USB/IP server (a VM is fine):
```
modprobe libcomposite usbip-vudc      # or dummy_hcd for a "physical" gadget
modprobe raw_gadget dummy_hcd         # for Tier B
apt install usbip                      # usbip + usbipd
# copy test/linux/ to the server (path goes in config.ini [linux] test_dir)
```

Windows client (a VM with snapshots is recommended):
- install the test-signed `usbip2_ude` + `usbip2_filter` drivers and `usbip.exe`,
- enable WinRM for the harness,
- copy `test/windows/helpers.ps1` (path goes in config.ini [windows] helpers).

> The harness loads `helpers.ps1` by content (as a script block), so it works
> even when PowerShell's execution policy is `Restricted`; no
> `Set-ExecutionPolicy` change is required on the client.

> With `usbip-vudc`, the gadget is exported by `usbipd` running in **device
> mode** (`usbipd --device`) and there is no `usbip bind` step — the harness
> starts/swaps the daemon into the right mode automatically. The client attaches
> with `usbip attach -r <server> -b usbip-vudc.0`. (With `dummy_hcd` the gadget
> is a normal local device and the host-mode `usbip bind -b <busid>` path is
> used instead.)

## Running

Unit tests only (no lab needed):
```
pytest test/test_descriptors.py -v
```

After creating `test/config.ini`, sanity-check the lab wiring itself before
running anything that builds gadgets or attaches devices:
```
pytest test/test_connectivity.py -v
```
This checks each leg in isolation (SSH to the Linux server, the UDC and
`test_dir` it expects, WinRM to the Windows client, `helpers.ps1` /
`usbip.exe` paths, and that the client can reach the USB/IP server's TCP
port) and fails with a message naming the specific `config.ini` key to fix.

Full integration:
```
pytest test/ -v
```

The efficacy / negative-control suite (`test_attack_efficacy.py`) is **opt-in**
because it executes real payloads (keystroke injection, storage read) on the
client. It is skipped by default; enable it explicitly:
```
pytest test/ -v --run-efficacy
# or just that suite:
pytest test/test_attack_efficacy.py -v --run-efficacy
```

## What each layer asserts

- **test_matrix.py** — for every (policy, device) it checks three independent
  oracles agree with the reference model in `devices.py`:
  1. attach result, 2. PnP enumeration (deny => not present), 3. event log.
- **test_robustness.py**
  - malformed descriptors must fail closed (deny + not enumerated),
  - TOCTOU must not let Windows enumerate an HID interface the filter never saw
    (baseline-diff of present HID devices).
- **test_attack_efficacy.py** (the negative control) — with the filter DISABLED,
  each device's malicious effect must actually fire:
  - BadUSB HID injects keystrokes that run code (a marker file is dropped),
  - mass storage exposes a payload the client can read back,
  - composite fires both channels,
  - rogue NIC presents a new network adapter.
  This proves the simulations are genuine attacks. Combined with the matrix
  (same devices, filter ON -> blocked), it shows the filter is what stops them.
  These execute real payloads on the client: run only on a disposable, isolated VM.

## Known design limits these tests encode (not bugs to "fix" in the test)

- The filter has a single **HID** bucket; a whitelisted HID device can still be a
  BadUSB keyboard. The matrix only asserts class-level allow/deny.
- Vendor-specific (`0xFF`) is allow/deny by class only; content is invisible.
- The TOCTOU and zero-interface cases probe genuinely uncertain behaviour; a
  failure there is a real finding to file, not a flaky test.
