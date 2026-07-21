# Device-type filter test harness

Validates the `usbip2_ude` device-type (USB class) filter against known USB
attacks, with emphasis on composite devices.

Because this is a **USB/IP client** filter, the "device" arrives over TCP from a
USB/IP server. So nearly every attack is simulated in software on the Linux
server side; no Flipper Zero / ESP32 is required to exercise the filter.

See [VALIDATION_PLAN.md](VALIDATION_PLAN.md) for the security properties,
known gaps, implementation phases, and completion criteria guiding this work.

## Layout

```
test/
  VALIDATION_PLAN.md     # security properties, work phases, and exit criteria
  devices.py            # Tier A device table + reference decision model
  conftest.py           # pytest fixtures (SSH to Linux, WinRM to Windows)
  config.example.ini    # copy to config.ini (gitignored) and fill in
  test_descriptors.py   # pure unit tests: Python builders + decision model
  test_parser_native.py # compiles + runs the PRODUCTION C++ parser (unit + fuzz)
  test_connectivity.py  # sanity-checks the config.ini wiring (SSH/WinRM/UDC/port)
  test_matrix.py        # integration: policy x device decision matrix (filter ON)
  test_robustness.py    # integration: attacks #9 (malformed) and #10 (TOCTOU)
  test_attack_efficacy.py # negative control: attacks really work (filter OFF)
  native/parser_fuzz.cpp # host driver that #includes device_filter_parser.h
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
modprobe libcomposite                 # configfs usb_gadget support
modprobe usbip-vudc                   # virtual UDC exported by usbipd --device
modprobe raw_gadget                   # for Tier B
modprobe dummy_hcd                    # software UDC for dummy_hcd / raw_gadget labs
apt install usbip                      # usbip + usbipd
# copy test/linux/ to the server (path goes in config.ini [linux] test_dir)
```

> **`libcomposite` is mandatory** for every Tier A/B test: it registers the
> `usb_gadget` configfs subsystem, i.e. it is what creates
> `/sys/kernel/config/usb_gadget`. The gadget builders `mkdir` *under* that
> directory; they cannot create the directory itself. To survive reboots,
> persist the modules: `echo -e 'libcomposite\nusbip-vudc\nraw_gadget\ndummy_hcd'
> | sudo tee /etc/modules-load.d/usbip-filter-test.conf`.

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
running anything that builds gadgets or attaches devices. Prefer the wrapper so
Linux module/service prompts happen before pytest starts capturing output:
```
python test/run_connectivity.py
```
It first checks the Linux USB gadget prerequisites, prints each status, prompts
before applying fixes, then runs `pytest test/test_connectivity.py -v`. Use
`python test/run_connectivity.py --yes` for non-interactive setup, or
`python test/run_connectivity.py -- --maxfail=1 -vv` to pass custom pytest args.

The lower-level command still works when you only want assertions:
```
pytest test/test_connectivity.py -v
```
This checks each leg in isolation (SSH to the Linux server, the UDC and
`test_dir` it expects, WinRM to the Windows client, `helpers.ps1` /
`usbip.exe` paths, and that the client can reach the USB/IP server's TCP
port) and fails with a message naming the specific `config.ini` key to fix.

When Linux USB gadget prerequisites are missing, the wrapper fix prints verbose
status such as `not loaded; loading...`, `load success`, or `load FAILED` for
`libcomposite`, `usbip-vudc`, `raw_gadget`, and `dummy_hcd`. It also checks the
configured USB/IP TCP port and starts `usbipd --device -D` for `usbip-vudc` or
host-mode `usbipd -D` for dummy_hcd / non-vudc labs. Direct pytest runs can also
auto-fix with `USBIP_TEST_AUTO_FIX=1`; set `USBIP_TEST_AUTO_FIX=0` to disable
auto-fix.

> It also asserts the server's `test_dir` is **byte-for-byte in sync** with
> this checkout's `test/linux/` (`test_linux_deploy_in_sync`). The harness runs
> gadget scripts and payloads from `test_dir`, not from your checkout, so a
> forgotten re-deploy means you debug code that isn't running. If this test
> fails, `git pull` here, re-`rsync` `test/linux/` to the server, and re-run.

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

## Troubleshooting

**`mkdir: cannot create directory '/sys/kernel/config/usb_gadget': Operation not
permitted`** (typically surfaced as a `RuntimeError` from `conftest.py` while a
gadget script runs)

This is *not* a permissions/sudo problem and not a test bug. The `usb_gadget`
directory is published by the **`libcomposite`** kernel module, which is not
loaded on the Linux server. It lives at the configfs root, where only registered
subsystems may create entries — so any `mkdir` there returns `EPERM` until the
module is present. Fix on the **server** (as root):
```
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
modprobe libcomposite        # creates /sys/kernel/config/usb_gadget
modprobe usbip-vudc          # creates the usbip-vudc.0 UDC
```
Verify: `test -d /sys/kernel/config/usb_gadget && ls /sys/class/udc/`.

The harness now preflights this automatically: before building any vudc gadget,
`LinuxServer.ensure_vudc_ready()` (conftest.py) checks for libcomposite, the
UDC, and a **device-mode** `usbipd`, attempts to set up each (mount configfs,
`modprobe`, `usbipd --device -D`), and otherwise raises an error naming the
exact command to run. `test_connectivity.py` also asserts these directly —
run it first when wiring a new lab.

**vudc gadget builds but the client never sees the device / `usbip list -r`
is empty** — `usbipd` is probably running in *host* mode. vudc gadgets are only
offered by `usbipd --device`. The harness swaps the daemon into device mode
automatically; to do it by hand: `pkill usbipd; usbipd --device -D`.

**A test sees a device as "present" that isn't actually attached (phantom PnP
node).** When a usbip2_ude session drops — the gadget is torn down server-side,
or the USB/IP connection resets — Windows can keep the device node around,
reported by `Get-PnpDevice -PresentOnly` as present and even `Status = OK`. The
presence oracle would then match that ghost and pass on a device that isn't
really there. Two defences: `Clear-UsbipState` (run by the `win` fixture around
every test) now *removes* lingering PnP nodes for the test VID, and
`Test-PnpPresent` requires the node be present **and** started (`Status = OK`).
`Clear-UsbipState` uses full `usbip.exe detach --all` rather than
`--all=closeonly`, because `closeonly` is intended for reboot/shutdown and only
drops TCP/IP connections; tests need `UdecxUsbDevicePlugOutAndDelete` so the
next attach gets a fresh root-hub child path. If you still see a stale node,
clear it by hand with `Remove-PnpDevice` when available, or with the portable
`pnputil` fallback: `pnputil /remove-device "HID\VID_16C0&PID_03E8\..."`.
Run pytest with `-s` to see live `[cleanup]` removal diagnostics. Current
helpers print `[cleanup] helpers.ps1 native-timeout revision: async-v2` before
detach; if that line is absent, the Windows VM is still running an older
`helpers.ps1` copy. If the last line is `[cleanup] detaching all USB/IP ports`,
the Windows-side `usbip.exe detach --all` call is stuck. `helpers.ps1` now runs
native USB/IP and PnP cleanup tools with explicit timeouts and async output
capture, reports the timeout, and continues to the stale-node cleanup instead of
letting pytest wait behind WinRM forever. The pytest harness also prints
`[cleanup] starting Windows cleanup` before entering WinRM and bounds the whole
cleanup call; tune `[windows] cleanup_timeout` in `test/config.ini` if your VM
needs more than the default 60 seconds.

**`usbip.exe attach` succeeds but no `VID_16C0` node becomes present in the
efficacy suite.** We diagnosed one concrete case where manual attach with
`usbip.exe filter --allow hid` enumerated `USB\VID_16C0&PID_03E8` and its HID
keyboard child, but `test_attack_efficacy.py` still failed because the suite
intentionally runs with the filter **disabled**. The WPP trace showed
`OP_REP_IMPORT`, descriptor fetches, whitelist snapshotting, `UdecxUsbDevicePlugIn`,
and `usbip.exe port` all succeeding in whitelist mode. In disabled mode, the
old driver path returned from `device_filter::check_device()` before descriptor
snapshotting, preserving the historical dynamic-descriptor path; in this lab
that left UdeCx without the immutable descriptors needed for reliable child PnP
enumeration. The driver fix is in `drivers/ude/device_filter.cpp`: disabled
mode now means "allow every class tuple" but still fetches, patches, and
registers the descriptor snapshot for UdeCx before plug-in. If this regresses,
compare `usbip.exe port`, `Get-PnpDevice` for `VID_16C0`, and the `usbip2_ude`
WPP lines around `device-type filter disabled`, `ALLOWED and snapshotted`, and
`dev ... plugged in`.

## What each layer asserts

- **test_matrix.py** — for every (policy, device) it checks three independent,
  correlated oracles agree with the reference model in `devices.py`:
  1. **attach result** — the intended policy is read back from the driver
     (`Set-FilterPolicy` returns the driver's own state and the harness raises on
     mismatch), so each row proves *which* policy it exercised. The attach is
     captured with its exit code, not just a boolean.
  2. **PnP** — on *allow*, the node must be present **and started** (`Status =
     OK`), sampled with a wait since enumeration is asynchronous. On *deny*, the
     harness watches the whole window for **any** matching node regardless of
     status (`Get-PnpExposure`): a failed-start or transient node is still
     exposure, and an absence assertion cannot stop at the first negative sample.
  3. **event log** — a cursor (`RecordId`) is taken immediately before attach and
     the rejection must be **newer** than it and match VID *and* PID *and* busid,
     so a stale event with the same PID cannot satisfy the oracle.
- **test_parser_native.py** — compiles `test/native/parser_fuzz.cpp`, which
  `#include`s the driver's own `drivers/ude/device_filter_parser.h`, and runs it.
  This tests the *production* parser (not a Python re-implementation) against
  malformed/inconsistent descriptors plus a 50k-iteration property fuzz that
  asserts the parser never accepts a device unless every interface is allowed and
  `bNumInterfaces` matches the distinct interfaces actually present. Skipped only
  when no C++17 host compiler is available.
- **test_robustness.py**
  - malformed descriptors must fail closed (deny + not enumerated),
  - TOCTOU must not let Windows observe a descriptor set different from the one
    the filter accepted. The benign snapshot must attach successfully; the Raw
    Gadget transcript must show the filter's two identical configuration fetches
    (header + full body), and **any** later changed response is a bypass. The
    driver now registers the accepted device/all-configuration snapshot with
    UdeCx, which should answer Windows internally without a later remote config
    request. As a secondary oracle the test polls the whole watch window and
    fails on the first new HID device seen: a transient interface must not evade
    a single late sample. (An absence assertion cannot stop after its first
    negative sample.)
- **test_attack_efficacy.py** (the negative control) — with the filter DISABLED,
  each device's malicious effect must actually fire:
  - BadUSB HID injects keystrokes that run code (a marker file is dropped),
  - mass storage exposes a payload the client can read back,
  - composite fires both channels,
  - rogue NIC presents a VID/PID-matched network adapter.
  This proves the simulations are genuine attacks. Combined with the matrix
  (same devices, filter ON -> blocked), it shows the filter is what stops them.
  These execute real payloads on the client: run only on a disposable, isolated VM.

  Function-child readiness matters for payload efficacy. A parent `VID/PID` node
  can appear before the function driver child is usable. The HID cases therefore
  wait for a present/OK `Keyboard` child before writing reports, and the NIC case
  waits for a present/OK `Net` child whose instance ID matches the test VID/PID.
  Mass storage already waits on the real payload file becoming readable from a
  removable volume, which is a stronger child/function readiness signal than PnP
  presence alone. The matrix tests deliberately keep their allow oracle at
  parent present+started, because they validate filter allow/deny rather than
  payload usability; deny paths still watch for any matching PnP exposure.

## Known design limits these tests encode (not bugs to "fix" in the test)

- The filter has a single **HID** bucket; a whitelisted HID device can still be a
  BadUSB keyboard. The matrix only asserts class-level allow/deny.
- Vendor-specific (`0xFF`) is allow/deny by class only; content is invisible.
- Malformed / inconsistent configuration descriptors now fail closed
  deterministically: the parser (`device_filter_parser.h`) rejects a
  zero-interface configuration, a `bNumInterfaces` that disagrees with the
  interface descriptors actually present, length/`wTotalLength` inconsistencies,
  and trailing partial descriptors. `test_parser_native.py` pins this behaviour.
- The TOCTOU case still probes genuinely uncertain end-to-end behaviour; a
  failure there is a real finding to file, not a flaky test.
- **HID keystroke *injection* does not fire through the `usbip2_ude` client**
  (`test_badusb_hid_keystrokes_execute` and `test_composite_both_channels_live`).
  Injection writes 8-byte reports to the gadget's `/dev/hidgN`, which only works
  while the gadget's HID interrupt-IN endpoint is enabled. When the Windows
  `usbip2_ude` client is the USB host — over **either** `usbip-vudc` **or**
  `dummy_hcd` + `usbip-host` — that endpoint never becomes writable: every write
  fails with `ESHUTDOWN`, even though the device reaches `state=configured`. The
  identical gadget works when a native Linux host drives it, so this is a
  property of how the client handles the HID interrupt-IN endpoint, not of the
  gadget or this harness.

  This is now **diagnosed, not blanket-suppressed.** Both tests run every
  precondition (attach, enumeration, keyboard-child startup, and for the composite
  test the storage channel) as hard assertions, then probe the endpoint with a
  non-blocking write (`hid_type.py --probe`) and `xfail` **only** when the probe
  confirms the `endpoint_disabled` (all-`ESHUTDOWN`) condition. Any other probe
  result (`live`, `no_host_polling`, `unknown`) means the endpoint should work,
  so injection is then *required* to succeed — a fixed client shows up as a normal
  pass, and a different regression is a real failure rather than a hidden xfail.
  The keyboard-child gate matters because the USB HID parent can be present with
  `HidUsb` before the `Keyboard`/`kbdhid` child is started; writes to `/dev/hidgN`
  can queue in that window without producing keystrokes. HID *enumeration*
  (allow/deny) remains fully covered by `test_matrix.py`. This is still a
  candidate driver-side finding to investigate in `usbip2_ude`.
