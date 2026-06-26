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
running anything that builds gadgets or attaches devices:
```
pytest test/test_connectivity.py -v
```
This checks each leg in isolation (SSH to the Linux server, the UDC and
`test_dir` it expects, WinRM to the Windows client, `helpers.ps1` /
`usbip.exe` paths, and that the client can reach the USB/IP server's TCP
port) and fails with a message naming the specific `config.ini` key to fix.

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

## What each layer asserts

- **test_matrix.py** — for every (policy, device) it checks three independent
  oracles agree with the reference model in `devices.py`:
  1. attach result, 2. PnP enumeration (deny => not present), 3. event log.
- **test_robustness.py**
  - malformed descriptors must fail closed (deny + not enumerated),
  - TOCTOU must not let Windows enumerate an HID interface the filter never saw
    (baseline-diff of present HID devices). The check **polls** for the whole
    watch window and fails on the *first* new HID device seen, rather than
    sampling once after a fixed sleep: a bypass may enumerate the HID interface
    only transiently before the device tears it down, and a single late check
    could miss that and falsely pass. (Contrast the *allow*-path waits in
    `test_matrix.py` / `test_attack_efficacy.py`, which assert *presence* and so
    can stop at the first positive sample. An absence assertion cannot.)
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
