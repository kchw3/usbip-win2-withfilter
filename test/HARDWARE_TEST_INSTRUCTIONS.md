# Physical hardware test instructions

The hardware lane is deliberately opt-in. It temporarily unbinds a selected
physical USB device on the Linux USB/IP server, exports it through
`usbip-host`, and attaches it to the disposable Windows test client.

Use only dedicated lab hardware and an isolated Windows VM. Never use a system
disk, mounted storage device, production NIC, or a device carrying the SSH or
controller route.

VMware virtual mouse/keyboard devices, USB hubs, root hubs, and the synthetic
`dummy_hcd` device are not physical hardware profiles. They may be used by the
software and Tier B test lanes, but they do not satisfy the hardware-lane
requirement and must not be configured under `[hardware:NAME]`.

## 1. Identify the hardware

Run these read-only commands on the Linux USB/IP server:

```bash
lsusb
lsusb -t

for d in /sys/bus/usb/devices/*; do
  [ -f "$d/idVendor" ] || continue
  printf '%s VID=%s PID=%s SERIAL=%s CLASS=%s\n' \
    "$(basename "$d")" \
    "$(cat "$d/idVendor")" \
    "$(cat "$d/idProduct")" \
    "$(cat "$d/serial" 2>/dev/null || true)" \
    "$(cat "$d/bDeviceClass" 2>/dev/null || true)"
done
```

Record the exact Linux sysfs `busid`, VID, PID, and preferably serial number.
The bus ID must identify one physical device, such as `1-4`; `auto` and
wildcards are not accepted.

Confirm that the selected device is not a hub. Storage must be unmounted and
must not be the root, swap, or system disk. Network devices must be isolated
and must not own default, SSH, controller, or Windows routes.

## 2. Configure `test/config.ini`

`test/config.ini` is ignored by Git. Start with one profile, preferably a
keyboard, and add more only after that profile passes.

```ini
[hardware]
profiles = keyboard
artifact_dir = artifacts/hardware
capture_traffic = false
deny_watch_seconds = 15

[hardware:keyboard]
kind = keyboard
busid = 1-2
vid = 1234
pid = 0001
serial = LAB-KBD-01
allow_categories = hid
oracles = keyboard_ready
confirm_physical_unbind = I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE
```

Available profile shapes are:

```ini
[hardware:storage]
kind = storage
busid = 1-3
vid = 1234
pid = 0002
serial = LAB-STORAGE-01
allow_categories = mass_storage
oracles = storage_marker
prepare_hook = /opt/usbip-filter-test/hardware/prepare_storage_marker.sh
confirm_physical_unbind = I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE

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

[hardware:programmable_hid]
kind = programmable_hid
busid = 1-5
vid = 1209
pid = 0001
serial = LAB-PROG-HID-01
allow_categories = hid
oracles = hid_marker
trigger_hook = /opt/usbip-filter-test/hardware/trigger_hid_marker.sh
confirm_physical_unbind = I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE
```

The parser requires a `prepare_hook` for `storage_marker` and a `trigger_hook`
for `hid_marker`. Composite profiles must explicitly list their independent
oracles.

Do not commit `config.ini`, credentials, serial numbers, private addresses, or
hardware artifacts.

## 3. Prepare hooks and the isolated peer

Hooks run on the Linux USB/IP server. They receive only these variables:

```text
USBIP_TEST_RUN_ID
USBIP_TEST_TOKEN
USBIP_TEST_BUSID
USBIP_TEST_VID
USBIP_TEST_PID
```

The storage preparation hook must create `ub_<USBIP_TEST_TOKEN>.txt` on the
dedicated device without formatting it. The programmable HID trigger must
cause the device to type the token and create:

```text
C:\Users\Public\ub_<USBIP_TEST_TOKEN>.txt
```

Install hooks with restrictive permissions:

```bash
chmod 700 /opt/usbip-filter-test/hardware/*.sh
```

For a NIC profile, configure the isolated Windows adapter with
`windows_ipv4`, and run a TCP listener on the isolated peer:

```bash
nc -l 9000
```

Never use a production network or a route shared with SSH.

## 4. Deploy and run read-only preflight

Deploy the Linux helpers from the controller:

```bash
rsync -az test/linux/ root@LINUX_SERVER:/opt/usbip-filter-test/linux/
```

Run preflight on the Linux server. Replace the identity values with the actual
device values:

```bash
sudo /opt/usbip-filter-test/linux/hardware_device.sh preflight \
  --busid 1-2 \
  --vid 1234 \
  --pid 0001 \
  --serial LAB-KBD-01 \
  --kind keyboard \
  --ack I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE
```

Preflight checks identity, hub status, active mounts and routes, existing
USB/IP exports, and host-mode USB/IP prerequisites. Do not continue if it
fails.

## 5. Validate configuration and run one profile

Run the local configuration tests:

```bash
/root/.venv/usbip-win2-withfilter/bin/pytest -q \
  test/test_hardware_profiles.py \
  test/test_hardware_fixture.py \
  test/test_hardware_script.py
```

Run each physical profile separately:

```bash
/root/.venv/usbip-win2-withfilter/bin/pytest -q \
  test/test_hardware_efficacy.py \
  --run-hardware \
  --hardware-profile keyboard \
  --hardware-artifact-dir artifacts/hardware \
  -ra --maxfail=1
```

Repeat with `storage`, `nic`, and `programmable_hid` after their individual
setup is verified.

The deny path requires no matching PnP exposure during the complete watch
window and a fresh correlated rejection event. The allow path requires the
profile-specific functional oracle, such as a started Keyboard child, exact
storage marker, or isolated NIC peer connection.

## 6. Restore after interruption

If a run is interrupted, restore the recorded device explicitly:

```bash
sudo /opt/usbip-filter-test/linux/hardware_device.sh restore \
  --busid 1-2 \
  --vid 1234 \
  --pid 0001 \
  --serial LAB-KBD-01 \
  --kind keyboard \
  --ack I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE
```

The restore operation unexports the device, reprobes only the drivers recorded
during preflight, and is safe to repeat. If it reports a recovery command,
execute that exact command only after confirming the device identity.

## Current lab limitations

The software and hardware lanes are independent. Hardware tests remain skipped
until `[hardware]` profiles are configured. Tier B Raw Gadget tests additionally
require the Linux `raw_gadget` module and `/dev/raw-gadget`; a missing device
prevents those robustness rows from starting.

The current Linux lab inventory contains only VMware virtual USB input devices,
USB hubs/root hubs, and the synthetic `dummy_hcd` bus. A physical HID,
mass-storage device, NIC, or programmable HID must be passed through to the VM
before the hardware profiles can be configured and run.
