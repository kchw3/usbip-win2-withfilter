# Tier B simulations: raw_gadget

These cases cannot be expressed with stock configfs functions, so they use the
Linux `raw_gadget` interface (`/dev/raw-gadget`, kernel module `raw_gadget`),
which lets a userspace program answer every USB control request with arbitrary
bytes. Bind it to `dummy_hcd` (all-software) or to `usbip-vudc`, then export the
UDC over USB/IP exactly like the Tier A gadgets.

Setup:

```bash
modprobe raw_gadget
modprobe dummy_hcd        # provides a software UDC named e.g. dummy_udc.0
# then run one of the profiles below as root
```

Profiles:

- `malformed_descriptors.py` — covers attack #9:
  - configuration descriptor whose `bNumInterfaces` disagrees with the actual
    number of interface descriptors,
  - a configuration with **zero** interface descriptors (probes the vacuous-pass
    risk flagged in the implementation review),
  - descriptors with bad `bLength` / truncated `wTotalLength`.
  Expected: the filter fails closed (deny) for every variant.

- `toctou.py` — covers attack #10 (the most important Tier B case):
  - returns **benign** configuration snapshots (e.g. mass storage only) to the
    expected local pre-export and filter `GET_DESCRIPTOR(CONFIGURATION)` requests
    (header and full body for each),
  - returns a **malicious** descriptor (adds an HID/keyboard interface) to later
    requests from Windows' enumeration.
  Expected (desired): the device is still safe. If Windows ends up enumerating an
  interface the filter never saw, that is a real filter bypass and must be filed.

Tier B integration tests are active security gates after the Raw Gadget canaries
validated the lab path. The event loop (`_raw_gadget.py`), the profile runner
that writes `status.json` / `transcript.jsonl` (`_runner.py`), and the harness
readiness + verified-export protocol (`conftest.py` `start_raw_gadget`) are in
place and unit-tested (`test/test_raw_gadget.py`). The ioctl numbers are
computed from the kernel `_IOC` encoding and pinned against
`include/uapi/linux/usb/raw_gadget.h`. See the in-kernel `tools/usb/raw-gadget`
reference when extending profiles.
