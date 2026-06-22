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
  - returns a **benign** configuration descriptor (e.g. mass storage only) to the
    first `GET_DESCRIPTOR(CONFIGURATION)` request (the filter's in-kernel fetch),
  - returns a **malicious** descriptor (adds an HID/keyboard interface) to
    subsequent `GET_DESCRIPTOR(CONFIGURATION)` requests (Windows' enumeration).
  Expected (desired): the device is still safe. If Windows ends up enumerating an
  interface the filter never saw, that is a real filter bypass and must be filed.

> These scripts are skeletons: the descriptor builders are exact and reusable, but
> the raw_gadget event loop (ioctl numbers / event structs) must be validated
> against the running kernel's `include/uapi/linux/usb/raw_gadget.h`. See the
> in-kernel reference `tools/usb/raw-gadget` for a working C example.
