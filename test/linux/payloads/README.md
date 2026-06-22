# Live attack payloads (efficacy / negative control)

These make the simulated devices behave as *real* attacks, so the efficacy suite
(`test/test_attack_efficacy.py`, filter DISABLED) can prove the simulation is
genuine — not just a device that enumerates. With the filter ON the device never
attaches and none of this fires.

- `hid_type.py` — BadUSB keystroke injection over USB/IP. After the client
  attaches the HID gadget, writes boot-keyboard reports to `/dev/hidgN`. The
  `--run-marker <token>` mode opens Run and drops
  `C:\Users\Public\ub_<token>.txt`, which the WinRM oracle then reads. That file
  appearing proves arbitrary keystrokes (hence code execution) reached the client.

- Mass-storage payload is seeded into the FAT image by `gadget_lib.sh`
  (`g_seed_mass_storage_payload`) when `PAYLOAD_TOKEN` is set: it writes
  `ub_<token>.txt` (+ a benign `autorun.inf`) onto the volume. The oracle reads it
  back from the removable drive, proving the storage exfil/drop channel is live.

- Rogue NIC efficacy is verified more lightly: with the filter off, a new network
  adapter appears on the client. Full PoisonTap-style routing (DHCP + default
  route hijack) is left as a documented manual step.

Safety: payloads only drop uniquely-named marker files in world-writable
locations on a disposable test VM. No exfiltration, no persistence, no harm.
Keep this lab isolated.
