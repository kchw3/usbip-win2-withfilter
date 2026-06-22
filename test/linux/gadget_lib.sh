#!/usr/bin/env bash
#
# gadget_lib.sh - helpers to build Linux USB gadgets (configfs / libcomposite)
# and export them over USB/IP, for testing the usbip2_ude device-type filter.
#
# These are Tier A simulations (well-formed, real devices). They cover the
# functional / composite test cases. The nastier descriptor-level cases
# (malformed descriptors, descriptor TOCTOU, per-request lies) live under
# raw_gadget/ (Tier B) and cannot be expressed with stock configfs functions.
#
# Requires (load on the server):
#   modprobe libcomposite
#   modprobe usbip-vudc            # virtual UDC -> export over IP without hardware
#   # OR for a "physically present" gadget that 'usbip list -l' shows:
#   modprobe dummy_hcd
#
# NOTE (open item): the exact usbip bind/list command for usbip-vudc must be
# verified on the target kernel. With dummy_hcd the gadget appears as a normal
# local device and the standard 'usbip list -l' / 'usbip bind -b <busid>' work.
#
# Usage: source this file, then call g_* functions. See gadgets/*.sh.

set -euo pipefail

GADGET_ROOT="${GADGET_ROOT:-/sys/kernel/config/usb_gadget}"
GADGET_NAME="${GADGET_NAME:-usbiptest}"
G="${GADGET_ROOT}/${GADGET_NAME}"

# Default identity. Override before g_init if you want a distinct VID/PID per case
# so the Windows-side oracle can match on InstanceId (VID_xxxx&PID_xxxx).
VID="${VID:-0x1d6b}"   # Linux Foundation
PID="${PID:-0x0104}"   # Multifunction Composite Gadget
PRODUCT="${PRODUCT:-usbip-filter-test}"
MANUF="${MANUF:-usbip-test}"
SERIAL="${SERIAL:-0001}"

# UDC to bind to. For vudc this is typically "usbip-vudc.0".
UDC_NAME="${UDC_NAME:-usbip-vudc.0}"

# Backing image for mass storage functions.
MS_IMG="${MS_IMG:-/tmp/usbip-filter-test-disk.img}"

_require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "gadget_lib: must run as root (configfs)" >&2
    exit 1
  fi
}

# g_init: create a fresh empty gadget skeleton (idempotent: tears down first).
g_init() {
  _require_root
  g_teardown || true

  mkdir -p "${G}"
  echo "${VID}" > "${G}/idVendor"
  echo "${PID}" > "${G}/idProduct"
  echo 0x0200   > "${G}/bcdUSB"      # USB 2.0

  mkdir -p "${G}/strings/0x409"
  echo "${MANUF}"   > "${G}/strings/0x409/manufacturer"
  echo "${PRODUCT}" > "${G}/strings/0x409/product"
  echo "${SERIAL}"  > "${G}/strings/0x409/serialnumber"
}

# g_config <n> [label] : create configuration c.<n>.
g_config() {
  local n="$1"; local label="${2:-config ${1}}"
  mkdir -p "${G}/configs/c.${n}/strings/0x409"
  echo "${label}" > "${G}/configs/c.${n}/strings/0x409/configuration"
  echo 250 > "${G}/configs/c.${n}/MaxPower"
}

# --- function builders -------------------------------------------------------

# g_add_mass_storage <cfg> : USB Mass Storage (class 0x08).
g_add_mass_storage() {
  local cfg="$1"
  if [[ ! -f "${MS_IMG}" ]]; then
    dd if=/dev/zero of="${MS_IMG}" bs=1M count=16 status=none
    mkfs.vfat "${MS_IMG}" >/dev/null 2>&1 || true
  fi
  mkdir -p "${G}/functions/mass_storage.0"
  echo "${MS_IMG}" > "${G}/functions/mass_storage.0/lun.0/file"
  ln -sf "${G}/functions/mass_storage.0" "${G}/configs/c.${cfg}/"
}

# g_seed_mass_storage_payload <token> : write a marker file (+ benign autorun.inf)
# onto the FAT image so the Windows oracle can read it back from the removable
# drive, proving the storage exfil/drop channel is live. Call BEFORE g_bind, after
# g_add_mass_storage. Requires the image to be FAT (g_add_mass_storage mkfs's it).
g_seed_mass_storage_payload() {
  local token="$1"
  local mnt; mnt="$(mktemp -d)"
  mount -o loop "${MS_IMG}" "${mnt}"
  printf '%s' "${token}" > "${mnt}/ub_${token}.txt"
  printf '[autorun]\r\nlabel=USBIP-TEST\r\n' > "${mnt}/autorun.inf"
  sync
  umount "${mnt}"
  rmdir "${mnt}"
}

# g_add_hid_keyboard <cfg> : HID boot keyboard (class 0x03). This is the BadUSB
# shape: from the filter's point of view it is indistinguishable from a benign
# keyboard (the filter does not read the HID report descriptor).
g_add_hid_keyboard() {
  local cfg="$1"
  mkdir -p "${G}/functions/hid.0"
  echo 1 > "${G}/functions/hid.0/protocol"     # 1 = keyboard
  echo 1 > "${G}/functions/hid.0/subclass"     # 1 = boot interface
  echo 8 > "${G}/functions/hid.0/report_length"
  # Standard boot-keyboard report descriptor.
  printf '\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0' \
    > "${G}/functions/hid.0/report_desc"
  ln -sf "${G}/functions/hid.0" "${G}/configs/c.${cfg}/"
}

# g_add_cdc_ecm <cfg> : CDC ECM network adapter (class 0x02 / 0x0a). Rogue-NIC shape.
g_add_cdc_ecm() {
  local cfg="$1"
  mkdir -p "${G}/functions/ecm.0"
  ln -sf "${G}/functions/ecm.0" "${G}/configs/c.${cfg}/"
}

# g_add_rndis <cfg> : RNDIS network adapter (advertised via misc/0xEF + vendor bits).
# Models the PoisonTap-style rogue NIC that hides behind composite/misc glue.
g_add_rndis() {
  local cfg="$1"
  mkdir -p "${G}/functions/rndis.0"
  ln -sf "${G}/functions/rndis.0" "${G}/configs/c.${cfg}/"
}

# g_add_vendor <cfg> : vendor-specific interface (class 0xFF) via the gadget
# zero source/sink function. Models DFU / RNDIS / custom BadUSB hiding behind 0xFF.
g_add_vendor() {
  local cfg="$1"
  mkdir -p "${G}/functions/SourceSink.0"
  ln -sf "${G}/functions/SourceSink.0" "${G}/configs/c.${cfg}/"
}

# --- bind / export / teardown ------------------------------------------------

# g_bind : attach the gadget to the UDC (makes it live).
g_bind() {
  echo "${UDC_NAME}" > "${G}/UDC"
}

# usbip_export : bind the busid for export. See NOTE at top re: vudc vs dummy_hcd.
usbip_export() {
  local busid="${1:-${UDC_NAME}}"
  pgrep -x usbipd >/dev/null || usbipd -D
  usbip bind -b "${busid}"
}

usbip_unexport() {
  local busid="${1:-${UDC_NAME}}"
  usbip unbind -b "${busid}" || true
}

# g_teardown : fully remove the gadget (safe to call when nothing exists).
g_teardown() {
  [[ -d "${G}" ]] || return 0
  # unbind UDC
  if [[ -e "${G}/UDC" ]]; then echo "" > "${G}/UDC" 2>/dev/null || true; fi
  # remove function symlinks from every config, then the configs
  for cfg in "${G}"/configs/*/; do
    [[ -d "${cfg}" ]] || continue
    find "${cfg}" -maxdepth 1 -type l -exec rm -f {} +
    rmdir "${cfg}"/strings/* 2>/dev/null || true
    rmdir "${cfg}" 2>/dev/null || true
  done
  # remove functions
  for fn in "${G}"/functions/*/; do
    [[ -d "${fn}" ]] || continue
    rmdir "${fn}" 2>/dev/null || true
  done
  rmdir "${G}"/strings/* 2>/dev/null || true
  rmdir "${G}" 2>/dev/null || true
}
