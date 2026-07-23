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
# NOTE: with usbip-vudc the gadget is exported by usbipd in *device* mode
# (usbipd --device); there is no 'usbip bind' step. With dummy_hcd the gadget
# appears as a normal local device and the usbip-host path ('usbip bind -b
# <busid>') applies instead. usbip_export() below handles both automatically.
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

# UDC to bind to. For vudc this is typically "usbip-vudc.0"; for dummy_hcd it
# is usually "dummy_udc.0". With dummy_hcd, the USB/IP busid is assigned only
# after bind and must be discovered dynamically from the enumerated host device.
UDC_NAME="${UDC_NAME:-usbip-vudc.0}"

# Backing image for mass storage functions.
MS_IMG="${MS_IMG:-/tmp/usbip-filter-test-disk.img}"

_require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "gadget_lib: must run as root (configfs)" >&2
    exit 1
  fi
}

# _require_gadget_subsystem: the usb_gadget configfs subsystem must exist before
# we can create a gadget under it. That directory (${GADGET_ROOT}) is published
# by the 'libcomposite' kernel module, NOT by mkdir -- it lives at the configfs
# root, where only registered subsystems may create entries. If libcomposite is
# not loaded, the g_init mkdir below fails with the cryptic
#   mkdir: cannot create directory '/sys/kernel/config/usb_gadget': Operation not permitted
# We try to set it up automatically (mount configfs + modprobe), then fail with
# an actionable message naming the exact fix if it still is not there.
_require_gadget_subsystem() {
  if [[ ! -d "${GADGET_ROOT}" ]]; then
    mountpoint -q /sys/kernel/config 2>/dev/null \
      || mount -t configfs none /sys/kernel/config 2>/dev/null || true
    modprobe libcomposite 2>/dev/null || true
  fi
  if [[ ! -d "${GADGET_ROOT}" ]]; then
    echo "gadget_lib: ${GADGET_ROOT} is absent -- the 'libcomposite' kernel" >&2
    echo "module is not loaded (it registers the usb_gadget configfs subsystem)." >&2
    echo "Without it the next mkdir fails with 'Operation not permitted'." >&2
    echo "Fix on this server (as root):" >&2
    echo "    modprobe libcomposite      # provides ${GADGET_ROOT}" >&2
    echo "    modprobe usbip-vudc        # provides the ${UDC_NAME} UDC" >&2
    exit 1
  fi
}

# g_init: create a fresh empty gadget skeleton (idempotent: tears down first).
g_init() {
  _require_root
  _require_gadget_subsystem
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

g_enable_rndis_ms_os_desc() {
  local cfg="$1"
  # Windows does not necessarily bind an in-box network driver to a plain
  # configfs RNDIS function. Microsoft OS 1.0 descriptors advertise the
  # interface as RNDIS/5162001 so Windows can match its RNDIS class driver
  # without a vendor INF.
  mkdir -p "${G}/os_desc"
  echo 1        > "${G}/os_desc/use"
  echo 0xcd     > "${G}/os_desc/b_vendor_code"
  echo MSFT100  > "${G}/os_desc/qw_sign"
  mkdir -p "${G}/functions/rndis.0/os_desc/interface.rndis"
  echo RNDIS    > "${G}/functions/rndis.0/os_desc/interface.rndis/compatible_id"
  echo 5162001  > "${G}/functions/rndis.0/os_desc/interface.rndis/sub_compatible_id"
  rm -f "${G}/os_desc/c.${cfg}"
  ln -s "${G}/configs/c.${cfg}" "${G}/os_desc/c.${cfg}"
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

_usb_id_norm() {
  local v="${1,,}"
  v="${v#0x}"
  printf '%04x' "$((16#${v}))"
}

usbip_find_busid() {
  local src_vid="${VID}"
  local src_pid="${PID}"
  [[ -f "${G}/idVendor" ]] && src_vid="$(<"${G}/idVendor")"
  [[ -f "${G}/idProduct" ]] && src_pid="$(<"${G}/idProduct")"
  local vid; vid="$(_usb_id_norm "${src_vid}")"
  local pid; pid="$(_usb_id_norm "${src_pid}")"
  local timeout="${1:-10}"
  local deadline=$((SECONDS + timeout))
  local dev idv idp

  while (( SECONDS <= deadline )); do
    for dev in /sys/bus/usb/devices/*; do
      [[ -f "${dev}/idVendor" && -f "${dev}/idProduct" ]] || continue
      [[ "$(basename "${dev}")" != *:* ]] || continue
      idv="$(<"${dev}/idVendor")"
      idp="$(<"${dev}/idProduct")"
      if [[ "${idv,,}" == "${vid}" && "${idp,,}" == "${pid}" ]]; then
        basename "${dev}"
        return 0
      fi
    done
    sleep 0.5
  done

  echo "usbip_find_busid: no USB device found for VID=${vid} PID=${pid}" >&2
  return 1
}

_usbip_unbind_host_drivers() {
  local busid="$1"
  local intf driver
  for intf in /sys/bus/usb/devices/"${busid}":*; do
    [[ -e "${intf}" ]] || continue
    [[ -L "${intf}/driver" ]] || continue
    driver="$(basename "$(readlink -f "${intf}/driver")")"
    echo "$(basename "${intf}")" > "/sys/bus/usb/drivers/${driver}/unbind" 2>/dev/null || true
  done
}

# _usbipd_ensure <host|device> : ensure usbipd is running in the requested mode.
# usbipd runs in exactly one mode at a time (host mode exports usbip-host stub
# devices; device mode '--device' exports vudc gadgets), so if it is up in the
# wrong mode we restart it.
_usbipd_ensure() {
  local want="$1"   # host | device
  local running_mode=""
  if pgrep -x usbipd >/dev/null; then
    if ps -C usbipd -o args= 2>/dev/null | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'; then
      running_mode="device"
    else
      running_mode="host"
    fi
  fi
  [[ "${running_mode}" == "${want}" ]] && return 0
  [[ -n "${running_mode}" ]] && { pkill -x usbipd 2>/dev/null || true; sleep 0.5; }
  if [[ "${want}" == "device" ]]; then
    usbipd --device -D
  else
    usbipd -D
  fi
  sleep 0.5
}

# usbip_export : make the gadget importable by USB/IP clients.
#
# vudc and the usbip-host stub use different mechanisms:
#   - vudc : the gadget is bound to the vudc UDC (g_bind) and offered by a
#            usbipd running in *device* mode. There is NO 'usbip bind' step, and
#            a host-mode daemon will not offer it.
#   - stub : (dummy_hcd / real hardware) a host-mode usbipd plus
#            'usbip bind -b <busid>' on the device's bus address.
# The client attaches the same way for both: usbip attach -r <server> -b <busid>.
usbip_export() {
  local busid="${1:-${UDC_NAME}}"
  case "${busid}" in
  *vudc*)
    _usbipd_ensure device
    local i
    for i in 1 2 3 4 5; do
      if usbip list -r 127.0.0.1 2>/dev/null | grep -q "${busid}"; then
        echo "${busid}"
        return 0
      fi
      sleep 1
    done
    echo "usbip_export: vudc device '${busid}' not offered by device-mode usbipd" >&2
    usbip list -r 127.0.0.1 >&2 || true
    return 1
    ;;
  *)
    if [[ -z "${busid}" || "${busid}" == "auto" || "${busid}" == dummy* ]]; then
      busid="$(usbip_find_busid)"
    fi
    modprobe usbip_host 2>/dev/null || modprobe usbip-host 2>/dev/null || true
    _usbipd_ensure host
    _usbip_unbind_host_drivers "${busid}"
    usbip bind -b "${busid}"
    echo "${busid}"
    ;;
  esac
}

usbip_unexport() {
  local busid="${1:-${UDC_NAME}}"
  case "${busid}" in
  *vudc*)
    # vudc has no stub 'unbind'; the gadget is detached by g_teardown (UDC clear).
    return 0
    ;;
  *)
    usbip unbind -b "${busid}" || true
    ;;
  esac
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
  # remove Microsoft OS descriptor config links and directory
  if [[ -d "${G}/os_desc" ]]; then
    find "${G}/os_desc" -maxdepth 1 -type l -exec rm -f {} +
    rmdir "${G}/os_desc" 2>/dev/null || true
  fi
  # remove functions
  for fn in "${G}"/functions/*/; do
    [[ -d "${fn}" ]] || continue
    if [[ -d "${fn}/os_desc" ]]; then
      find "${fn}/os_desc" -mindepth 1 -maxdepth 1 -type d -exec rmdir {} \; 2>/dev/null || true
      rmdir "${fn}/os_desc" 2>/dev/null || true
    fi
    rmdir "${fn}" 2>/dev/null || true
  done
  rmdir "${G}"/strings/* 2>/dev/null || true
  rmdir "${G}" 2>/dev/null || true
}
