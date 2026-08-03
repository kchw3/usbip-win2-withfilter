#!/usr/bin/env bash
# Safe lifecycle for one physical USB device exported through usbip-host.
#
# The production defaults intentionally point at /sys and /run.  Tests may
# override the roots and command paths with environment variables; this keeps
# the safety checks deterministic without ever touching a real device.
set -euo pipefail

SYSFS_ROOT="${HARDWARE_SYSFS_ROOT:-/sys}"
STATE_ROOT="${HARDWARE_STATE_ROOT:-/run/usbip-filter-hardware}"
LOCK_ROOT="${HARDWARE_LOCK_ROOT:-${STATE_ROOT}}"
USBIP_BIN="${HARDWARE_USBIP_BIN:-usbip}"
MODPROBE_BIN="${HARDWARE_MODPROBE_BIN:-modprobe}"
USBIPD_BIN="${HARDWARE_USBIPD_BIN:-usbipd}"
MOUNTINFO_FILE="${HARDWARE_MOUNTINFO_FILE:-/proc/self/mountinfo}"
ROUTES_FILE="${HARDWARE_ROUTES_FILE:-/proc/net/route}"
PROTECTED_INTERFACES="${HARDWARE_PROTECTED_INTERFACES:-}"
ACK_TEXT="I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE"

usage() {
  echo "usage: $0 {preflight|export|restore|status} --busid BUSID --vid VID --pid PID [options]" >&2
  echo "  --serial SERIAL       require an exact USB serial (recommended)" >&2
  echo "  --kind KIND           keyboard|storage|network|programmable_hid|composite" >&2
  echo "  --ack ACK             required for export and restore" >&2
  exit 2
}

die() { echo "hardware_device: $*" >&2; return 1 2>/dev/null || exit 1; }
norm_hex() {
  local value="${1,,}"; value="${value#0x}"
  [[ "$value" =~ ^[0-9a-f]{1,4}$ ]] || die "invalid hexadecimal USB id: $1"
  printf '%04x' "$((16#$value))"
}
valid_busid() {
  [[ "$1" =~ ^[0-9]+-[0-9]+(\.[0-9]+)*$ ]] || die "invalid physical busid: $1"
}

ACTION=""; BUSID=""; VID=""; PID=""; SERIAL=""; KIND=""; ACK=""
while (($#)); do
  case "$1" in
    preflight|export|restore|status) [[ -z "$ACTION" ]] || usage; ACTION="$1"; shift ;;
    --busid) BUSID="${2:-}"; shift 2 ;;
    --vid) VID="${2:-}"; shift 2 ;;
    --pid) PID="${2:-}"; shift 2 ;;
    --serial) SERIAL="${2:-}"; shift 2 ;;
    --kind) KIND="${2:-}"; shift 2 ;;
    --ack) ACK="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$ACTION" && -n "$BUSID" && -n "$VID" && -n "$PID" ]] || usage
valid_busid "$BUSID"
VID="$(norm_hex "$VID")"; PID="$(norm_hex "$PID")"
[[ -z "$SERIAL" || "$SERIAL" != "*" ]] || die "serial must be exact"
[[ -z "$KIND" || "$KIND" =~ ^(keyboard|storage|network|programmable_hid|composite)$ ]] || die "unsupported device kind: $KIND"

DEVICE="${SYSFS_ROOT}/bus/usb/devices/${BUSID}"
STATE="${STATE_ROOT}/${BUSID}.state"
INTERFACES="${STATE_ROOT}/${BUSID}.interfaces"
LOCK="${LOCK_ROOT}/.lock"

require_ack() { [[ "$ACK" == "$ACK_TEXT" ]] || die "physical-device acknowledgement is required (--ack ${ACK_TEXT})"; }
read_attr() { [[ -r "$1" ]] || die "missing USB identity attribute: $1"; tr -d '\r\n' < "$1"; }

identity_check() {
  [[ -d "$DEVICE" ]] || die "USB busid not found: $BUSID"
  local actual_vid actual_pid actual_serial device_class
  actual_vid="$(read_attr "$DEVICE/idVendor")"; actual_pid="$(read_attr "$DEVICE/idProduct")"
  [[ "${actual_vid,,}" == "$VID" ]] || die "VID mismatch for $BUSID: expected $VID, found $actual_vid"
  [[ "${actual_pid,,}" == "$PID" ]] || die "PID mismatch for $BUSID: expected $PID, found $actual_pid"
  if [[ -n "$SERIAL" ]]; then
    actual_serial="$(read_attr "$DEVICE/serial")"
    [[ "$actual_serial" == "$SERIAL" ]] || die "serial mismatch for $BUSID"
  fi
  device_class="$(cat "$DEVICE/bDeviceClass" 2>/dev/null || true)"
  [[ "${device_class,,}" != "09" && "${device_class,,}" != "0x09" ]] || die "refusing USB hub busid $BUSID"
}

net_interfaces() {
  local intf net
  for intf in "$DEVICE":*/net/*; do
    [[ -e "$intf" ]] || continue
    net="$(basename "$intf")"; printf '%s\n' "$net"
  done
}

safety_check() {
  local iface source tail block
  if [[ "$KIND" == "storage" || "$KIND" == "composite" ]]; then
    for block in "$DEVICE":*/block/*; do
      [[ -e "$block" ]] || continue
      source="/dev/$(basename "$block")"
      while IFS= read -r tail; do
        [[ "$tail" == *" - "* ]] || continue
        [[ "${tail#* - }" == "$source "* || "${tail#* - }" == "$source" ]] &&
          die "storage device is mounted: $source"
      done < "$MOUNTINFO_FILE"
    done
  fi
  if [[ "$KIND" == "network" || "$KIND" == "composite" ]]; then
    while IFS= read -r iface; do
      [[ -n "$iface" ]] || continue
      case ",${PROTECTED_INTERFACES}," in *,"$iface",*) die "network interface $iface is protected";; esac
      while IFS= read -r tail; do
        [[ "$tail" == *"$iface"* ]] && die "network interface $iface has an active route"
      done < "$ROUTES_FILE"
    done < <(net_interfaces)
  fi
}

record_state() {
  mkdir -p "$STATE_ROOT" "$LOCK_ROOT"
  : > "$INTERFACES"
  local intf driver
  for intf in "$DEVICE":*; do
    [[ -d "$intf" ]] || continue
    [[ -L "$intf/driver" ]] || continue
    driver="$(basename "$(readlink -f "$intf/driver")")"
    printf '%s\t%s\n' "$(basename "$intf")" "$driver" >> "$INTERFACES"
  done
  {
    printf 'busid=%s\nvid=%s\npid=%s\nserial=%s\nkind=%s\n' "$BUSID" "$VID" "$PID" "$SERIAL" "$KIND"
    printf 'interfaces=%s\nexported=false\n' "$INTERFACES"
  } > "$STATE"
}

exported_check() {
  "$USBIP_BIN" bind --list 2>/dev/null | grep -Eq "(^|[[:space:]])${BUSID}([[:space:]]|$)"
}

preflight() {
  identity_check; safety_check
  command -v "$USBIP_BIN" >/dev/null || die "usbip command is unavailable"
  command -v "$MODPROBE_BIN" >/dev/null || die "modprobe command is unavailable"
  command -v "$USBIPD_BIN" >/dev/null || die "usbipd command is unavailable"
  if pgrep -x "$(basename "$USBIPD_BIN")" >/dev/null 2>&1 &&
     ps -C "$(basename "$USBIPD_BIN")" -o args= 2>/dev/null | grep -q -- '--device'; then
    die "usbipd is running in device mode; physical export requires host mode"
  fi
  [[ -e /sys/module/usbip_host || -e /sys/module/usbip-host || "$SYSFS_ROOT/module/usbip_host" == */module/usbip_host ]] ||
    "$MODPROBE_BIN" -n usbip_host >/dev/null 2>&1 || die "usbip-host prerequisite is unavailable"
  exported_check && die "USB/IP export already exists for $BUSID"
  record_state
  echo "preflight ok: busid=$BUSID vid=$VID pid=$PID"
}

with_lock() {
  mkdir -p "$LOCK_ROOT"
  exec 9>"$LOCK"
  flock -n 9 || die "another physical hardware operation is in progress"
  "$@"
}

do_export() {
  require_ack; preflight
  identity_check
  if ! "$MODPROBE_BIN" usbip_host 2>/dev/null && ! "$MODPROBE_BIN" usbip-host; then
    do_restore || true
    die "could not load usbip-host"
  fi
  if ! pgrep -x "$(basename "$USBIPD_BIN")" >/dev/null 2>&1; then
    "$USBIPD_BIN" -D || { do_restore || true; die "could not start host-mode usbipd"; }
  fi
  local intf driver
  while IFS=$'\t' read -r intf driver; do
    if ! echo "$intf" > "${SYSFS_ROOT}/bus/usb/drivers/${driver}/unbind"; then
      do_restore || true
      die "could not unbind interface $intf from $driver"
    fi
  done < "$INTERFACES"
  if ! "$USBIP_BIN" bind -b "$BUSID"; then
    do_restore || true
    die "usbip bind failed for $BUSID"
  fi
  if ! exported_check; then
    do_restore || true
    die "usbip bind succeeded but export was not listed"
  fi
  sed -i 's/^exported=.*/exported=true/' "$STATE"
  echo "export ok: busid=$BUSID"
}

do_restore() {
  require_ack
  if [[ ! -f "$STATE" ]]; then echo "restore: no saved state for $BUSID"; return 0; fi
  local intf driver failed=0
  "$USBIP_BIN" unbind -b "$BUSID" 2>/dev/null || true
  while IFS=$'\t' read -r intf driver; do
    if [[ ! -e "${SYSFS_ROOT}/bus/usb/drivers/${driver}/bind" ]]; then
      failed=1
      echo "recovery required: missing ${SYSFS_ROOT}/bus/usb/drivers/${driver}/bind" >&2
      continue
    fi
    echo "$intf" > "${SYSFS_ROOT}/bus/usb/drivers/${driver}/bind" ||
      { failed=1; echo "recovery required: echo $intf > ${SYSFS_ROOT}/bus/usb/drivers/${driver}/bind" >&2; }
  done < "${INTERFACES:-${STATE_ROOT}/${BUSID}.interfaces}"
  if exported_check; then failed=1; fi
  (( failed == 0 )) || die "restore incomplete for $BUSID"
  sed -i 's/^exported=.*/exported=false/' "$STATE"
  echo "restore ok: busid=$BUSID"
}

do_status() {
  identity_check
  if exported_check; then echo "exported: true"; else echo "exported: false"; fi
  [[ -f "$STATE" ]] && cat "$STATE"
}

case "$ACTION" in
  preflight) preflight ;;
  export) with_lock do_export ;;
  restore) with_lock do_restore ;;
  status) do_status ;;
esac
