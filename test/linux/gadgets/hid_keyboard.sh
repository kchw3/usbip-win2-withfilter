#!/usr/bin/env bash
# Plain HID keyboard (class 0x03). BadUSB / keystroke-injection shape.
# Expected: blocked unless 'hid' is whitelisted.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03e8}" PRODUCT="${PRODUCT:-test-hid-keyboard}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "hid only"
g_add_hid_keyboard 1
g_bind
echo "built hid_keyboard gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
