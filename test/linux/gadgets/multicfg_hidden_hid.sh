#!/usr/bin/env bash
# Multi-configuration device that hides an HID interface in a NON-default config.
#   config 1 (default): mass storage (0x08)
#   config 2          : HID keyboard (0x03)
# The filter must evaluate EVERY configuration, so this should be denied unless
# both 'mass_storage' and 'hid' are whitelisted, even though config 1 alone looks
# benign. This exercises the "class hidden in non-default config" attack.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03ee}" PRODUCT="${PRODUCT:-test-multicfg-hidden-hid}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "mass storage (default)"
g_add_mass_storage 1
g_config 2 "hidden hid"
g_add_hid_keyboard 2
g_bind
echo "built multicfg_hidden_hid gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
echo "NOTE: confirm bNumConfigurations==2 is reported; the filter should walk both."
