#!/usr/bin/env bash
# Composite: mass storage (0x08) + hidden HID keyboard (0x03) in ONE config.
# The key composite-smuggling case.
# Expected: blocked unless BOTH 'mass_storage' AND 'hid' are whitelisted.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03ea}" PRODUCT="${PRODUCT:-test-composite-ms-hid}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "mass storage + hid"
g_add_mass_storage 1
# Optional live payload for the efficacy suite: PAYLOAD_TOKEN=<hex> seeds a marker.
[[ -n "${PAYLOAD_TOKEN:-}" ]] && g_seed_mass_storage_payload "${PAYLOAD_TOKEN}"
g_add_hid_keyboard 1
g_bind
echo "built composite_ms_hid gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
