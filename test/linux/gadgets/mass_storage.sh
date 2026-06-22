#!/usr/bin/env bash
# Mass storage (class 0x08). Data exfiltration / malware-drop shape.
# Expected: blocked unless 'mass_storage' is whitelisted.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03e9}" PRODUCT="${PRODUCT:-test-mass-storage}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "mass storage only"
g_add_mass_storage 1
# Optional live payload for the efficacy suite: PAYLOAD_TOKEN=<hex> seeds a marker.
[[ -n "${PAYLOAD_TOKEN:-}" ]] && g_seed_mass_storage_payload "${PAYLOAD_TOKEN}"
g_bind
echo "built mass_storage gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
