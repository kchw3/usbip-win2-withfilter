#!/usr/bin/env bash
# CDC ECM network adapter (class 0x02 / 0x0a). Rogue-NIC / traffic-hijack shape.
# Expected: blocked unless 'network' is whitelisted.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03eb}" PRODUCT="${PRODUCT:-test-cdc-nic}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "cdc ecm"
g_add_cdc_ecm 1
g_bind
echo "built cdc_nic gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
