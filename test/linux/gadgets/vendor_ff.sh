#!/usr/bin/env bash
# Vendor-specific interface (class 0xFF) via the gadget zero source/sink function.
# Models DFU / RNDIS / custom BadUSB hiding behind 0xFF. The filter is class-blind
# here: it can only allow/deny the whole 0xFF class.
# Expected: blocked unless 'vendor' (0xFF) is whitelisted (default: denied).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03ed}" PRODUCT="${PRODUCT:-test-vendor-ff}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "vendor specific"
g_add_vendor 1
g_bind
echo "built vendor_ff gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
