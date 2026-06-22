#!/usr/bin/env bash
# RNDIS network adapter (advertised via misc 0xEF + vendor bits). PoisonTap-style
# rogue NIC that hides behind composite/misc glue. The device-descriptor class is
# 0xEF (skipped by the filter), so the decision rests on the interface classes.
# Expected: blocked unless the RNDIS interface classes are whitelisted (normally
# not -> denied by default).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03ec}" PRODUCT="${PRODUCT:-test-rndis-nic}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "rndis"
g_add_rndis 1
g_bind
echo "built rndis_nic gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
