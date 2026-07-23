#!/usr/bin/env bash
# RNDIS network adapter with Microsoft OS 1.0 descriptors.
#
# This is an efficacy-only rogue-NIC shape for Windows images that do not bind a
# Net child to the plain configfs CDC ECM/RNDIS gadgets. The OS descriptor
# advertises compatible_id=RNDIS and sub_compatible_id=5162001.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VID="${VID:-0x16c0}" PID="${PID:-0x03ef}" PRODUCT="${PRODUCT:-test-rndis-os-nic}"
source "${DIR}/gadget_lib.sh"

g_init
g_config 1 "rndis os"
g_add_rndis 1
g_enable_rndis_ms_os_desc 1
g_bind
echo "built rndis_os_nic gadget (VID=${VID} PID=${PID}) on ${UDC_NAME}"
