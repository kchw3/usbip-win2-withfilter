#!/usr/bin/env bash
# Tear down any test gadget and unexport it.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${DIR}/gadget_lib.sh"
usbip_unexport "${UDC_NAME}" || true
g_teardown
echo "torn down gadget ${GADGET_NAME}"
