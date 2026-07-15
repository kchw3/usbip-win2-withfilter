/*
 * Copyright (c) 2022-2026 Vadym Hrynchyshyn <vadimgrn@gmail.com>
 */

#pragma once

#include <libdrv/codeseg.h>

#include <usbip/ch9.h> // usb_device_speed

#include <usb.h>

namespace usbip
{

/*
 * Apply the compatibility transformations UdeCx must see for the imported
 * device speed. This used to run only after a remote descriptor response; the
 * descriptor snapshot path calls the same function before registering bytes
 * with UdeCx, preserving existing low/full-speed behaviour.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED void patch_configuration_for_udecx(
        _Inout_ USB_CONFIGURATION_DESCRIPTOR *configuration,
        _In_ usb_device_speed speed);

} // namespace usbip
