/*
 * Copyright (c) 2022-2026 Vadym Hrynchyshyn <vadimgrn@gmail.com>
 */

#include "descriptor_patch.h"

#include <libdrv/ch9.h>    // usb_endpoint_type
#include <libdrv/usbdsc.h> // libdrv::next

extern "C" {
#include <usbdlib.h>       // USBD_ParseDescriptors
}

namespace
{

/* Convert a low/full-speed interrupt interval in milliseconds to the
 * high-speed 2**(bInterval-1) microframe encoding expected by UdeCx. */
UCHAR to_high_speed_interval(UCHAR interval)
{
        NT_ASSERT(interval);
        constexpr UCHAR max_interval = 16;
        auto microframes = 8 * interval;
        for (UCHAR i = 1; i <= max_interval; ++i) {
                if ((1 << (i - 1)) >= microframes) {
                        return i;
                }
        }
        return max_interval;
}

} // namespace

/*
 * UdeCx needs endpoint parameters expressed for the imported device speed.
 * Keep this logic shared by both paths:
 *   1. filter enabled: patch the immutable cached configuration before it is
 *      registered with UdeCx;
 *   2. filter disabled: patch the live remote response in wsk_receive.cpp.
 *
 * USB 2.0 constraints (summarized): full/high-speed use different bulk packet
 * sizes and interrupt/isochronous bInterval units. Low/full-speed descriptors
 * therefore need the existing compatibility conversion below.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED void usbip::patch_configuration_for_udecx(
        _Inout_ USB_CONFIGURATION_DESCRIPTOR *configuration,
        _In_ usb_device_speed speed)
{
        PAGED_CODE();

        if (speed >= USB_SPEED_HIGH) {
                return;
        }

        for (auto cur = reinterpret_cast<USB_COMMON_DESCRIPTOR*>(configuration);
             bool(cur = USBD_ParseDescriptors(configuration, configuration->wTotalLength,
                                              cur, USB_ENDPOINT_DESCRIPTOR_TYPE));
             cur = libdrv::next(cur)) {

                // Filter-enabled snapshots were already validated by
                // evaluate_configuration. Keep the guard for filter-disabled
                // live responses too: never cast a short remote descriptor.
                if (cur->bLength < sizeof(USB_ENDPOINT_DESCRIPTOR)) {
                        continue;
                }
                auto &endpoint = *reinterpret_cast<USB_ENDPOINT_DESCRIPTOR*>(cur);
                switch (usb_endpoint_type(endpoint)) {
                case UsbdPipeTypeBulk:
                        endpoint.wMaxPacketSize = 512; // fixed value for high speed
                        break;
                case UsbdPipeTypeIsochronous:
                        // Full-speed bInterval is in 1ms frames; high-speed uses
                        // 125us microframes, hence +3 in the exponent.
                        NT_ASSERT(endpoint.bInterval >= 1 && endpoint.bInterval <= 16);
                        endpoint.bInterval = endpoint.bInterval + 3 < 16
                                                   ? endpoint.bInterval + 3
                                                   : 16;
                        break;
                case UsbdPipeTypeInterrupt:
                        endpoint.bInterval = to_high_speed_interval(endpoint.bInterval);
                        break;
                case UsbdPipeTypeControl:
                        break;
                }
        }
}
