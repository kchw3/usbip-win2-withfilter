/*
 * Copyright (c) 2026 Kelvin Wu
 *
 * Device-type (USB class) filtering for the UDE client driver.
 *
 * The policy is a whitelist of USB class tuples. A remote device is allowed to attach
 * only if every class token it exposes matches some whitelist entry, where a token is
 * the device-descriptor class (when meaningful) plus the class of every interface in
 * every configuration. The check runs before UdecxUsbDevicePlugIn(), so a denied
 * device is never presented to Windows. The policy is read from the driver's registry
 * Parameters key and is configured via the SET_DEVICE_FILTER / GET_DEVICE_FILTER IOCTLs.
 */

#pragma once

#include <usbip/vhci.h>

#include <libdrv/codeseg.h>
#include <libdrv/wdf_cpp.h>

#include <wdm.h>

namespace usbip
{

struct device_ctx_ext;
struct usbip_usb_device;

} // namespace usbip


namespace usbip::device_filter
{

/*
 * Runtime representation of the whitelist policy (fixed-size, easy to read/store).
 */
struct policy
{
        vhci::filter_mode mode;
        ULONG count; // number of valid entries
        vhci::device_filter_entry entries[vhci::ioctl::MAX_DEVICE_FILTER_ENTRIES];
};

/*
 * Load the policy from the registry. Fail-closed: if the value is missing or unreadable,
 * the returned policy is an empty whitelist (every device is denied) so that a fresh,
 * unconfigured install does not silently allow arbitrary device types.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED void load(_Out_ policy &p);

/*
 * Persist the policy to the registry. Requires KEY_SET_VALUE access.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED NTSTATUS store(_In_ const policy &p);

/*
 * Decide whether the remote device may attach.
 *
 * Returns STATUS_SUCCESS if allowed. Returns USBIP_ERROR_DEVICE_FILTERED if the device
 * is blocked by the whitelist (or fails closed). May perform synchronous control
 * transfers on ext.sock to fetch the configuration descriptor(s).
 *
 * Must be called after OP_REP_IMPORT (udev is valid, ext.sock is connected) and before
 * the UDECXUSBDEVICE is created/plugged in.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED NTSTATUS check_device(_Inout_ device_ctx_ext &ext, _In_ const usbip_usb_device &udev);

} // namespace usbip::device_filter
