/*
 * Copyright (c) 2021-2026 Vadym Hrynchyshyn <vadimgrn@gmail.com>
 */

#pragma once

#include <cstddef>
#include <guiddef.h>

#ifdef _KERNEL_MODE
  #include <wdm.h>
  #include <minwindef.h>
#else
  #include <windows.h>
  #include <winioctl.h>
#endif

#include "ch9.h"
#include "consts.h"

/*
 * Strings encoding is UTF8. 
 */

namespace usbip
{

/**
 * Check that the string consists only of ASCII alphanumeric characters.
 * @param s null-ternimated ASCII string
 * @param maxlen max buffer size
 * @return < 0 if parameters/characters are invalid,
 *         otherwise the same as strnlen(s, maxlen)
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
constexpr SSIZE_T is_ascii_alnum(_In_opt_ const char *s, _In_ SSIZE_T maxlen);

_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
constexpr auto is_ascii(_In_ unsigned char ch) { return ch < 0x7F; }

} // namespace usbip


namespace usbip::vhci
{

DEFINE_GUID(GUID_DEVINTERFACE_USB_HOST_CONTROLLER,
        0xB4030C06, 0xDC5F, 0x4FCC, 0x87, 0xEB, 0xE5, 0x51, 0x5A, 0x09, 0x35, 0xC0);

struct base
{
        ULONG size; // IN, self size
};

struct imported_device_location
{
        int port; // OUT, >= 1 or zero if an error

        char busid[BUS_ID_SIZE];
        char service[32]; // NI_MAXSERV
        char host[1025];  // NI_MAXHOST in ws2def.h
};
static_assert(!offsetof(imported_device_location, port)); // must be the first member

struct imported_device_properties
{
        UINT32 devid;
//      static_assert(sizeof(devid) == sizeof(usbip_header_basic::devid));

        usb_device_speed speed;
        static_assert(sizeof(speed) == sizeof(int));

        UINT16 vendor;
        UINT16 product;

        char serial[SERIAL_BUFSZ];
        UCHAR iserial; // USB_DEVICE_DESCRIPTOR.iSerialNumber
};

struct imported_device : imported_device_location, imported_device_properties {};

enum class state { unplugged, connecting, connected, plugged, disconnected, unplugging };

/*
 * Device-type filter (whitelist) policy.
 *
 * The policy is a list of allowed USB class "tuples". A device is allowed to attach
 * only if every class token it exposes is matched by some entry in the list, where a
 * token is the device-descriptor class (when meaningful) and the class of every
 * interface in every configuration. @see usbip::vhci::ioctl::device_filter
 */
enum class filter_mode : UINT8 {
        disabled, // filtering is off, every device is allowed
        whitelist, // only devices whose every class token matches an entry are allowed
};

enum filter_match_flags : UINT8 {
        FILTER_MATCH_CLASS    = 1, // bClass is significant
        FILTER_MATCH_SUBCLASS = 2, // bSubClass is significant
        FILTER_MATCH_PROTOCOL = 4, // bProtocol is significant
};

/*
 * A single whitelist entry. Only the fields flagged in match_flags are compared;
 * e.g. {bClass = 0x03, match_flags = FILTER_MATCH_CLASS} allows the whole HID class.
 */
struct device_filter_entry
{
        UINT8 bClass;
        UINT8 bSubClass;
        UINT8 bProtocol;
        UINT8 match_flags; // bitmask of filter_match_flags
};

/*
 * There can be multiple event sources for one device,
 * each of them emits events with a unique source_id.
 */
struct device_state : base, imported_device
{
        state state;
        ULONG source_id;
};

} // namespace usbip::vhci


namespace usbip::vhci::ioctl
{

enum class function { // 12 bit
        plugin_hardware = 0x800, // values of less than 0x800 are reserved for Microsoft
        plugout_hardware, 
        get_imported_devices,
        set_persistent,
        get_persistent,
                stop_attach_attempts,
        plugin_hardware_once,
        plugout_hardware_and_reattach,
        set_device_filter,
        get_device_filter,
};;

constexpr auto make(function id)
{
        return CTL_CODE(FILE_DEVICE_UNKNOWN, static_cast<int>(id), METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);
}

enum {
        PLUGIN_HARDWARE = make(function::plugin_hardware),
        PLUGOUT_HARDWARE = make(function::plugout_hardware),
        GET_IMPORTED_DEVICES = make(function::get_imported_devices),
        SET_PERSISTENT = make(function::set_persistent),
        GET_PERSISTENT = make(function::get_persistent),
        STOP_ATTACH_ATTEMPTS = make(function::stop_attach_attempts),
                PLUGIN_HARDWARE_ONCE = make(function::plugin_hardware_once),
        PLUGOUT_HARDWARE_AND_REATTACH = make(function::plugout_hardware_and_reattach), // for internal use only
        SET_DEVICE_FILTER = make(function::set_device_filter),
        GET_DEVICE_FILTER = make(function::get_device_filter),
};

enum { MAX_DEVICE_FILTER_ENTRIES = 64 };;

struct plugin_hardware : base, imported_device_location
{
        char serial[SERIAL_BUFSZ];

        // OUT, UTF-8. Empty unless the attach was denied by the device-type filter, in which
        // case it holds a human-readable reason (offending class, the reason, and the
        // whitelist) so the GUI can show it; the kernel sets the returned byte count to
        // include it only on that path. @see usbip::device_filter
        char filter_reason[256];
};

struct stop_attach_attempts : base, imported_device_location
{
        int count; // OUT, number of canceled requests
};

enum { PORT_ALL_CLOSEONLY = -2, PORT_ALL };

struct plugout_hardware : base
{
        int port;
};

struct get_imported_devices : base
{
        imported_device devices[ANYSIZE_ARRAY];
};

constexpr auto get_imported_devices_size(_In_ ULONG n)
{
        return offsetof(get_imported_devices, devices) + n*sizeof(*get_imported_devices::devices);
}

/*
 * SET_DEVICE_FILTER (input) / GET_DEVICE_FILTER (output).
 *
 * Whitelist policy used by the driver to decide whether a device may be attached.
 * @see SET_DEVICE_FILTER, GET_DEVICE_FILTER
 */
struct device_filter : base
{
        filter_mode mode;
        UINT8 reserved[3];
        ULONG count; // number of valid entries, <= MAX_DEVICE_FILTER_ENTRIES
        device_filter_entry entries[ANYSIZE_ARRAY];
};

constexpr auto device_filter_size(_In_ ULONG n)
{
        return offsetof(device_filter, entries) + n*sizeof(*device_filter::entries);
}

} // namespace usbip::vhci::ioctl


/*
 * UTF-8 is designed so that all ASCII characters (0–127)
 * are represented by a single byte with the high bit set to 0.
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
constexpr SSIZE_T usbip::is_ascii_alnum(_In_opt_ const char *s, _In_ SSIZE_T maxlen)
{
        if (!(s && maxlen >= 0)) {
                return -1;
        }

        for (SSIZE_T i = 0; i < maxlen; ++i) {

                unsigned char c = s[i];
                if (!c) {
                        return i;
                }

                auto alnum = (c <= 'z' && c >= 'a') ||
                             (c <= 'Z' && c >= 'A') ||
                             (c <= '9' && c >= '0');

                if (!alnum) {
                        return -1;
                }
        }

        return maxlen;
}

static_assert(usbip::is_ascii_alnum(nullptr, 1) < 0);
static_assert(usbip::is_ascii_alnum("", -1) < 0);
static_assert(usbip::is_ascii_alnum("", 0) == 0);
static_assert(usbip::is_ascii_alnum("", 1) == 0);
static_assert(usbip::is_ascii_alnum("1", 2) == 1);
static_assert(usbip::is_ascii_alnum("1@", 3) < 0);
static_assert(usbip::is_ascii_alnum("1", 1) == 1);
static_assert(usbip::is_ascii_alnum("1\0W", 4) == 1);
