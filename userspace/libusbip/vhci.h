/*
 * Copyright (c) 2021-2026 Vadym Hrynchyshyn <vadimgrn@gmail.com>
 */

#pragma once

#include "dllspec.h"
#include "win_handle.h"
#include <usbspec.h>

#include <string>
#include <vector>
#include <optional>

/*
 * Strings encoding is UTF8. 
 */

namespace usbip
{

struct device_location
{
        std::string hostname;
        std::string service; // TCP/IP port number or symbolic name
        std::string busid;
};

struct persistent_device
{
        device_location location;
        std::string serial;
};

struct imported_device
{
        device_location location;
        int port{}; // hub port number, >= 1

        UINT32 devid{};
        USB_DEVICE_SPEED speed = UsbLowSpeed;

        UINT16 vendor{};
        UINT16 product{};

        std::string serial; // only filled if you set it in attach_args
};

enum class state { unplugged, connecting, connected, plugged, disconnected, unplugging };

/**
 * There can be multiple event sources for the same device,
 * each of them emits events with a unique source_id.
 */
struct device_state
{
        imported_device device;
        state state = state::unplugged;
        ULONG source_id;
};

/*
 * Device-type (USB class) filter policy mirrored from the driver ABI.
 * @see usbip::vhci::ioctl::device_filter
 */
enum class filter_mode {
        disabled,  // filtering off, every device is allowed
        whitelist, // only devices whose every class token matches an entry are allowed
};

enum filter_match_flags : unsigned char {
        filter_match_class    = 1,
        filter_match_subclass = 2,
        filter_match_protocol = 4,
};

struct device_filter_entry
{
        UINT8 bClass{};
        UINT8 bSubClass{};
        UINT8 bProtocol{};
        UINT8 match_flags{}; // bitmask of filter_match_flags

        bool operator==(const device_filter_entry &o) const // keep C++17-compatible (see libusbip_check)
        {
                return bClass == o.bClass && bSubClass == o.bSubClass &&
                       bProtocol == o.bProtocol && match_flags == o.match_flags;
        }
};

struct device_filter_policy
{
        filter_mode mode = filter_mode::whitelist;
        std::vector<device_filter_entry> entries;
};

/*
 * A user-facing device-type category (e.g. "Mass storage") that expands to one or more
 * whitelist entries. Shared by the GUI and CLI so they present the same choices.
 */
struct device_type_category
{
        std::string id;   // stable identifier, e.g. "mass_storage"
        std::string name; // display name, e.g. "Mass storage (USB drives)"
        std::vector<device_filter_entry> entries;
};

/**
 * @return the well-known device-type categories, in display order.
 */
USBIP_API const std::vector<device_type_category>& device_type_categories();

/**
 * @return max length of usb device serial number, constant
 */
USBIP_API int get_device_serial_maxlen() noexcept;;

/**
 * Serial number must contain no more than N alphanumeric ASCII characters.
 * @param serial number of usb device
 * @return call GetLastError() if false is returned
 * @see get_device_serial_maxlen
 */
USBIP_API bool validate_device_serial(_In_ const std::string &serial) noexcept;

/**
 * The function is thread-safe.
 * @return unique serial number for the device
 */
USBIP_API std::string generate_device_serial();

} // namespace usbip


namespace usbip::vhci
{

/**
 * Open driver's device interface
 * @param overlapped open the device for asynchronous I/O
 * @return handle, call GetLastError() if it is invalid
 */
USBIP_API Handle open(_In_ bool overlapped = false);

/**
 * @param dev handle of the driver device
 * @return imported devices if the result contains a value, otherwise call GetLastError()
 */
USBIP_API std::optional<std::vector<imported_device>> get_imported_devices(_In_ HANDLE dev);

/**
 * Read the device-type filter (whitelist) policy from the driver.
 * @param dev handle of the driver device
 * @return policy if the result contains a value, otherwise call GetLastError()
 */
USBIP_API std::optional<device_filter_policy> get_device_filter(_In_ HANDLE dev);

/**
 * Write the device-type filter (whitelist) policy to the driver. Requires administrator rights.
 * @param dev handle of the driver device
 * @param policy whitelist policy to store
 * @return call GetLastError() if false is returned
 */
USBIP_API bool set_device_filter(_In_ HANDLE dev, _In_ const device_filter_policy &policy);;


/**
 * @see generate_device_serial
 * @see validate_device_serial
 * @see get_device_serial_maxlen
 */
struct attach_args
{
        device_location location;
        std::string serial; // optional device serial number if you want to set/override it
        bool once; // do not run automatic attach attempts if an error is returned
};

/**
 * @param dev handle of the driver device
 * @param args arguments
 * @return hub port number, >= 1. Call GetLastError() if zero is returned. 
 */
USBIP_API int attach(_In_ HANDLE dev, _In_ const attach_args &args);

/**
 * @param dev handle of the driver device
 * @param location stop attach attempts to this device or stop all active attach attempts if NULL
 * @return number of canceled requests, call GetLastError() if -1 is returned
 */
USBIP_API int stop_attach_attempts(_In_ HANDLE dev, _In_opt_ const device_location *location);

enum { port_all_closeonly = -2, port_all };

/**
 * @param dev handle of the driver device
 * @param port hub port number starting from 1
 *        port_all - detach all ports
 *        port_all_closeonly - close tcp/ip connections for all ports,
 *              use to skip unnecessary steps on Windows reboot/shutdown
 * @return call GetLastError() if false is returned
 */
USBIP_API bool detach(_In_ HANDLE dev, _In_ int port);

/**
 * @return textual representation of the given constant
 */
USBIP_API const char* get_state_str(_In_ state state) noexcept;

/**
 * Read this number of bytes and pass them to get_device_state()
 * @return bytes to read from the device handle, constant
 */
USBIP_API DWORD get_device_state_size() noexcept;

/**
 * @param data that was read from the device handle
 * @param length data length, must be equal to get_device_state_size()
 * @return state constructed from passed data if the result contains a value, otherwise call GetLastError()
 */
USBIP_API std::optional<device_state> get_device_state(_In_ const void *data, _In_ DWORD length);

/**
 * @param dev handle of the driver device that must be opened for serialized I/O
 * @return state that was obtained by read operation on the given handle
           if the result contains a value, otherwise call GetLastError()
 */
USBIP_API std::optional<device_state> read_device_state(_In_ HANDLE dev);

} // namespace usbip::vhci
