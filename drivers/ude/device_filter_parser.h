/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 usbip-win2-withfilter contributors
 *
 * Side-effect-free USB configuration-descriptor parser for the device-type
 * filter. This header intentionally avoids OS and C++ standard-library headers:
 * the kernel driver and host-side unit/fuzz tests compile the exact same code
 * without pulling desktop STL headers into a WDK build.
 */

#pragma once

namespace usbip::device_filter
{

using parser_size_t = decltype(sizeof(0));
using parser_uint8_t = unsigned char;

/* Minimal view type instead of std::span so host tests can use C++17 compilers. */
struct descriptor_bytes
{
        const parser_uint8_t *data{};
        parser_size_t size{};
};

struct interface_class
{
        parser_uint8_t number{};
        parser_uint8_t alternate_setting{};
        parser_uint8_t cls{};
        parser_uint8_t subcls{};
        parser_uint8_t protocol{};
};

enum class descriptor_error
{
        none,
        configuration_header_too_short,
        invalid_configuration_header,
        total_length_mismatch,
        descriptor_header_truncated,
        invalid_descriptor_length,
        invalid_interface_descriptor,
        invalid_endpoint_descriptor,
        no_interfaces,
        interface_count_mismatch,
        interface_not_allowed,
};

struct descriptor_result
{
        descriptor_error error{descriptor_error::none};
        unsigned declared_interfaces{};
        unsigned observed_interfaces{}; /* distinct bInterfaceNumber values */
        interface_class offending_interface{};

        explicit operator bool() const { return error == descriptor_error::none; }
};

inline const char *descriptor_error_reason(descriptor_error error)
{
        switch (error) {
        case descriptor_error::none:                         return "valid";
        case descriptor_error::configuration_header_too_short:return "configuration descriptor header too short";
        case descriptor_error::invalid_configuration_header: return "invalid configuration descriptor header";
        case descriptor_error::total_length_mismatch:        return "configuration wTotalLength mismatch";
        case descriptor_error::descriptor_header_truncated:  return "trailing partial descriptor header";
        case descriptor_error::invalid_descriptor_length:    return "invalid descriptor length";
        case descriptor_error::invalid_interface_descriptor: return "short interface descriptor";
        case descriptor_error::invalid_endpoint_descriptor:  return "short endpoint descriptor";
        case descriptor_error::no_interfaces:                return "configuration has no interfaces";
        case descriptor_error::interface_count_mismatch:     return "bNumInterfaces does not match descriptors";
        case descriptor_error::interface_not_allowed:        return "interface class not in whitelist";
        }
        return "unknown descriptor error";
}

/*
 * Parse one complete configuration descriptor and evaluate every interface
 * descriptor (including alternate settings) with is_allowed(interface_class).
 *
 * Security invariants enforced here:
 * - the supplied bytes are exactly the wTotalLength snapshot;
 * - every descriptor is fully contained and advances by at least two bytes;
 * - interface and endpoint descriptors are large enough for every field the
 *   filter / UdeCx compatibility patch reads;
 * - at least one interface exists;
 * - bNumInterfaces equals the number of distinct interface numbers (alternate
 *   settings do not increase that count);
 * - every interface/alternate-setting class tuple is allowed.
 *
 * No allocation, exceptions, OS headers, registry, socket, or logging. The
 * function can therefore be fuzzed directly outside the driver.
 */
template <typename IsAllowed>
descriptor_result evaluate_configuration(descriptor_bytes bytes, IsAllowed is_allowed)
{
        constexpr parser_size_t configuration_descriptor_size = 9;
        constexpr parser_size_t interface_descriptor_size = 9;
        constexpr parser_size_t endpoint_descriptor_size = 7;
        constexpr parser_uint8_t configuration_descriptor_type = 0x02;
        constexpr parser_uint8_t interface_descriptor_type = 0x04;
        constexpr parser_uint8_t endpoint_descriptor_type = 0x05;

        descriptor_result result;
        if (!bytes.data || bytes.size < configuration_descriptor_size) {
                result.error = descriptor_error::configuration_header_too_short;
                return result;
        }

        auto p = bytes.data;
        if (p[0] != configuration_descriptor_size || p[1] != configuration_descriptor_type) {
                result.error = descriptor_error::invalid_configuration_header;
                return result;
        }

        auto total = static_cast<parser_size_t>(p[2]) |
                     (static_cast<parser_size_t>(p[3]) << 8);
        if (total != bytes.size) {
                result.error = descriptor_error::total_length_mismatch;
                return result;
        }

        result.declared_interfaces = p[4];
        bool seen_interfaces[256]{};
        parser_size_t offset = 0;
        unsigned interface_descriptors = 0;

        while (offset < bytes.size) {
                if (bytes.size - offset < 2) {
                        result.error = descriptor_error::descriptor_header_truncated;
                        return result;
                }

                auto length = p[offset];
                auto type = p[offset + 1];
                if (length < 2 || length > bytes.size - offset) {
                        result.error = descriptor_error::invalid_descriptor_length;
                        return result;
                }

                if (type == interface_descriptor_type) {
                        if (length < interface_descriptor_size) {
                                result.error = descriptor_error::invalid_interface_descriptor;
                                return result;
                        }

                        interface_class intf{
                                p[offset + 2], /* bInterfaceNumber */
                                p[offset + 3], /* bAlternateSetting */
                                p[offset + 5], /* bInterfaceClass */
                                p[offset + 6], /* bInterfaceSubClass */
                                p[offset + 7], /* bInterfaceProtocol */
                        };
                        ++interface_descriptors;
                        if (!seen_interfaces[intf.number]) {
                                seen_interfaces[intf.number] = true;
                                ++result.observed_interfaces;
                        }
                        if (!is_allowed(intf)) {
                                result.error = descriptor_error::interface_not_allowed;
                                result.offending_interface = intf;
                                return result;
                        }
                } else if (type == endpoint_descriptor_type &&
                           length < endpoint_descriptor_size) {
                        // The UdeCx compatibility patch reads through bInterval
                        // (byte 6), so a short endpoint must be rejected before
                        // that cast. Longer audio endpoint descriptors are valid.
                        result.error = descriptor_error::invalid_endpoint_descriptor;
                        return result;
                }

                offset += length;
        }

        if (!interface_descriptors) {
                result.error = descriptor_error::no_interfaces;
                return result;
        }
        if (result.observed_interfaces != result.declared_interfaces) {
                result.error = descriptor_error::interface_count_mismatch;
                return result;
        }
        return result;
}

} // namespace usbip::device_filter
