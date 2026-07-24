/*
 * Host-side tests for the production policy serialization helpers.
 */

#include <cstdint>
#include <cstdlib>
#include <iostream>

#include "../../drivers/ude/device_filter_policy.h"

namespace {

enum class filter_mode : std::uint8_t {
    disabled,
    whitelist,
    unknown = 0x7f,
};

struct entry {
    std::uint8_t cls{};
    std::uint8_t subcls{};
    std::uint8_t protocol{};
    std::uint8_t match_flags{};
};

struct policy {
    filter_mode mode{};
    std::uint32_t count{};
    entry entries[64]{};
};

using usbip::device_filter::policy_value_status;
using usbip::device_filter::sanitize_loaded_policy;
using usbip::device_filter::sanitize_policy_for_store;
using usbip::device_filter::serialized_policy_size;

void check(bool ok, const char *what) {
    if (!ok) {
        std::cerr << "FAIL: " << what << "\n";
        std::exit(1);
    }
}

entry ent(std::uint8_t cls) {
    return entry{cls, static_cast<std::uint8_t>(cls + 1),
                 static_cast<std::uint8_t>(cls + 2), 1};
}

void unit_cases() {
    constexpr unsigned long reg_binary = 3;
    constexpr unsigned long reg_dword = 4;

    {
        policy raw{};
        raw.mode = filter_mode::disabled;
        raw.count = 2;
        raw.entries[0] = ent(0x03);
        raw.entries[1] = ent(0x08);

        policy out{};
        auto status = sanitize_loaded_policy(
            out, raw, serialized_policy_size<policy>(2), reg_binary, reg_binary,
            filter_mode::disabled, filter_mode::whitelist);
        check(status == policy_value_status::ok, "valid binary policy loads");
        check(out.mode == filter_mode::disabled, "disabled mode preserved");
        check(out.count == 2, "valid count preserved");
        check(out.entries[0].cls == 0x03 && out.entries[1].cls == 0x08,
              "entry prefix copied");
    }

    {
        policy raw{};
        raw.mode = filter_mode::unknown;
        raw.count = 1;
        raw.entries[0] = ent(0x0a);

        policy out{};
        auto status = sanitize_loaded_policy(
            out, raw, serialized_policy_size<policy>(1), reg_binary, reg_binary,
            filter_mode::disabled, filter_mode::whitelist);
        check(status == policy_value_status::ok, "unknown mode value loads");
        check(out.mode == filter_mode::whitelist,
              "unknown loaded mode normalizes to whitelist");
        check(out.count == 1 && out.entries[0].cls == 0x0a,
              "unknown mode does not discard valid entries");
    }

    {
        policy raw{};
        raw.mode = filter_mode::disabled;
        raw.count = 4;
        raw.entries[0] = ent(0x02);
        raw.entries[1] = ent(0xff);

        policy out{};
        auto status = sanitize_loaded_policy(
            out, raw, serialized_policy_size<policy>(2), reg_binary, reg_binary,
            filter_mode::disabled, filter_mode::whitelist);
        check(status == policy_value_status::ok,
              "count larger than value length still loads");
        check(out.count == 2, "count clamped by actual registry value length");
        check(out.entries[1].cls == 0xff, "length-clamped entries copied");
    }

    {
        policy raw{};
        raw.mode = filter_mode::disabled;
        raw.count = 1000;
        for (std::uint8_t i = 0; i < 64; ++i) raw.entries[i] = ent(i);

        policy out{};
        auto status = sanitize_loaded_policy(
            out, raw, sizeof(raw), reg_binary, reg_binary,
            filter_mode::disabled, filter_mode::whitelist);
        check(status == policy_value_status::ok,
              "oversized count with full value loads");
        check(out.count == 64, "count clamped by fixed policy capacity");
        check(out.entries[63].cls == 63, "capacity-clamped entries copied");
    }

    {
        policy raw{};
        raw.mode = filter_mode::disabled;
        raw.count = 1;
        raw.entries[0] = ent(0x03);

        policy out{};
        out.mode = filter_mode::disabled;
        out.count = 9;
        auto status = sanitize_loaded_policy(
            out, raw, serialized_policy_size<policy>(1), reg_dword, reg_binary,
            filter_mode::disabled, filter_mode::whitelist);
        check(status == policy_value_status::bad_type_or_size,
              "wrong registry type rejected");
        check(out.mode == filter_mode::whitelist && out.count == 0,
              "wrong registry type fails closed");
    }

    {
        policy raw{};
        raw.mode = filter_mode::disabled;
        raw.count = 1;

        policy out{};
        auto status = sanitize_loaded_policy(
            out, raw, serialized_policy_size<policy>(0) - 1, reg_binary, reg_binary,
            filter_mode::disabled, filter_mode::whitelist);
        check(status == policy_value_status::bad_type_or_size,
              "short registry value rejected");
        check(out.mode == filter_mode::whitelist && out.count == 0,
              "short registry value fails closed");
    }

    {
        policy raw{};
        raw.mode = filter_mode::unknown;
        raw.count = 1000;
        raw.entries[0] = ent(0x03);

        auto stored = sanitize_policy_for_store(
            raw, filter_mode::disabled, filter_mode::whitelist);
        check(stored.mode == filter_mode::whitelist,
              "unknown stored mode normalizes to whitelist");
        check(stored.count == 64, "stored count clamped to capacity");
        check(serialized_policy_size<policy>(stored.count) == sizeof(policy),
              "serialized size covers active stored prefix");
    }
}

} // namespace

int main() {
    unit_cases();
    return 0;
}
