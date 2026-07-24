/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 usbip-win2-withfilter contributors
 *
 * Side-effect-free policy serialization helpers for the device-type filter.
 * The WDF registry load/store path and host-side native tests compile the exact
 * same sanitization logic.
 */

#pragma once

#include <stddef.h>

namespace usbip::device_filter
{

using policy_size_t = decltype(sizeof(0));

enum class policy_value_status
{
        ok,
        bad_type_or_size,
};

template <typename Policy>
constexpr policy_size_t policy_entry_capacity()
{
        return sizeof(((Policy *)0)->entries) / sizeof(((Policy *)0)->entries[0]);
}

template <typename Policy>
constexpr policy_size_t policy_entries_offset()
{
        return static_cast<policy_size_t>(offsetof(Policy, entries));
}

template <typename Policy>
void make_fail_closed_policy(Policy &p, decltype(p.mode) whitelist_mode)
{
        p = {};
        p.mode = whitelist_mode;
        p.count = 0;
}

/*
 * Sanitize a REG_BINARY policy value read from the Parameters key.
 *
 * Security invariants:
 * - unreadable, wrong-type, or too-short values fail closed;
 * - unknown modes normalize to whitelist, not disabled;
 * - count is clamped to both the bytes actually present and the fixed policy
 *   capacity before entries are copied.
 */
template <typename Policy>
policy_value_status sanitize_loaded_policy(
        Policy &out, const Policy &raw, policy_size_t actual_bytes,
        unsigned long value_type, unsigned long binary_type,
        decltype(out.mode) disabled_mode, decltype(out.mode) whitelist_mode)
{
        make_fail_closed_policy(out, whitelist_mode);

        if (value_type != binary_type || actual_bytes < policy_entries_offset<Policy>()) {
                return policy_value_status::bad_type_or_size;
        }

        auto max_by_len = (actual_bytes - policy_entries_offset<Policy>()) /
                          sizeof(raw.entries[0]);
        auto count = static_cast<policy_size_t>(raw.count);
        if (count > max_by_len) {
                count = max_by_len;
        }
        auto capacity = policy_entry_capacity<Policy>();
        if (count > capacity) {
                count = capacity;
        }

        out.mode = (raw.mode == disabled_mode) ? disabled_mode : whitelist_mode;
        out.count = static_cast<decltype(out.count)>(count);
        for (policy_size_t i = 0; i < count; ++i) {
                out.entries[i] = raw.entries[i];
        }
        return policy_value_status::ok;
}

/*
 * Normalize a policy before persisting it. Store only the active entry prefix so
 * a later registry load can bound count by the value length.
 */
template <typename Policy>
Policy sanitize_policy_for_store(
        const Policy &in, decltype(in.mode) disabled_mode, decltype(in.mode) whitelist_mode)
{
        Policy out = in;
        auto capacity = policy_entry_capacity<Policy>();
        if (static_cast<policy_size_t>(out.count) > capacity) {
                out.count = static_cast<decltype(out.count)>(capacity);
        }
        if (out.mode != disabled_mode) {
                out.mode = whitelist_mode;
        }
        return out;
}

template <typename Policy>
constexpr policy_size_t serialized_policy_size(policy_size_t count)
{
        return policy_entries_offset<Policy>() + count * sizeof(((Policy *)0)->entries[0]);
}

} // namespace usbip::device_filter
