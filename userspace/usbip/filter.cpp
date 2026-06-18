/*
 * Copyright (c) 2026 Kelvin Wu
 */

#include "usbip.h"

#include <libusbip\vhci.h>

#include <spdlog\spdlog.h>

#include <print>
#include <algorithm>

namespace
{

using namespace usbip;

const device_type_category* find_category(const std::string &id)
{
        for (auto &c: device_type_categories()) {
                if (c.id == id) {
                        return &c;
                }
        }
        return nullptr;
}

auto contains(const std::vector<device_filter_entry> &v, const device_filter_entry &e)
{
        return std::find(v.begin(), v.end(), e) != v.end();
}

auto category_enabled(const device_filter_policy &p, const device_type_category &c)
{
        if (c.entries.empty()) {
                return false;
        }
        for (auto &e: c.entries) {
                if (!contains(p.entries, e)) {
                        return false;
                }
        }
        return true;
}

void print_entry(const device_filter_entry &e)
{
        std::string fields;
        if (e.match_flags & filter_match_class)    { fields += std::format(" class={:#04x}", e.bClass); }
        if (e.match_flags & filter_match_subclass) { fields += std::format(" subclass={:#04x}", e.bSubClass); }
        if (e.match_flags & filter_match_protocol) { fields += std::format(" protocol={:#04x}", e.bProtocol); }
        if (fields.empty()) {
                fields = " (matches any)";
        }
        std::println("    -{}", fields);
}

void print_policy(const device_filter_policy &p)
{
        if (p.mode == filter_mode::disabled) {
                std::println("Device-type filter: DISABLED (all device types are allowed)");
                return;
        }

        std::println("Device-type filter: WHITELIST{}",
                     p.entries.empty() ? " (empty => every device is denied)" : "");

        std::println("Categories:");
        for (auto &c: device_type_categories()) {
                std::println("  [{}] {:<14} {}", category_enabled(p, c) ? 'x' : ' ', c.id, c.name);
        }

        // Entries that are not fully represented by a known category.
        std::vector<device_filter_entry> covered;
        for (auto &c: device_type_categories()) {
                if (category_enabled(p, c)) {
                        for (auto &e: c.entries) {
                                covered.push_back(e);
                        }
                }
        }

        auto first = true;
        for (auto &e: p.entries) {
                if (contains(covered, e)) {
                        continue;
                }
                if (first) {
                        first = false;
                        std::println("Additional entries:");
                }
                print_entry(e);
        }
}

} // namespace


bool usbip::cmd_filter(void *p)
{
        auto &args = *reinterpret_cast<filter_args*>(p);

        if (args.list_categories) {
                std::println("Available device-type categories:");
                for (auto &c: device_type_categories()) {
                        std::println("  {:<14} {}", c.id, c.name);
                }
                return true;
        }

        auto dev = vhci::open();
        if (!dev) {
                spdlog::error(GetLastErrorMsg());
                return false;
        }

        auto modify = args.disable || args.deny_all || !args.categories.empty();
        if (!modify) {
                auto policy = vhci::get_device_filter(dev.get());
                if (!policy) {
                        spdlog::error(GetLastErrorMsg());
                        return false;
                }
                print_policy(*policy);
                return true;
        }

        device_filter_policy policy;

        if (args.disable) {
                policy.mode = filter_mode::disabled;
        } else if (args.deny_all) {
                policy.mode = filter_mode::whitelist; // empty whitelist denies all
        } else {
                policy.mode = filter_mode::whitelist;
                for (auto &id: args.categories) {
                        auto c = find_category(id);
                        if (!c) {
                                spdlog::error("unknown device-type category '{}', use --list-categories", id);
                                return false;
                        }
                        for (auto &e: c->entries) {
                                if (!contains(policy.entries, e)) {
                                        policy.entries.push_back(e);
                                }
                        }
                }
        }

        if (!vhci::set_device_filter(dev.get(), policy)) {
                spdlog::error(GetLastErrorMsg());
                return false;
        }

        std::println("Device-type filter updated.");
        print_policy(policy);
        return true;
}
