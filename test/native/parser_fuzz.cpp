// Host-side unit + fuzz driver for the PRODUCTION descriptor parser.
//
// This includes the exact header the kernel driver compiles
// (drivers/ude/device_filter_parser.h) -- not a reimplementation -- so the
// malformed/inconsistent-descriptor cases exercise the real logic. It exits
// non-zero with a diagnostic on the first failure.
//
// Build/run is driven by test/test_parser_native.py, or manually:
//   c++ -std=c++17 -O1 -Wall -Wextra test/native/parser_fuzz.cpp -o /tmp/pf && /tmp/pf

#include "../../drivers/ude/device_filter_parser.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <set>
#include <vector>

using usbip::device_filter::descriptor_bytes;
using usbip::device_filter::descriptor_error;
using usbip::device_filter::evaluate_configuration;
using usbip::device_filter::interface_class;

namespace {

int g_failures = 0;

void check(bool cond, const char *what) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_failures;
    }
}

std::vector<std::uint8_t> iface(std::uint8_t number, std::uint8_t alt,
                                std::uint8_t cls, std::uint8_t sub = 0,
                                std::uint8_t proto = 0) {
    return {9, 0x04, number, alt, 0, cls, sub, proto, 0};
}

std::vector<std::uint8_t> endpoint(std::uint8_t length = 7) {
    std::vector<std::uint8_t> out = {length, 0x05, 0x81, 0x03, 8, 0, 10};
    out.resize(length);
    return out;
}

std::vector<std::uint8_t> iad() {
    return {8, 0x0B, 0, 2, 0x02, 0x02, 0x01, 0};
}

std::vector<std::uint8_t> class_specific(std::uint8_t length = 5) {
    std::vector<std::uint8_t> out = {length, 0x24, 0x00, 0x10, 0x01};
    out.resize(length);
    return out;
}

std::vector<std::uint8_t> unknown_descriptor(std::uint8_t length, std::uint8_t type = 0x30) {
    std::vector<std::uint8_t> out;
    out.reserve(length);
    out.push_back(length);
    out.push_back(type);
    for (std::uint8_t i = 2; i < length; ++i) out.push_back(i);
    return out;
}

// Build a CONFIGURATION descriptor. num_interfaces/total_override let tests lie.
std::vector<std::uint8_t> config(const std::vector<std::vector<std::uint8_t>> &ifaces,
                                 int num_interfaces = -1, int total_override = -1) {
    std::vector<std::uint8_t> body;
    int true_count = 0;
    for (auto &i : ifaces) {
        if (i.size() >= 2 && i[1] == 0x04) ++true_count;
        body.insert(body.end(), i.begin(), i.end());
    }
    std::size_t total = total_override >= 0
                            ? static_cast<std::size_t>(total_override)
                            : 9 + body.size();
    std::uint8_t nif = num_interfaces >= 0
                           ? static_cast<std::uint8_t>(num_interfaces)
                           : static_cast<std::uint8_t>(true_count);
    std::vector<std::uint8_t> out = {
        9, 0x02, static_cast<std::uint8_t>(total & 0xFF),
        static_cast<std::uint8_t>((total >> 8) & 0xFF),
        nif, 1, 0, 0x80, 50};
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

descriptor_error eval(const std::vector<std::uint8_t> &bytes,
                      const std::set<std::uint8_t> &allowed_classes) {
    descriptor_bytes view{bytes.data(), bytes.size()};
    auto r = evaluate_configuration(view, [&](const interface_class &i) {
        return allowed_classes.count(i.cls) != 0;
    });
    return r.error;
}

void unit_cases() {
    const std::set<std::uint8_t> ms{0x08};
    const std::set<std::uint8_t> hid{0x03};
    const std::set<std::uint8_t> ms_hid{0x08, 0x03};

    check(eval(config({iface(0, 0, 0x08)}), ms) == descriptor_error::none,
          "benign mass-storage allowed");
    check(eval(config({iface(0, 0, 0x08), iface(1, 0, 0x03)}), ms) ==
              descriptor_error::interface_not_allowed,
          "composite hid smuggled past ms-only policy is denied");
    check(eval(config({iface(0, 0, 0x08), iface(1, 0, 0x03)}), ms_hid) ==
              descriptor_error::none,
          "composite allowed when both classes whitelisted");

    // Zero interfaces but declares one: vacuous-pass risk must fail closed.
    check(eval(config({}, /*num_interfaces=*/1), ms_hid) ==
              descriptor_error::no_interfaces,
          "zero-interface config denied");

    // Real HID interface but bNumInterfaces lies (0).
    check(eval(config({iface(0, 0, 0x03)}, /*num_interfaces=*/0), hid) ==
              descriptor_error::interface_count_mismatch,
          "lying bNumInterfaces denied");

    // wTotalLength shorter than the body actually sent.
    check(eval(config({iface(0, 0, 0x03)}, -1, /*total_override=*/9), hid) ==
              descriptor_error::total_length_mismatch,
          "short wTotalLength denied");

    // Trailing partial descriptor header (1 stray byte).
    {
        auto c = config({iface(0, 0, 0x08)});
        c.push_back(0x01);              // stray byte
        c[2] = static_cast<std::uint8_t>(c.size());  // keep total==size
        check(eval(c, ms) == descriptor_error::descriptor_header_truncated,
              "trailing partial descriptor denied");
    }

    // bLength == 0 somewhere.
    {
        auto c = config({iface(0, 0, 0x08)});
        c.push_back(0x00);
        c.push_back(0x04);
        c[2] = static_cast<std::uint8_t>(c.size());
        check(eval(c, ms) == descriptor_error::invalid_descriptor_length,
              "zero bLength denied");
    }

    // Interface descriptor too short (bLength 8, type 0x04).
    {
        std::vector<std::uint8_t> shortif = {8, 0x04, 0, 0, 0, 0x08, 0, 0};
        check(eval(config({shortif}), ms) ==
                  descriptor_error::invalid_interface_descriptor,
              "short interface descriptor denied");
    }

    // Endpoint descriptor shorter than USB_ENDPOINT_DESCRIPTOR (7 bytes) must
    // be denied before the compatibility patch can cast/read through byte 6.
    check(eval(config({iface(0, 0, 0x03), endpoint(/*length=*/2)},
                      /*num_interfaces=*/1), hid) ==
              descriptor_error::invalid_endpoint_descriptor,
          "short endpoint descriptor denied before patching");
    check(eval(config({iface(0, 0, 0x03), endpoint()},
                      /*num_interfaces=*/1), hid) == descriptor_error::none,
          "valid endpoint descriptor accepted");

    // Alternate settings: two descriptors, same interface number => count 1.
    check(eval(config({iface(0, 0, 0x03), iface(0, 1, 0x03)},
                      /*num_interfaces=*/1), hid) == descriptor_error::none,
          "alternate settings counted once");

    // Non-contiguous interface numbers are legal; bNumInterfaces is a count of
    // distinct interface numbers, not max(interface_number)+1.
    check(eval(config({iface(2, 0, 0x03), iface(7, 0, 0x08)},
                      /*num_interfaces=*/2), ms_hid) == descriptor_error::none,
          "non-contiguous interface numbers accepted");

    // IAD and class-specific descriptors are not themselves class tokens; they
    // must be skipped safely while adjacent interfaces still drive policy.
    check(eval(config({iad(), iface(0, 0, 0x02, 0x06, 0x00),
                       class_specific(), endpoint(),
                       iface(1, 0, 0x0A, 0x00, 0x00), endpoint()},
                      /*num_interfaces=*/2), {0x02, 0x0A}) ==
              descriptor_error::none,
          "IAD/class-specific CDC descriptors skipped while interfaces allowed");
    check(eval(config({iad(), iface(0, 0, 0x02, 0x06, 0x00),
                       class_specific(), iface(1, 0, 0x03)},
                      /*num_interfaces=*/2), {0x02}) ==
              descriptor_error::interface_not_allowed,
          "IAD does not hide later disallowed interface");

    // Subclass/protocol-aware matching: same class, wrong protocol must deny.
    {
        auto c = config({iface(0, 0, 0x08, 0x06, 0x50)});
        descriptor_bytes view{c.data(), c.size()};
        auto ok = evaluate_configuration(view, [](const interface_class &i) {
            return i.cls == 0x08 && i.subcls == 0x06 && i.protocol == 0x50;
        });
        check(ok.error == descriptor_error::none,
              "subclass/protocol predicate accepts exact mass-storage tuple");
        auto bad = evaluate_configuration(view, [](const interface_class &i) {
            return i.cls == 0x08 && i.subcls == 0x06 && i.protocol == 0x62;
        });
        check(bad.error == descriptor_error::interface_not_allowed &&
                  bad.offending_interface.cls == 0x08 &&
                  bad.offending_interface.subcls == 0x06 &&
                  bad.offending_interface.protocol == 0x50,
              "subclass/protocol predicate denies and reports offending tuple");
    }

    // Maximum bNumInterfaces value is representable and should not
    // overflow the seen_interfaces[256] table.
    {
        std::vector<std::vector<std::uint8_t>> many;
        for (int i = 0; i < 255; ++i) {
            many.push_back(iface(static_cast<std::uint8_t>(i), 0, 0x03));
        }
        check(eval(config(many, /*num_interfaces=*/255), hid) ==
                  descriptor_error::none,
              "255 distinct interfaces accepted");
    }

    // A descriptor can be long and unknown; it is safe if it is fully contained.
    check(eval(config({iface(0, 0, 0x03), unknown_descriptor(255)},
                      /*num_interfaces=*/1), hid) == descriptor_error::none,
          "oversized unknown descriptor skipped when contained");

    // But inflated wTotalLength claims must fail even when the real buffer is
    // otherwise well-formed.
    check(eval(config({iface(0, 0, 0x03)}, -1, /*total_override=*/65535), hid) ==
              descriptor_error::total_length_mismatch,
          "inflated wTotalLength denied");

    // Header too short / wrong type.
    {
        std::vector<std::uint8_t> tiny = {9, 0x02, 9, 0};  // < 9 bytes
        check(eval(tiny, ms) == descriptor_error::configuration_header_too_short,
              "sub-9-byte header denied");
        auto c = config({iface(0, 0, 0x08)});
        c[1] = 0x03;  // wrong descriptor type
        check(eval(c, ms) == descriptor_error::invalid_configuration_header,
              "wrong config descriptor type denied");
    }
}

// Property fuzz: the parser must never crash and must uphold its invariants for
// arbitrary bytes behind a valid config header.
void fuzz(int iterations) {
    std::mt19937 rng(0x5eed);  // fixed seed => reproducible
    std::uniform_int_distribution<int> byte(0, 255);
    std::uniform_int_distribution<int> body_len(0, 40);

    const std::set<std::uint8_t> allow_all{};      // handled below
    for (int it = 0; it < iterations; ++it) {
        int n = body_len(rng);
        std::vector<std::uint8_t> buf;
        std::size_t total = 9 + n;
        bool mismatch_total = (byte(rng) % 4) == 0;
        std::size_t declared_total = mismatch_total ? (byte(rng) | (byte(rng) << 8)) : total;
        buf = {9, 0x02, static_cast<std::uint8_t>(declared_total & 0xFF),
               static_cast<std::uint8_t>((declared_total >> 8) & 0xFF),
               static_cast<std::uint8_t>(byte(rng)), 1, 0, 0x80, 50};
        for (int i = 0; i < n; ++i) buf.push_back(static_cast<std::uint8_t>(byte(rng)));

        descriptor_bytes view{buf.data(), buf.size()};

        // allow-all: ok implies a self-consistent, non-empty interface set.
        auto all = evaluate_configuration(view, [](const interface_class &) { return true; });
        if (all) {
            check(all.observed_interfaces >= 1 &&
                      all.observed_interfaces == all.declared_interfaces,
                  "fuzz: ok under allow-all violates count invariant");
        }

        // allow-none: a well-formed config always has >=1 interface, which is
        // then denied, so ok must be impossible.
        auto none = evaluate_configuration(view, [](const interface_class &) { return false; });
        check(!none, "fuzz: allow-none must never accept a device");
        (void)allow_all;
    }
}

}  // namespace

int main() {
    unit_cases();
    fuzz(50000);
    if (g_failures) {
        std::fprintf(stderr, "%d parser check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("parser_fuzz: all unit cases + 50000 fuzz iterations passed\n");
    return 0;
}
