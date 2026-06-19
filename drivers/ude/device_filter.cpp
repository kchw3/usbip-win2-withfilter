/*
 * Copyright (c) 2026 Kelvin Wu
 */

#include "device_filter.h"
#include "trace.h"
#include "device_filter.tmh"

#include "context.h"
#include "network.h"
#include "driver.h"
#include "persistent.h"

#include <usbip/proto.h>
#include <usbip/proto_op.h>
#include <usbip/consts.h>

#include <libdrv/pdu.h>
#include <libdrv/usbdsc.h>
#include <libdrv/mdl_cpp.h>

#include <resources/messages.h>

#include <ntstrsafe.h>

namespace
{

using namespace usbip;
using usbip::device_filter::policy;

enum : ULONG { MAX_CONFIG_DESCRIPTOR_SIZE = 0xFFFF }; // wTotalLength is UINT16

inline UNICODE_STRING value_name()
{
        UNICODE_STRING s;
        RtlInitUnicodeString(&s, device_filter_value_name);
        return s;
}

/*
 * @return true if (cls, sub, proto) matches at least one whitelist entry.
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
bool is_allowed(_In_ const policy &p, _In_ UINT8 cls, _In_ UINT8 sub, _In_ UINT8 proto)
{
        for (ULONG i = 0; i < p.count; ++i) {
                auto &e = p.entries[i];

                if ((e.match_flags & vhci::FILTER_MATCH_CLASS)    && e.bClass    != cls)   { continue; }
                if ((e.match_flags & vhci::FILTER_MATCH_SUBCLASS) && e.bSubClass != sub)   { continue; }
                if ((e.match_flags & vhci::FILTER_MATCH_PROTOCOL) && e.bProtocol != proto) { continue; }

                return true;
        }

        return false;
}

/*
 * Human-readable name for a USB base class code (bDeviceClass / bInterfaceClass), so that
 * an admin reading the event log sees e.g. "class 08 (Mass Storage)" instead of a bare
 * number. Returns "Unknown" for codes that are not well-known base classes.
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
const char *usb_class_name(_In_ UINT8 cls)
{
        switch (cls) {
        case 0x00: return "per-interface";
        case 0x01: return "Audio";
        case 0x02: return "Communications/CDC";
        case 0x03: return "HID";
        case 0x05: return "Physical";
        case 0x06: return "Image";
        case 0x07: return "Printer";
        case 0x08: return "Mass Storage";
        case 0x09: return "Hub";
        case 0x0A: return "CDC-Data";
        case 0x0B: return "Smart Card";
        case 0x0D: return "Content Security";
        case 0x0E: return "Video";
        case 0x0F: return "Personal Healthcare";
        case 0x10: return "Audio/Video";
        case 0x11: return "Billboard";
        case 0x12: return "USB Type-C Bridge";
        case 0xDC: return "Diagnostic";
        case 0xE0: return "Wireless Controller";
        case 0xEF: return "Miscellaneous";
        case 0xFE: return "Application Specific";
        case 0xFF: return "Vendor Specific";
        default:   return "Unknown";
        }
}

/*
 * Render one match field of a whitelist entry as "%02X" if the entry actually constrains
 * it (FILTER_MATCH_* flag set), or "**" if the field is a wildcard for that entry.
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
void format_match_field(_In_ bool matched, _In_ UINT8 v, _Out_writes_z_(3) WCHAR *out)
{
        if (matched) {
                RtlStringCchPrintfW(out, 3, L"%02X", v);
        } else {
                out[0] = L'*';
                out[1] = L'*';
                out[2] = L'\0';
        }
}

/*
 * Render the currently configured whitelist as a comma-separated list of class/sub/proto
 * triples (for example "08/06/50, 03/xx/xx" where xx is a wildcard field), so a rejection
 * log shows exactly what is allowed instead of leaving the admin to guess why the attempted
 * type didn't match anything. Wildcard fields are emitted as "**" in the actual output.
 * Truncates with a trailing "..." if the policy has more entries than fit in buf.
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
void format_whitelist(_In_ const policy &p, _Out_writes_z_(cch) WCHAR *buf, _In_ size_t cch)
{
        if (!p.count) {
                RtlStringCchCopyW(buf, cch, L"(empty)");
                return;
        }

        buf[0] = L'\0';

        for (ULONG i = 0; i < p.count; ++i) {
                auto &e = p.entries[i];

                WCHAR c[3], s[3], pr[3];
                format_match_field((e.match_flags & vhci::FILTER_MATCH_CLASS) != 0, e.bClass, c);
                format_match_field((e.match_flags & vhci::FILTER_MATCH_SUBCLASS) != 0, e.bSubClass, s);
                format_match_field((e.match_flags & vhci::FILTER_MATCH_PROTOCOL) != 0, e.bProtocol, pr);

                WCHAR item[20];
                RtlStringCchPrintfW(item, RTL_NUMBER_OF(item), i ? L", %s/%s/%s" : L"%s/%s/%s", c, s, pr);

                size_t used{};
                RtlStringCchLengthW(buf, cch, &used);

                constexpr size_t reserve_for_ellipsis = RTL_NUMBER_OF(L", ...");
                size_t itemlen{};
                RtlStringCchLengthW(item, RTL_NUMBER_OF(item), &itemlen);

                if (used + itemlen + reserve_for_ellipsis >= cch) {
                        RtlStringCchCatW(buf, cch, L", ...");
                        return;
                }

                RtlStringCchCatW(buf, cch, item);
        }
}

/*
 * Write an admin-visible Windows System Event Log entry plus a verbose WPP trace.
 * Both records carry the remote endpoint, the device VID/PID, the offending class triple
 * (with its human-readable class name), the reason, and the full whitelist that the
 * attempted type failed to match, so a rejection can be diagnosed from either the event
 * log or a WPP trace without cross-referencing or reading back the policy separately.
 *
 * @param ifnum interface number, or -1 for device-level / global reasons
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
void report_rejection(
        _In_ device_ctx_ext &ext, _In_ const usbip_usb_device &udev, _In_ const policy &p,
        _In_ const char *reason, _In_ int ifnum, _In_ UINT8 cls, _In_ UINT8 sub, _In_ UINT8 proto)
{
        WCHAR wl[128];
        format_whitelist(p, wl, RTL_NUMBER_OF(wl));

        Trace(TRACE_LEVEL_ERROR,
                "device-type filter REJECT %!USTR!:%!USTR!/%!USTR! VID_%04X&PID_%04X attempted "
                "%s type class/sub/proto %02X/%02X/%02X (%s), interface %d: %s; not matched by whitelist [%lu]: %S",
                ext.node_name(), ext.service_name(), ext.busid(), udev.idVendor, udev.idProduct,
                ifnum >= 0 ? "interface" : "device", cls, sub, proto, usb_class_name(cls), ifnum,
                reason, p.count, wl);

        auto drvobj = WdfDriverWdmGetDriverObject(WdfGetDriver());
        if (!drvobj) {
                Trace(TRACE_LEVEL_WARNING, "no WDM driver object, event-log entry skipped");
                return;
        }

        // Keep the inserted string within ERROR_LOG_MAXIMUM_SIZE.
        constexpr USHORT max_str_bytes = ERROR_LOG_MAXIMUM_SIZE - sizeof(IO_ERROR_LOG_PACKET);
        constexpr size_t max_chars = max_str_bytes / sizeof(WCHAR);

        // Interface fragment only when an interface is the cause; device-level reasons omit it.
        WCHAR ifrag[24] = L"";
        if (ifnum >= 0) {
                RtlStringCchPrintfW(ifrag, RTL_NUMBER_OF(ifrag), L"interface %d, ", ifnum);
        }

        WCHAR msg[max_chars];
        auto st = RtlStringCchPrintfW(msg, RTL_NUMBER_OF(msg),
                L"Blocked VID_%04X&PID_%04X on %wZ (%wZ): %hs (%sclass %02X/%02X/%02X %hs); whitelist: %s",
                udev.idVendor, udev.idProduct, ext.node_name(), ext.busid(),
                reason, ifrag, cls, sub, proto, usb_class_name(cls), wl);

        if (st == STATUS_BUFFER_OVERFLOW) {
                msg[RTL_NUMBER_OF(msg) - 1] = L'\0'; // truncated copy is fine for logging
        } else if (NT_ERROR(st)) {
                Trace(TRACE_LEVEL_WARNING, "format event-log string %!STATUS!, entry skipped", st);
                return;
        }

        size_t cch{};
        if (NT_ERROR(RtlStringCchLengthW(msg, RTL_NUMBER_OF(msg), &cch))) {
                return;
        }

        auto slen = static_cast<USHORT>((cch + 1) * sizeof(WCHAR));
        auto size = static_cast<USHORT>(sizeof(IO_ERROR_LOG_PACKET) + slen);

        auto entry = static_cast<PIO_ERROR_LOG_PACKET>(IoAllocateErrorLogEntry(drvobj, static_cast<UCHAR>(size)));
        if (!entry) {
                Trace(TRACE_LEVEL_WARNING, "IoAllocateErrorLogEntry(%u bytes) failed, event-log entry skipped", size);
                return;
        }

        RtlZeroMemory(entry, size);
        entry->ErrorCode = USBIP_ERROR_DEVICE_FILTERED;
        entry->NumberOfStrings = 1;
        entry->StringOffset = sizeof(IO_ERROR_LOG_PACKET);
        entry->DumpDataSize = 0;
        RtlCopyMemory(reinterpret_cast<PUCHAR>(entry) + entry->StringOffset, msg, slen);

        IoWriteErrorLogEntry(entry);
}

/*
 * Issue a standard GET_DESCRIPTOR (device-to-host, standard, device recipient) control-IN
 * over the already-connected socket and read the result.
 *
 * @param pool   memory::stack for an on-stack buffer, memory::nonpaged for a pool buffer
 * @param actual number of bytes received into buf
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED NTSTATUS get_descriptor(
        _Inout_ device_ctx_ext &ext, _Inout_ ULONG &seqnum, _In_ UINT8 type, _In_ UINT8 index,
        _In_ memory pool, _Out_writes_bytes_(len) void *buf, _In_ UINT16 len, _Out_ UINT16 &actual)
{
        PAGED_CODE();
        actual = 0;

        header hdr{};
        hdr.command = CMD_SUBMIT;
        hdr.seqnum = seqnum++;
        hdr.devid = ext.properties().devid;
        hdr.direction = direction::in;
        hdr.ep = 0;

        auto &s = hdr.cmd_submit;
        s.transfer_flags = 0;
        s.transfer_buffer_length = len;
        s.start_frame = 0;
        s.number_of_packets = number_of_packets_non_isoch;
        s.interval = 0;

        s.setup[0] = 0x80;                       // bmRequestType: dev-to-host, standard, device
        s.setup[1] = 0x06;                       // bRequest: GET_DESCRIPTOR
        s.setup[2] = index;                      // wValue low
        s.setup[3] = type;                       // wValue high (descriptor type)
        s.setup[4] = 0;                          // wIndex low
        s.setup[5] = 0;                          // wIndex high
        s.setup[6] = static_cast<UINT8>(len);    // wLength low
        s.setup[7] = static_cast<UINT8>(len >> 8); // wLength high

        byteswap_header(hdr, swap_dir::host2net);

        TraceDbg("%!USTR!: GET_DESCRIPTOR type %#x index %u, requesting %u bytes (seqnum %lu)",
                ext.busid(), type, index, len, hdr.seqnum);

        if (auto err = send(ext.sock, memory::stack, &hdr, sizeof(hdr))) {
                Trace(TRACE_LEVEL_ERROR, "%!USTR!: send CMD_SUBMIT GET_DESCRIPTOR(type %#x index %u) %!STATUS!",
                        ext.busid(), type, index, err);
                return err;
        }

        header rep{};
        if (auto err = recv(ext.sock, memory::stack, &rep, sizeof(rep))) {
                Trace(TRACE_LEVEL_ERROR, "%!USTR!: recv RET_SUBMIT header for GET_DESCRIPTOR(type %#x index %u) %!STATUS!",
                        ext.busid(), type, index, err);
                return err;
        }
        byteswap_header(rep, swap_dir::net2host);

        if (rep.command != RET_SUBMIT) {
                Trace(TRACE_LEVEL_ERROR, "%!USTR!: expected RET_SUBMIT, got command %#x (GET_DESCRIPTOR type %#x index %u)",
                        ext.busid(), rep.command, type, index);
                return USBIP_ERROR_PROTOCOL;
        }

        if (auto status = rep.ret_submit.status) {
                Trace(TRACE_LEVEL_ERROR, "%!USTR!: GET_DESCRIPTOR(type %#x index %u) RET_SUBMIT status %d (device stalled/errored)",
                        ext.busid(), type, index, status);
                return USBIP_ERROR_GENERAL;
        }

        auto n = rep.ret_submit.actual_length;
        if (n < 0 || static_cast<ULONG>(n) > len) {
                Trace(TRACE_LEVEL_ERROR, "%!USTR!: GET_DESCRIPTOR(type %#x index %u) bad actual_length %d (requested %u)",
                        ext.busid(), type, index, n, len);
                return USBIP_ERROR_PROTOCOL;
        }

        if (n) {
                if (auto err = recv(ext.sock, pool, buf, static_cast<ULONG>(n))) {
                        Trace(TRACE_LEVEL_ERROR, "%!USTR!: recv GET_DESCRIPTOR(type %#x index %u) payload of %d bytes %!STATUS!",
                                ext.busid(), type, index, n, err);
                        return err;
                }
        }

        TraceDbg("%!USTR!: GET_DESCRIPTOR type %#x index %u returned %d bytes", ext.busid(), type, index, n);

        actual = static_cast<UINT16>(n);
        return STATUS_SUCCESS;
}

/*
 * Fetch and evaluate every interface of one configuration. Fail-closed on any error
 * or malformed descriptor.
 */
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED NTSTATUS check_configuration(
        _Inout_ device_ctx_ext &ext, _In_ const policy &p, _In_ const usbip_usb_device &udev,
        _Inout_ ULONG &seqnum, _In_ UINT8 cfg_index)
{
        PAGED_CODE();

        TraceDbg("%!USTR!: evaluating configuration %u of %u", ext.busid(), cfg_index, udev.bNumConfigurations);

        USB_CONFIGURATION_DESCRIPTOR head{};
        UINT16 got{};

        if (auto err = get_descriptor(ext, seqnum, USB_CONFIGURATION_DESCRIPTOR_TYPE, cfg_index,
                                      memory::stack, &head, sizeof(head), got)) {
                report_rejection(ext, udev, p, "config descriptor header fetch failed", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        if (got < sizeof(head) || !libdrv::is_valid(head)) {
                report_rejection(ext, udev, p, "invalid config descriptor", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        ULONG total = head.wTotalLength;
        if (total < sizeof(head) || total > MAX_CONFIG_DESCRIPTOR_SIZE) {
                report_rejection(ext, udev, p, "bad config wTotalLength", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        unique_ptr buf(NonPagedPoolNx, total);
        if (!buf) {
                report_rejection(ext, udev, p, "out of memory for config descriptor", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        UINT16 full{};
        if (auto err = get_descriptor(ext, seqnum, USB_CONFIGURATION_DESCRIPTOR_TYPE, cfg_index,
                                      memory::nonpaged, buf.get(), static_cast<UINT16>(total), full)) {
                report_rejection(ext, udev, p, "full config descriptor fetch failed", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        if (full < total) {
                report_rejection(ext, udev, p, "short config descriptor", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        auto base = buf.get<UCHAR>();
        auto end = base + full;
        unsigned interfaces = 0;

        for (auto cur = base; cur + sizeof(USB_COMMON_DESCRIPTOR) <= end; ) {

                auto d = reinterpret_cast<USB_COMMON_DESCRIPTOR*>(cur);

                if (d->bLength < sizeof(USB_COMMON_DESCRIPTOR) || cur + d->bLength > end) {
                        report_rejection(ext, udev, p, "malformed descriptor in configuration", -1, 0, 0, 0);
                        return USBIP_ERROR_DEVICE_FILTERED;
                }

                if (d->bDescriptorType == USB_INTERFACE_DESCRIPTOR_TYPE &&
                    d->bLength >= sizeof(USB_INTERFACE_DESCRIPTOR)) {

                        auto &id = *reinterpret_cast<USB_INTERFACE_DESCRIPTOR*>(d);
                        ++interfaces;

                        if (!is_allowed(p, id.bInterfaceClass, id.bInterfaceSubClass, id.bInterfaceProtocol)) {
                                report_rejection(ext, udev, p, "interface class not in whitelist",
                                        id.bInterfaceNumber, id.bInterfaceClass, id.bInterfaceSubClass,
                                        id.bInterfaceProtocol);
                                return USBIP_ERROR_DEVICE_FILTERED;
                        }

                        TraceDbg("%!USTR!: config %u interface %d class/sub/proto %02X/%02X/%02X (%s) allowed",
                                ext.busid(), cfg_index, id.bInterfaceNumber, id.bInterfaceClass,
                                id.bInterfaceSubClass, id.bInterfaceProtocol, usb_class_name(id.bInterfaceClass));
                }

                cur += d->bLength;
        }

        TraceDbg("%!USTR!: configuration %u passed (%u interface(s) checked)", ext.busid(), cfg_index, interfaces);

        return STATUS_SUCCESS;
}

} // namespace


_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED void usbip::device_filter::load(_Out_ policy &p)
{
        PAGED_CODE();

        RtlZeroMemory(&p, sizeof(p));
        p.mode = vhci::filter_mode::whitelist; // fail-closed default: empty whitelist denies all
        p.count = 0;

        Registry key;
        if (auto err = open(key, DriverRegKeyParameters)) {
                Trace(TRACE_LEVEL_WARNING, "open Parameters %!STATUS!, using fail-closed whitelist", err);
                return;
        }

        auto name = value_name();

        policy tmp;
        ULONG actual{};
        auto type = REG_NONE;

        auto st = WdfRegistryQueryValue(key.get(), &name, sizeof(tmp), &tmp, &actual, &type);
        if (st) {
                Trace(TRACE_LEVEL_INFORMATION, "no '%!USTR!' value (%!STATUS!), using fail-closed whitelist",
                        &name, st);
                return;
        }

        if (type != REG_BINARY || actual < FIELD_OFFSET(policy, entries)) {
                Trace(TRACE_LEVEL_WARNING, "'%!USTR!' has bad type/size (type %lu, %lu bytes), fail-closed",
                        &name, type, actual);
                return;
        }

        auto max_by_len = (actual - FIELD_OFFSET(policy, entries)) / sizeof(vhci::device_filter_entry);
        auto count = tmp.count;

        if (count > max_by_len) {
                count = static_cast<ULONG>(max_by_len);
        }
        if (count > vhci::ioctl::MAX_DEVICE_FILTER_ENTRIES) {
                count = vhci::ioctl::MAX_DEVICE_FILTER_ENTRIES;
        }

        p.mode = (tmp.mode == vhci::filter_mode::disabled) ? vhci::filter_mode::disabled
                                                           : vhci::filter_mode::whitelist;
        p.count = count;
        RtlCopyMemory(p.entries, tmp.entries, count * sizeof(vhci::device_filter_entry));

        Trace(TRACE_LEVEL_INFORMATION, "device-type filter loaded: mode %d, %lu entries",
                static_cast<int>(p.mode), p.count);
}

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED NTSTATUS usbip::device_filter::store(_In_ const policy &p)
{
        PAGED_CODE();

        policy tmp = p;
        if (tmp.count > vhci::ioctl::MAX_DEVICE_FILTER_ENTRIES) {
                tmp.count = vhci::ioctl::MAX_DEVICE_FILTER_ENTRIES;
        }
        if (tmp.mode != vhci::filter_mode::disabled) {
                tmp.mode = vhci::filter_mode::whitelist;
        }

        Registry key;
        if (auto err = open(key, DriverRegKeyParameters, KEY_SET_VALUE)) {
                return err;
        }

        auto name = value_name();
        auto len = static_cast<ULONG>(FIELD_OFFSET(policy, entries) +
                                      tmp.count * sizeof(vhci::device_filter_entry));

        auto st = WdfRegistryAssignValue(key.get(), &name, REG_BINARY, len, &tmp);
        if (st) {
                Trace(TRACE_LEVEL_ERROR, "WdfRegistryAssignValue('%!USTR!') %!STATUS!", &name, st);
        } else {
                Trace(TRACE_LEVEL_INFORMATION, "device-type filter stored: mode %d, %lu entries",
                        static_cast<int>(tmp.mode), tmp.count);
        }

        return st;
}

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
PAGED NTSTATUS usbip::device_filter::check_device(_Inout_ device_ctx_ext &ext, _In_ const usbip_usb_device &udev)
{
        PAGED_CODE();

        policy p;
        load(p);

        if (p.mode == vhci::filter_mode::disabled) {
                TraceDbg("%!USTR!:%!USTR!/%!USTR! VID_%04X&PID_%04X: device-type filter disabled, allow",
                        ext.node_name(), ext.service_name(), ext.busid(), udev.idVendor, udev.idProduct);
                return STATUS_SUCCESS;
        }

        Trace(TRACE_LEVEL_INFORMATION,
                "device-type filter: evaluating %!USTR!:%!USTR!/%!USTR! VID_%04X&PID_%04X "
                "(device class %02X/%02X/%02X %s, %u config(s)) against whitelist of %lu entrie(s)",
                ext.node_name(), ext.service_name(), ext.busid(), udev.idVendor, udev.idProduct,
                udev.bDeviceClass, udev.bDeviceSubClass, udev.bDeviceProtocol, usb_class_name(udev.bDeviceClass),
                udev.bNumConfigurations, p.count);

        // Device-descriptor class token (skip 0x00 = defined per interface, 0xEF = composite glue).
        if (udev.bDeviceClass && udev.bDeviceClass != 0xEF) {
                if (!is_allowed(p, udev.bDeviceClass, udev.bDeviceSubClass, udev.bDeviceProtocol)) {
                        report_rejection(ext, udev, p, "device class not in whitelist", -1,
                                udev.bDeviceClass, udev.bDeviceSubClass, udev.bDeviceProtocol);
                        return USBIP_ERROR_DEVICE_FILTERED;
                }
        }

        if (!udev.bNumConfigurations) {
                report_rejection(ext, udev, p, "device reports no configurations", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        ULONG seqnum = 1;

        for (UINT8 i = 0; i < udev.bNumConfigurations; ++i) {
                if (auto err = check_configuration(ext, p, udev, seqnum, i)) {
                        return err;
                }
        }

        Trace(TRACE_LEVEL_INFORMATION,
                "device-type filter: %!USTR!:%!USTR!/%!USTR! VID_%04X&PID_%04X ALLOWED (all %u config(s) passed the whitelist)",
                ext.node_name(), ext.service_name(), ext.busid(), udev.idVendor, udev.idProduct,
                udev.bNumConfigurations);

        return STATUS_SUCCESS;
}
