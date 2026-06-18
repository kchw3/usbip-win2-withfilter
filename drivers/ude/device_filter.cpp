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
 * Write an admin-visible Windows System Event Log entry plus a verbose WPP trace.
 * @param ifnum interface number, or -1 for device-level / global reasons
 */
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
void report_rejection(
        _In_ device_ctx_ext &ext, _In_ const usbip_usb_device &udev, _In_ const char *reason,
        _In_ int ifnum, _In_ UINT8 cls, _In_ UINT8 sub, _In_ UINT8 proto)
{
        Trace(TRACE_LEVEL_ERROR,
                "device-type filter REJECT %!USTR!:%!USTR!/%!USTR! vid %#06x pid %#06x, reason '%s', "
                "interface %d, class/sub/proto %02x/%02x/%02x",
                ext.node_name(), ext.service_name(), ext.busid(), udev.idVendor, udev.idProduct,
                reason, ifnum, cls, sub, proto);

        auto drvobj = WdfDriverWdmGetDriverObject(WdfGetDriver());
        if (!drvobj) {
                return;
        }

        // Keep the inserted string within ERROR_LOG_MAXIMUM_SIZE.
        constexpr USHORT max_str_bytes = ERROR_LOG_MAXIMUM_SIZE - sizeof(IO_ERROR_LOG_PACKET);
        constexpr size_t max_chars = max_str_bytes / sizeof(WCHAR);

        WCHAR msg[max_chars];
        auto st = RtlStringCchPrintfW(msg, RTL_NUMBER_OF(msg),
                L"Blocked VID_%04X&PID_%04X iface %d class %02X/%02X/%02X",
                udev.idVendor, udev.idProduct, ifnum, cls, sub, proto);

        if (st == STATUS_BUFFER_OVERFLOW) {
                msg[RTL_NUMBER_OF(msg) - 1] = L'\0'; // truncated copy is fine for logging
        } else if (NT_ERROR(st)) {
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

        if (auto err = send(ext.sock, memory::stack, &hdr, sizeof(hdr))) {
                Trace(TRACE_LEVEL_ERROR, "send CMD_SUBMIT %!STATUS!", err);
                return err;
        }

        header rep{};
        if (auto err = recv(ext.sock, memory::stack, &rep, sizeof(rep))) {
                Trace(TRACE_LEVEL_ERROR, "recv RET_SUBMIT header %!STATUS!", err);
                return err;
        }
        byteswap_header(rep, swap_dir::net2host);

        if (rep.command != RET_SUBMIT) {
                Trace(TRACE_LEVEL_ERROR, "unexpected command %#x", rep.command);
                return USBIP_ERROR_PROTOCOL;
        }

        if (auto status = rep.ret_submit.status) {
                Trace(TRACE_LEVEL_ERROR, "RET_SUBMIT status %d", status);
                return USBIP_ERROR_GENERAL;
        }

        auto n = rep.ret_submit.actual_length;
        if (n < 0 || static_cast<ULONG>(n) > len) {
                Trace(TRACE_LEVEL_ERROR, "bad actual_length %d (len %u)", n, len);
                return USBIP_ERROR_PROTOCOL;
        }

        if (n) {
                if (auto err = recv(ext.sock, pool, buf, static_cast<ULONG>(n))) {
                        Trace(TRACE_LEVEL_ERROR, "recv descriptor payload %!STATUS!", err);
                        return err;
                }
        }

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

        USB_CONFIGURATION_DESCRIPTOR head{};
        UINT16 got{};

        if (auto err = get_descriptor(ext, seqnum, USB_CONFIGURATION_DESCRIPTOR_TYPE, cfg_index,
                                      memory::stack, &head, sizeof(head), got)) {
                report_rejection(ext, udev, "config descriptor fetch failed", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        if (got < sizeof(head) || !libdrv::is_valid(head)) {
                report_rejection(ext, udev, "invalid config descriptor", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        ULONG total = head.wTotalLength;
        if (total < sizeof(head) || total > MAX_CONFIG_DESCRIPTOR_SIZE) {
                report_rejection(ext, udev, "bad config wTotalLength", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        unique_ptr buf(NonPagedPoolNx, total);
        if (!buf) {
                report_rejection(ext, udev, "out of memory for config descriptor", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        UINT16 full{};
        if (auto err = get_descriptor(ext, seqnum, USB_CONFIGURATION_DESCRIPTOR_TYPE, cfg_index,
                                      memory::nonpaged, buf.get(), static_cast<UINT16>(total), full)) {
                report_rejection(ext, udev, "full config descriptor fetch failed", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        if (full < total) {
                report_rejection(ext, udev, "short config descriptor", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        auto base = buf.get<UCHAR>();
        auto end = base + full;

        for (auto cur = base; cur + sizeof(USB_COMMON_DESCRIPTOR) <= end; ) {

                auto d = reinterpret_cast<USB_COMMON_DESCRIPTOR*>(cur);

                if (d->bLength < sizeof(USB_COMMON_DESCRIPTOR) || cur + d->bLength > end) {
                        report_rejection(ext, udev, "malformed descriptor in configuration", -1, 0, 0, 0);
                        return USBIP_ERROR_DEVICE_FILTERED;
                }

                if (d->bDescriptorType == USB_INTERFACE_DESCRIPTOR_TYPE &&
                    d->bLength >= sizeof(USB_INTERFACE_DESCRIPTOR)) {

                        auto &id = *reinterpret_cast<USB_INTERFACE_DESCRIPTOR*>(d);

                        if (!is_allowed(p, id.bInterfaceClass, id.bInterfaceSubClass, id.bInterfaceProtocol)) {
                                report_rejection(ext, udev, "interface class not in whitelist",
                                        id.bInterfaceNumber, id.bInterfaceClass, id.bInterfaceSubClass,
                                        id.bInterfaceProtocol);
                                return USBIP_ERROR_DEVICE_FILTERED;
                        }

                        TraceDbg("device-type filter: interface %d class/sub/proto %02x/%02x/%02x allowed",
                                id.bInterfaceNumber, id.bInterfaceClass, id.bInterfaceSubClass,
                                id.bInterfaceProtocol);
                }

                cur += d->bLength;
        }

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
                TraceDbg("device-type filter disabled, allow");
                return STATUS_SUCCESS;
        }

        // Device-descriptor class token (skip 0x00 = defined per interface, 0xEF = composite glue).
        if (udev.bDeviceClass && udev.bDeviceClass != 0xEF) {
                if (!is_allowed(p, udev.bDeviceClass, udev.bDeviceSubClass, udev.bDeviceProtocol)) {
                        report_rejection(ext, udev, "device class not in whitelist", -1,
                                udev.bDeviceClass, udev.bDeviceSubClass, udev.bDeviceProtocol);
                        return USBIP_ERROR_DEVICE_FILTERED;
                }
        }

        if (!udev.bNumConfigurations) {
                report_rejection(ext, udev, "device reports no configurations", -1, 0, 0, 0);
                return USBIP_ERROR_DEVICE_FILTERED;
        }

        ULONG seqnum = 1;

        for (UINT8 i = 0; i < udev.bNumConfigurations; ++i) {
                if (auto err = check_configuration(ext, p, udev, seqnum, i)) {
                        return err;
                }
        }

        Trace(TRACE_LEVEL_INFORMATION, "device-type filter: %!USTR!/%!USTR! allowed (vid %#06x pid %#06x)",
                ext.node_name(), ext.busid(), udev.idVendor, udev.idProduct);

        return STATUS_SUCCESS;
}
