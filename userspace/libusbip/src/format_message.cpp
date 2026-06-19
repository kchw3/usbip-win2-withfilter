/*
 * Copyright (c) 2022-2026 Vadym Hrynchyshyn <vadimgrn@gmail.com>
 */
#include "..\format_message.h"
#include "strconv.h"

#include <memory>
#include <format>
#include <cwctype>

namespace
{

/*
 * This module always formats with FORMAT_MESSAGE_IGNORE_INSERTS and never supplies
 * insertion strings, so any "%n" placeholder left in the text is display noise.
 * Strip trailing placeholders (and the whitespace around them) so messages whose
 * detail is only filled in elsewhere - e.g. USBIP_ERROR_DEVICE_FILTERED, whose "%2"
 * is supplied by the kernel event-log packet - render cleanly in the GUI.
 */
void strip_trailing_inserts(_Inout_ std::wstring &s)
{
        for (bool changed = true; changed; ) {
                changed = false;

                while (!s.empty() && std::iswspace(s.back())) {
                        s.pop_back();
                        changed = true;
                }

                auto n = s.size();
                while (n && std::iswdigit(s[n - 1])) {
                        --n;
                }

                if (n < s.size() && n && s[n - 1] == L'%') {
                        s.resize(n - 1);
                        changed = true;
                }
        }
}

} // namespace

std::wstring usbip::wformat_message(
        _In_ DWORD flags, _In_opt_ HMODULE module, _In_ DWORD msg_id, _In_ DWORD lang_id)
{
        std::wstring msg;

        flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS |
                 FORMAT_MESSAGE_MAX_WIDTH_MASK; // do not append '\n'

        if (LPWSTR buf{}; auto cch = FormatMessageW(flags, module, msg_id, lang_id, (LPWSTR)&buf, 0, nullptr)) {
                std::unique_ptr<void, decltype(LocalFree)&> buf_ptr(buf, LocalFree);
                msg.assign(buf, cch);
                strip_trailing_inserts(msg);
        } else {
                msg = std::format(L"FormatMessageW error {:#x}", GetLastError());
        }

        return msg;
}

std::string usbip::format_message(_In_ DWORD msg_id, _In_ DWORD lang_id) 
{ 
        auto ws = wformat_message(msg_id, lang_id);
        return wchar_to_utf8_or(ws);
}

std::string usbip::format_message(_In_opt_ HMODULE module, _In_ DWORD msg_id, _In_ DWORD lang_id)
{
        auto ws = wformat_message(module, msg_id, lang_id);
        return wchar_to_utf8_or(ws);
}
