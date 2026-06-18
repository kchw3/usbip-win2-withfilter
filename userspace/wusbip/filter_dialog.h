/*
 * Copyright (c) 2026 Kelvin Wu
 */

#pragma once

#include <libusbip/vhci.h>

#include <wx/dialog.h>

class wxCheckBox;
class wxCheckListBox;

/*
 * Modal dialog to view/edit the device-type (USB class) whitelist.
 *
 * Presents a checkbox to enable/disable filtering and a checklist of the well-known
 * device-type categories (HID, mass storage, network, ...). On OK, policy() returns the
 * resulting whitelist which the caller stores via usbip::vhci::set_device_filter().
 */
class FilterDialog : public wxDialog
{
public:
        FilterDialog(_In_ wxWindow *parent, _In_ const usbip::device_filter_policy &policy);

        usbip::device_filter_policy policy() const;

private:
        wxCheckBox *m_enable{};
        wxCheckListBox *m_list{};
        std::vector<usbip::device_type_category> m_categories;

        void on_enable(wxCommandEvent &event);
        void update_enabled_state();
};
