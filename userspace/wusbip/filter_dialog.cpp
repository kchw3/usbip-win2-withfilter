/*
 * Copyright (c) 2026 Kelvin Wu
 */

#include "filter_dialog.h"

#include <wx/checkbox.h>
#include <wx/checklst.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/statline.h>
#include <wx/arrstr.h>

#include <algorithm>

namespace
{

auto contains(const std::vector<usbip::device_filter_entry> &v, const usbip::device_filter_entry &e)
{
        return std::find(v.begin(), v.end(), e) != v.end();
}

auto category_enabled(const usbip::device_filter_policy &p, const usbip::device_type_category &c)
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

} // namespace


FilterDialog::FilterDialog(_In_ wxWindow *parent, _In_ const usbip::device_filter_policy &policy) :
        wxDialog(parent, wxID_ANY, _("Device type filter"), wxDefaultPosition, wxSize(420, 460),
                 wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER),
        m_categories(usbip::device_type_categories())
{
        auto top = new wxBoxSizer(wxVERTICAL);

        auto intro = new wxStaticText(this, wxID_ANY, _(
                "Only the device types checked below are allowed to attach.\n"
                "A device is allowed only if every one of its USB interface classes is checked\n"
                "(this is enforced in the driver, before the device is shown to Windows)."));
        top->Add(intro, wxSizerFlags().Border(wxALL));

        m_enable = new wxCheckBox(this, wxID_ANY, _("Enable device-type filtering (whitelist)"));
        m_enable->SetValue(policy.mode != usbip::filter_mode::disabled);
        top->Add(m_enable, wxSizerFlags().Border(wxLEFT | wxRIGHT | wxBOTTOM));

        m_enable->Bind(wxEVT_CHECKBOX, &FilterDialog::on_enable, this);

        top->Add(new wxStaticLine(this), wxSizerFlags().Expand().Border(wxLEFT | wxRIGHT));

        auto label = new wxStaticText(this, wxID_ANY, _("Allowed device types:"));
        top->Add(label, wxSizerFlags().Border(wxALL));

        wxArrayString names;
        for (auto &c: m_categories) {
                names.Add(wxString::FromUTF8(c.name));
        }

        m_list = new wxCheckListBox(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, names);
        for (unsigned i = 0; i < m_categories.size(); ++i) {
                m_list->Check(i, category_enabled(policy, m_categories[i]));
        }
        top->Add(m_list, wxSizerFlags(1).Expand().Border(wxLEFT | wxRIGHT | wxBOTTOM));

        auto warn = new wxStaticText(this, wxID_ANY, _(
                "Note: leaving everything unchecked denies all devices (fail-closed)."));
        top->Add(warn, wxSizerFlags().Border(wxLEFT | wxRIGHT | wxBOTTOM));

        if (auto buttons = CreateButtonSizer(wxOK | wxCANCEL)) {
                top->Add(buttons, wxSizerFlags().Expand().Border(wxALL));
        }

        SetSizer(top);
        update_enabled_state();
}

void FilterDialog::on_enable(wxCommandEvent&)
{
        update_enabled_state();
}

void FilterDialog::update_enabled_state()
{
        m_list->Enable(m_enable->IsChecked());
}

usbip::device_filter_policy FilterDialog::policy() const
{
        usbip::device_filter_policy p;

        if (!m_enable->IsChecked()) {
                p.mode = usbip::filter_mode::disabled;
                return p;
        }

        p.mode = usbip::filter_mode::whitelist;

        for (unsigned i = 0; i < m_categories.size(); ++i) {
                if (!m_list->IsChecked(i)) {
                        continue;
                }
                for (auto &e: m_categories[i].entries) {
                        if (!contains(p.entries, e)) {
                                p.entries.push_back(e);
                        }
                }
        }

        return p;
}
