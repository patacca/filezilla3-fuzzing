#include "../filezilla.h"
#include "../Options.h"
#include "settingsdialog.h"
#include "optionspage.h"
#include "optionspage_language.h"
#include "../filezillaapp.h"
#include <algorithm>

#include <wx/listbox.h>
#include <wx/statbox.h>

bool COptionsPageLanguage::CreateControls(wxWindow* parent)
{
	auto const& lay = m_pOwner->layout();

	Create(parent);
	auto main = lay.createFlex(1);
	main->AddGrowableCol(0);
	main->AddGrowableRow(0);
	SetSizer(main);

	auto [box, inner] = lay.createStatBox(main, _("&Select language:"), 1);
	inner->AddGrowableRow(0);
	lb_ = new wxListBox(box, nullID, wxDefaultPosition, wxDefaultSize, wxArrayString(), wxLB_SINGLE | wxLB_NEEDED_SB);
	inner->Add(lb_, lay.grow);
	inner->Add(new wxStaticText(box, nullID, _("If you change the language, you need to restart FileZilla.")));

	return true;
}

bool COptionsPageLanguage::LoadPage()
{
	return true;
}

bool COptionsPageLanguage::SavePage()
{
	if (!m_was_selected) {
		return true;
	}

	if (lb_->GetSelection() == wxNOT_FOUND) {
		return true;
	}

	const int selection = lb_->GetSelection();
	std::wstring code;
	if (selection > 0) {
		code = locales_[selection - 1].code;
	}

	m_pOptions->set(OPTION_LANGUAGE, code);

	return true;
}

bool COptionsPageLanguage::Validate()
{
	return true;
}

bool COptionsPageLanguage::OnDisplayedFirstTime()
{
	std::wstring currentLanguage = m_pOptions->get_string(OPTION_LANGUAGE);

	lb_->Clear();

	const wxString defaultName = _("Default system language");
	int n = lb_->Append(defaultName);
	if (currentLanguage.empty()) {
		lb_->SetSelection(n);
	}

	GetLocales();

	for (auto const& locale : locales_) {
		n = lb_->Append(locale.name + _T(" (") + locale.code + _T(")"));
		if (locale.code == currentLanguage) {
			lb_->SetSelection(n);
		}
	}
	lb_->GetContainingSizer()->Layout();

	return true;
}

void COptionsPageLanguage::GetLocales()
{
}
