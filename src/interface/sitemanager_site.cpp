#include "filezilla.h"
#include "sitemanager_site.h"

#include "filezillaapp.h"
#include "Options.h"
#include "sitemanager_controls.h"
#include "sitemanager_dialog.h"
#include "textctrlex.h"
#include "xrc_helper.h"

#include "../include/s3sse.h"

#include <libfilezilla/translate.hpp>

#include <wx/dcclient.h>
#include <wx/gbsizer.h>
#include <wx/statline.h>
#include <wx/wupdlock.h>

#ifdef __WXMSW__
#include "commctrl.h"
#endif

CSiteManagerSite::CSiteManagerSite(CSiteManagerDialog &sitemanager)
    : sitemanager_(sitemanager)
{
}

bool CSiteManagerSite::Load(wxWindow* parent)
{
}

void CSiteManagerSite::SetControlVisibility(ServerProtocol protocol, LogonType type)
{
	for (auto & controls : controls_) {
		controls->SetPredefined(predefined_);
		controls->SetControlVisibility(protocol, type);
	}

	if (charsetPage_) {
		if (CServer::ProtocolHasFeature(protocol, ProtocolFeature::Charset)) {
			if (FindPage(charsetPage_) == wxNOT_FOUND) {
				AddPage(charsetPage_, m_charsetPageText);
			}
		}
		else {
			int const charsetPageIndex = FindPage(charsetPage_);
			if (charsetPageIndex != wxNOT_FOUND) {
				RemovePage(charsetPageIndex);
			}
		}
	}

	if (s3Page_) {
		if (protocol == S3) {
			if (FindPage(s3Page_) == wxNOT_FOUND) {
				AddPage(s3Page_, L"S3");
			}
		}
		else {
			int const s3pageIndex = FindPage(s3Page_);
			if (s3pageIndex != wxNOT_FOUND) {
				RemovePage(s3pageIndex);
			}
		}
	}

	GetPage(0)->GetSizer()->Fit(GetPage(0));
}


bool CSiteManagerSite::UpdateSite(Site &site, bool silent)
{
	for (auto & controls : controls_) {
		if (!controls->UpdateSite(site, silent)) {
			return false;
		}
	}

	site.comments_ = xrc_call(*this, "ID_COMMENTS", &wxTextCtrl::GetValue).ToStdWstring();
	site.m_colour = CSiteManager::GetColourFromIndex(xrc_call(*this, "ID_COLOR", &wxChoice::GetSelection));

	return true;
}

void CSiteManagerSite::SetSite(Site const& site, bool predefined)
{
	predefined_ = predefined;

	if (site) {
		SetControlVisibility(site.server.GetProtocol(), site.credentials.logonType_);
	}
	else {
		bool const kiosk_mode = COptions::Get()->get_int(OPTION_DEFAULT_KIOSKMODE) != 0;
		auto const logonType = kiosk_mode ? LogonType::ask : LogonType::normal;
		SetControlVisibility(FTP, logonType);
	}

	xrc_call(*this, "ID_COLOR", &wxWindow::Enable, !predefined);
	xrc_call(*this, "ID_COMMENTS", &wxWindow::Enable, !predefined);

	for (auto & controls : controls_) {
		controls->SetSite(site);
		controls->SetControlState();
	}

	if (!site) {
		xrc_call(*this, "ID_COMMENTS", &wxTextCtrl::ChangeValue, wxString());
		xrc_call(*this, "ID_COLOR", &wxChoice::Select, 0);
	}
	else {
		xrc_call(*this, "ID_COMMENTS", &wxTextCtrl::ChangeValue, site.comments_);
		xrc_call(*this, "ID_COLOR", &wxChoice::Select, CSiteManager::GetColourIndex(site.m_colour));
	}
}
