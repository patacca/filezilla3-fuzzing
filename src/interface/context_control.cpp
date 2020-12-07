#include "filezilla.h"
#include "cmdline.h"
#include "commandqueue.h"
#include "context_control.h"
#include "filelist_statusbar.h"
#include "filezillaapp.h"
#include "list_search_panel.h"
#include "local_recursive_operation.h"
#include "LocalListView.h"
#include "LocalTreeView.h"
#include "Mainfrm.h"
#include "Options.h"
#include "queue.h"
#include "remote_recursive_operation.h"
#include "recursive_operation_status.h"
#include "RemoteListView.h"
#include "RemoteTreeView.h"
#include "sitemanager.h"
#include "splitter.h"
#include "view.h"
#include "viewheader.h"
#include "xmlfunctions.h"

#ifdef USE_MAC_SANDBOX
#include "osx_sandbox_userdirs.h"
#endif

#include <wx/menu.h>
#include <wx/wupdlock.h>

#include <array>

wxDECLARE_EVENT(fzEVT_TAB_CLOSING_DEFERRED, wxCommandEvent);
wxDEFINE_EVENT(fzEVT_TAB_CLOSING_DEFERRED, wxCommandEvent);

BEGIN_EVENT_TABLE(CContextControl, wxSplitterWindow)
EVT_MENU(XRCID("ID_TABCONTEXT_REFRESH"), CContextControl::OnTabRefresh)
EVT_COMMAND(wxID_ANY, fzEVT_TAB_CLOSING_DEFERRED, CContextControl::OnTabClosing_Deferred)
EVT_MENU(XRCID("ID_TABCONTEXT_CLOSE"), CContextControl::OnTabContextClose)
EVT_MENU(XRCID("ID_TABCONTEXT_CLOSEOTHERS"), CContextControl::OnTabContextCloseOthers)
EVT_MENU(XRCID("ID_TABCONTEXT_NEW"), CContextControl::OnTabContextNew)
END_EVENT_TABLE()

CContextControl::CContextControl(CMainFrame& mainFrame)
	: m_mainFrame(mainFrame)
{
	wxASSERT(!CContextManager::Get()->HandlerCount(STATECHANGE_CHANGEDCONTEXT));
	CContextManager::Get()->RegisterHandler(this, STATECHANGE_CHANGEDCONTEXT, false);
	CContextManager::Get()->RegisterHandler(this, STATECHANGE_SERVER, false);
	CContextManager::Get()->RegisterHandler(this, STATECHANGE_REWRITE_CREDENTIALS, false);
}

CContextControl::~CContextControl()
{
}

void CContextControl::Create(wxWindow *parent)
{
	wxSplitterWindow::Create(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSP_NOBORDER);
}

bool CContextControl::CreateTab()
{
	CLocalPath localPath;
	Site site;
	CServerPath remotePath;

	auto const* controls = GetCurrentControls();
	if (controls && controls->pState) {
		localPath = controls->pState->GetLocalDir();
		site = controls->pState->GetLastSite();
		remotePath = controls->pState->GetLastServerPath();
	}
	return CreateTab(localPath, site, remotePath);
}

bool CContextControl::CreateTab(CLocalPath const& localPath, Site const& site, CServerPath const& remotePath)
{
	return true;
}

void CContextControl::CreateContextControls(CState& state)
{
}

void CContextControl::OnTabRefresh(wxCommandEvent&)
{
	if (m_right_clicked_tab == -1) {
		return;
	}

	auto * controls = GetControlsFromTabIndex(m_right_clicked_tab);
	if (controls) {
		controls->pState->RefreshLocal();
		controls->pState->RefreshRemote();
	}
}

 CContextControl::_context_controls* CContextControl::GetCurrentControls()
{
	if (m_current_context_controls == -1) {
		return 0;
	}

	return &m_context_controls[m_current_context_controls];
}

CContextControl::_context_controls* CContextControl::GetControlsFromState(CState* pState)
{
	size_t i = 0;
	for (i = 0; i < m_context_controls.size(); ++i) {
		if (m_context_controls[i].pState == pState) {
			return &m_context_controls[i];
		}
	}
	return 0;
}

bool CContextControl::CloseTab(int tab)
{
	if (!m_tabs) {
		return false;
	}
	if (tab < 0 || static_cast<size_t>(tab) >= m_tabs->GetPageCount()) {
		return false;
	}


	auto *const removeControls = GetControlsFromTabIndex(tab);

	CState *const pState = removeControls->pState;

	if (!pState->m_pCommandQueue->Idle()) {
		if (wxMessageBoxEx(_("Cannot close tab while busy.\nCancel current operation and close tab?"), _T("FileZilla"), wxYES_NO | wxICON_QUESTION) != wxYES) {
			return false;
		}
	}

#ifndef __WXMAC__
	// Some reparenting is being done when closing tabs. Reparenting of frozen windows isn't working
	// on OS X.
	wxWindowUpdateLocker lock(this);
#endif

	pState->m_pCommandQueue->Cancel();
	pState->GetLocalRecursiveOperation()->StopRecursiveOperation();
	pState->GetRemoteRecursiveOperation()->StopRecursiveOperation();

	pState->GetComparisonManager()->SetListings(0, 0);

	if (m_tabs->GetPageCount() == 2) {
		// Get rid again of tab bar
		m_tabs->Disconnect(wxEVT_COMMAND_AUINOTEBOOK_PAGE_CHANGED, wxAuiNotebookEventHandler(CContextControl::OnTabChanged), 0, this);

		int keep = tab ? 0 : 1;

		auto * keptControls = GetControlsFromTabIndex(keep);
		m_tabs->RemovePage(keep);

		CContextManager::Get()->SetCurrentContext(keptControls->pState);

		keptControls->pViewSplitter->Reparent(this);
		ReplaceWindow(m_tabs, keptControls->pViewSplitter);
		keptControls->pViewSplitter->Show();

		wxAuiNotebookEx *tabs = m_tabs;
		m_tabs = 0;

		// We don't actually delete the controls outselves, that's done by wx as part of the RemovePage call.
		removeControls->pViewSplitter = 0;

		CContextManager::Get()->SetCurrentContext(keptControls->pState);

		tabs->Destroy();
	}
	else {
		if (pState == CContextManager::Get()->GetCurrentContext()) {
			int newsel = tab + 1;
			if (newsel >= (int)m_tabs->GetPageCount()) {
				newsel = m_tabs->GetPageCount() - 2;
			}

			m_tabs->SetSelection(newsel);
			CContextManager::Get()->SetCurrentContext(GetControlsFromTabIndex(newsel)->pState);
		}

		removeControls->pViewSplitter = 0;
		m_tabs->DeletePage(tab);
	}

	pState->Disconnect();

	return true;
}

void CContextControl::OnTabBgDoubleclick(wxAuiNotebookEvent&)
{
	CreateTab();
}

void CContextControl::OnTabRightclick(wxAuiNotebookEvent& event)
{
	wxMenu menu;
	menu.Append(XRCID("ID_TABCONTEXT_NEW"), _("&Create new tab"));

	menu.AppendSeparator();
	menu.Append(XRCID("ID_TABCONTEXT_CLOSE"), _("Cl&ose tab"));
	menu.Append(XRCID("ID_TABCONTEXT_CLOSEOTHERS"), _("Close &all other tabs"));

	menu.AppendSeparator();
	menu.Append(XRCID("ID_TABCONTEXT_REFRESH"), _("&Refresh"));

	if (!m_tabs || m_tabs->GetPageCount() < 2) {
		menu.Enable(XRCID("ID_TABCONTEXT_CLOSE"), false);
		menu.Enable(XRCID("ID_TABCONTEXT_CLOSEOTHERS"), false);
	}

	m_right_clicked_tab = event.GetSelection();

	PopupMenu(&menu);
}

void CContextControl::OnTabContextClose(wxCommandEvent&)
{
	if (m_right_clicked_tab == -1) {
		return;
	}

	// Need to defer event, wxAUI would write to free'd memory
	// if we'd actually delete tab and potenially the notebook with it
	QueueEvent(new wxCommandEvent(fzEVT_TAB_CLOSING_DEFERRED, m_right_clicked_tab));
}

void CContextControl::OnTabContextCloseOthers(wxCommandEvent&)
{
	QueueEvent(new wxCommandEvent (fzEVT_TAB_CLOSING_DEFERRED, -m_right_clicked_tab - 1));
}

void CContextControl::OnTabClosing_Deferred(wxCommandEvent& event)
{
	int tab = event.GetId();
	if (tab < 0) {
		++tab;
		int count = GetTabCount();
		for (int i = count - 1; i >= 0; --i) {
			if (i != -tab) {
				CloseTab(i);
			}
		}
	}
	else {
		CloseTab(tab);
	}
}


void CContextControl::OnTabChanged(wxAuiNotebookEvent&)
{
	int i = m_tabs->GetSelection();
	auto * const controls = GetControlsFromTabIndex(i);
	if (!controls) {
		return;
	}

	CContextManager::Get()->SetCurrentContext(controls->pState);
}

void CContextControl::OnTabClosing(wxAuiNotebookEvent& event)
{
	// Need to defer event, wxAUI would write to free'd memory
	// if we'd actually delete tab and potenially the notebook with it
	QueueEvent(new wxCommandEvent(fzEVT_TAB_CLOSING_DEFERRED, event.GetSelection()));

	event.Veto();
}

int CContextControl::GetCurrentTab() const
{
	return m_tabs ? m_tabs->GetSelection() : (m_context_controls.empty() ? -1 : 0);
}

int CContextControl::GetTabCount() const
{
	return m_tabs ? m_tabs->GetPageCount() : (m_context_controls.empty() ? 0 : 1);
}

CContextControl::_context_controls* CContextControl::GetControlsFromTabIndex(int i)
{
	if (!m_tabs) {
		if (i == 0 && !m_context_controls.empty()) {
			for (auto & controls : m_context_controls) {
				if (controls.pViewSplitter != 0) {
					return &controls;
				}
			}
		}
		return 0;
	}

	wxWindow* page = m_tabs->GetPage(i);
	if (page) {
		for (auto & controls : m_context_controls) {
			if (controls.pViewSplitter == page) {
				return &controls;
			}
		}
	}

	return 0;
}

bool CContextControl::SelectTab(int i)
{
	if (i < 0) {
		return false;
	}

	if (!m_tabs) {
		if (i != 0) {
			return false;
		}

		return true;
	}

	if ((int)m_tabs->GetPageCount() <= i) {
		return false;
	}

	m_tabs->SetSelection(i);

	return true;
}

void CContextControl::AdvanceTab(bool forward)
{
	if (!m_tabs) {
		return;
	}

	m_tabs->AdvanceTab(forward);
}

void CContextControl::OnStateChange(CState* pState, t_statechange_notifications notification, std::wstring const&, const void*)
{
	if (notification == STATECHANGE_CHANGEDCONTEXT) {
		if (!pState) {
			m_current_context_controls = m_context_controls.empty() ? -1 : 0;
			return;
		}

		// Get current controls for new current context
		for (m_current_context_controls = 0; m_current_context_controls < static_cast<int>(m_context_controls.size()); ++m_current_context_controls) {
			if (m_context_controls[m_current_context_controls].pState == pState) {
				break;
			}
		}
		if (m_current_context_controls == static_cast<int>(m_context_controls.size())) {
			m_current_context_controls = -1;
		}
	}
	else if (notification == STATECHANGE_SERVER) {
		if (!m_tabs) {
			return;
		}

		CContextControl::_context_controls* controls = GetControlsFromState(pState);
		if (controls && controls->used()) {
			int i = m_tabs->GetPageIndex(controls->pViewSplitter);
			if (i != wxNOT_FOUND) {
				m_tabs->SetTabColour(i, controls->pState->GetSite().m_colour);
				m_tabs->SetPageText(i, controls->pState->GetTitle());
			}
		}
	}
	else if (notification == STATECHANGE_REWRITE_CREDENTIALS) {
		SaveTabs();
	}
}

void CContextControl::OnTabContextNew(wxCommandEvent&)
{
	CreateTab();
}

void CContextControl::SaveTabs()
{
	pugi::xml_document xml;
	auto tabs = xml.append_child("Tabs");

	int const currentTab = GetCurrentTab();

	for (int i = 0; i < GetTabCount(); ++i) {
		auto controls = GetControlsFromTabIndex(i);
		if (!controls || !controls->pState) {
			continue;
		}

		Site const site = controls->pState->GetLastSite();

		auto tab = tabs.append_child("Tab");
		SetServer(tab, site);
		tab.append_child("Site").text().set(fz::to_utf8(site.SitePath()).c_str());
		tab.append_child("RemotePath").text().set(fz::to_utf8(controls->pState->GetLastServerPath().GetSafePath()).c_str());
		tab.append_child("LocalPath").text().set(fz::to_utf8(controls->pState->GetLocalDir().GetPath()).c_str());

		if (controls->pState->IsRemoteConnected()) {
			tab.append_attribute("connected").set_value(1);
		}
		if (i == currentTab) {
			tab.append_attribute("selected").set_value(1);
		}
	}

	COptions::Get()->set(OPTION_TAB_DATA, xml);
}

void CContextControl::RestoreTabs()
{
}

namespace {
bool SwitchFocus(wxWindow *focus, wxWindow *first, wxWindow *second)
{
	if (focus == first) {
		if (second && second->IsShownOnScreen() && second->IsEnabled()) {
			second->SetFocus();
		}
		return true;
	}
	return false;
}
}

void CContextControl::_context_controls::SwitchFocusedSide()
{
	std::array<std::pair<wxWindow*, wxWindow*>, 3> ctrls =
	{{
		{pLocalListView, pRemoteListView},
		{pLocalTreeView, pRemoteTreeView},
		{pLocalViewHeader, pRemoteViewHeader}
	}};
	auto *focus = wxWindow::FindFocus();
	while (focus) {
		for (auto & p : ctrls) {
			if (SwitchFocus(focus, p.first, p.second)) {
					return;
			}
			if (SwitchFocus(focus, p.second, p.first)) {
					return;
			}
		}
		focus = focus->GetParent();
	}
}

std::tuple<double, int, int> CContextControl::_context_controls::GetSplitterPositions()
{
	std::tuple<double, int, int> ret;

	std::get<0>(ret) = pViewSplitter ? pViewSplitter->GetRelativeSashPosition() : 0.5f;
	std::get<1>(ret) = pLocalSplitter ? pLocalSplitter->GetSashPosition() : 135;
	std::get<2>(ret) = pRemoteSplitter ? pRemoteSplitter->GetSashPosition() : 135;

	return ret;
}

void CContextControl::_context_controls::SetSplitterPositions(std::tuple<double, int, int> const& positions)
{
	if (pViewSplitter) {
		double pos = std::get<0>(positions);
		if (pos < 0 || pos > 1) {
			pos = 0.5;
		}
		pViewSplitter->SetRelativeSashPosition(pos);
	}
	if (pLocalSplitter) {
		pLocalSplitter->SetSashPosition(std::get<1>(positions));
	}
	if (pRemoteSplitter) {
		pRemoteSplitter->SetSashPosition(std::get<2>(positions));
	}
}
