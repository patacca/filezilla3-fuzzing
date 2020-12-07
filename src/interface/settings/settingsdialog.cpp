#include "../filezilla.h"
#include "settingsdialog.h"
#include "../Options.h"
#include "optionspage.h"
#include "optionspage_connection.h"
#include "optionspage_connection_ftp.h"
#include "optionspage_connection_active.h"
#include "optionspage_connection_passive.h"
#include "optionspage_ftpproxy.h"
#include "optionspage_connection_sftp.h"
#include "optionspage_filetype.h"
#include "optionspage_fileexists.h"
#include "optionspage_themes.h"
#include "optionspage_language.h"
#include "optionspage_transfer.h"
#include "optionspage_updatecheck.h"
#include "optionspage_logging.h"
#include "optionspage_debug.h"
#include "optionspage_interface.h"
#include "optionspage_dateformatting.h"
#include "optionspage_sizeformatting.h"
#include "optionspage_edit.h"
#include "optionspage_edit_associations.h"
#include "optionspage_passwords.h"
#include "optionspage_proxy.h"
#include "optionspage_filelists.h"
#include "../filezillaapp.h"
#include "../Mainfrm.h"
#include "../treectrlex.h"

CSettingsDialog::CSettingsDialog(CFileZillaEngineContext & engine_context)
	: m_engine_context(engine_context)
{
	m_pOptions = COptions::Get();
}

CSettingsDialog::~CSettingsDialog()
{
	m_activePanel = nullptr;
	m_pages.clear();

	if (tree_) {
		// Trees can generate these events during destruction, not good.
		tree_->Unbind(wxEVT_TREE_SEL_CHANGING, &CSettingsDialog::OnPageChanging, this);
		tree_->Unbind(wxEVT_TREE_SEL_CHANGED, &CSettingsDialog::OnPageChanged, this);
	}
}

bool CSettingsDialog::Create(CMainFrame* pMainFrame)
{
	m_pMainFrame = pMainFrame;

	SetExtraStyle(wxWS_EX_BLOCK_EVENTS);
	if (!wxDialogEx::Create(pMainFrame, nullID, _("Settings"))) {
		return false;
	}

	auto & lay = layout();
	auto * main = lay.createMain(this, 2);
	main->AddGrowableRow(0);

	auto* left = lay.createFlex(1);
	left->AddGrowableRow(1);
	main->Add(left, 1, wxGROW);

	left->Add(new wxStaticText(this, nullID, _("Select &page:")));

	tree_ = new wxTreeCtrlEx(this, nullID, wxDefaultPosition, wxDefaultSize, DEFAULT_TREE_STYLE | wxTR_HIDE_ROOT);
	tree_->SetFocus();
	left->Add(tree_, 1, wxGROW);

	auto ok = new wxButton(this, wxID_OK, _("OK"));
	ok->Bind(wxEVT_BUTTON, &CSettingsDialog::OnOK, this);
	ok->SetDefault();
	left->Add(ok, lay.grow);
	auto cancel = new wxButton(this, wxID_CANCEL, _("Cancel"));
	cancel->Bind(wxEVT_BUTTON, &CSettingsDialog::OnCancel, this);
	left->Add(cancel, lay.grow);

	pagePanel_ = new wxPanel(this);
	main->Add(pagePanel_, lay.grow);

	tree_->Bind(wxEVT_TREE_SEL_CHANGING, &CSettingsDialog::OnPageChanging, this);
	tree_->Bind(wxEVT_TREE_SEL_CHANGED, &CSettingsDialog::OnPageChanged, this);

	if (!LoadPages()) {
		return false;
	}

	return true;
}

void CSettingsDialog::AddPage(wxString const& name, COptionsPage* page, int nest)
{
	wxTreeItemId parent = tree_->GetRootItem();
	while (nest--) {
		parent = tree_->GetLastChild(parent);
		wxCHECK_RET(parent != wxTreeItemId(), "Nesting level too deep");
	}

	t_page p;
	p.page = page;
	p.id = tree_->AppendItem(parent, name);
	if (parent != tree_->GetRootItem()) {
		tree_->Expand(parent);
	}

	m_pages.push_back(p);
}

bool CSettingsDialog::LoadPages()
{}

bool CSettingsDialog::LoadSettings()
{
	for (auto const& page : m_pages) {
		if (!page.page->LoadPage()) {
			return false;
		}
	}

	return true;
}

void CSettingsDialog::OnPageChanged(wxTreeEvent& event)
{
	if (m_activePanel) {
		m_activePanel->Hide();
	}

	wxTreeItemId item = event.GetItem();

	for (auto const& page : m_pages) {
		if (page.id == item) {
			m_activePanel = page.page;
			m_activePanel->Display();
			break;
		}
	}
}

void CSettingsDialog::OnOK(wxCommandEvent&)
{
	for (auto const& page : m_pages) {
		if (!page.page->Validate()) {
			if (m_activePanel != page.page) {
				tree_->SelectItem(page.id);
			}
			return;
		}
	}

	for (auto const& page : m_pages) {
		page.page->SavePage();
	}

	m_activePanel = nullptr;
	m_pages.clear();

	EndModal(wxID_OK);
}

void CSettingsDialog::OnCancel(wxCommandEvent&)
{
	m_activePanel = nullptr;
	m_pages.clear();

	EndModal(wxID_CANCEL);

	for (auto const& saved : m_oldValues) {
		m_pOptions->set(saved.first, saved.second);
	}
}

void CSettingsDialog::OnPageChanging(wxTreeEvent& event)
{
	if (!m_activePanel) {
		return;
	}

	if (!m_activePanel->Validate()) {
		event.Veto();
	}
}

void CSettingsDialog::RememberOldValue(interfaceOptions option)
{
	m_oldValues[option] = m_pOptions->get_string(option);
}
