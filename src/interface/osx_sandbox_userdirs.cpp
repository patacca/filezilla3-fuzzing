#include "filezilla.h"
#include "osx_sandbox_userdirs.h"

#include "filezillaapp.h"
#include "ipcmutex.h"
#include "Options.h"
#include "xmlfunctions.h"

#include <wx/dirdlg.h>
#include <wx/osx/core/cfstring.h>

OSXSandboxUserdirs::OSXSandboxUserdirs()
{
}

OSXSandboxUserdirs::~OSXSandboxUserdirs()
{
	for (auto const& dir : userdirs_) {
		CFURLStopAccessingSecurityScopedResource(dir.second.url.get());
	}
}


OSXSandboxUserdirs& OSXSandboxUserdirs::Get()
{
	static OSXSandboxUserdirs userDirs;
	return userDirs;
}


namespace {
std::wstring GetPath(CFURLRef url)
{
	char buf[2048];
	if (!CFURLGetFileSystemRepresentation(url, true, reinterpret_cast<uint8_t*>(buf), sizeof(buf))) {
		return std::wstring();
	}

	return fz::to_wstring(std::string(buf));
}

void append(wxString& error, CFErrorRef ref, wxString const& func)
{
	wxString s;
	if (ref) {
		wxCFStringRef sref(CFErrorCopyDescription(ref));
		s = sref.AsString();
	}
	error += "\n";
	if (s.empty()) {
		error += wxString::Format(_("Function %s failed"), func);
	}
	else {
		error += s;
	}
}
}

void OSXSandboxUserdirs::Load()
{
}


bool OSXSandboxUserdirs::Save()
{
}

bool OSXSandboxUserdirs::Add()
{
	std::wstring home = GetEnv("HOME");
	wxDirDialog dlg(0, (L"Select local data directory"), home, wxDD_DEFAULT_STYLE|wxDD_DIR_MUST_EXIST);
	if (dlg.ShowModal() != wxID_OK) {
		return false;
	}

	auto path = dlg.GetPath().ToStdWstring();
	wxCFStringRef pathref(path);
	wxCFRef<CFURLRef> url(CFURLCreateWithFileSystemPath(0, pathref.get(), kCFURLPOSIXPathStyle, true));
	if (!url) {
		wxMessageBoxEx(wxString::Format(_("Could not create CFURL from path %s"), path));
		return false;
	}

	CFErrorRef errorRef = 0;
	wxCFDataRef bookmark(CFURLCreateBookmarkData(0, url.get(), kCFURLBookmarkCreationWithSecurityScope, 0, 0, &errorRef));
	if (!bookmark) {
		wxString error;
		append(error, errorRef, L"CFURLCreateBookmarkData");
		wxMessageBoxEx(_("Could not create security-scoped bookmark from URL:") + error);
		return false;
	}

	std::wstring actualPath = GetPath(url.get());
	if (actualPath.empty()) {
		wxMessageBoxEx(_("Could not get path from URL"));
		return false;
	}

	if (actualPath.back() != '/') {
		actualPath += '/';
	}

	auto it = userdirs_.find(actualPath);
	if (it != userdirs_.end()) {
		CFURLStopAccessingSecurityScopedResource(it->second.url.get());
	}
	userdirs_[actualPath] = Data{true, bookmark, url};

	CInterProcessMutex mutex(MUTEX_MAC_SANDBOX_USERDIRS);

	return Save();
}

bool OSXSandboxUserdirs::AddFile(std::wstring const& file)
{
	if (file.empty() || file.back() == '/') {
		return false;
	}

	wxCFStringRef pathref(file);
	wxCFRef<CFURLRef> url(CFURLCreateWithFileSystemPath(0, pathref.get(), kCFURLPOSIXPathStyle, true));
	if (!url) {
		wxMessageBoxEx(wxString::Format(_("Could not create CFURL from path %s"), file));
		return false;
	}

	CFErrorRef errorRef = 0;
	wxCFDataRef bookmark(CFURLCreateBookmarkData(0, url.get(), kCFURLBookmarkCreationWithSecurityScope, 0, 0, &errorRef));
	if (!bookmark) {
		wxString error;
		append(error, errorRef, L"CFURLCreateBookmarkData");
		wxMessageBoxEx(_("Could not create security-scoped bookmark from URL:") + error);
		return false;
	}

	std::wstring actualPath = GetPath(url.get());
	if (actualPath.empty()) {
		wxMessageBoxEx(_("Could not get path from URL"));
		return false;
	}

	auto it = userdirs_.find(actualPath);
	if (it != userdirs_.end()) {
		CFURLStopAccessingSecurityScopedResource(it->second.url.get());
	}
	userdirs_[actualPath] = Data{false, bookmark, url};

	CInterProcessMutex mutex(MUTEX_MAC_SANDBOX_USERDIRS);

	return Save();
}

std::vector<std::wstring> OSXSandboxUserdirs::GetDirs() const
{
	std::vector<std::wstring> ret;
	ret.reserve(userdirs_.size());
	for (auto const& it : userdirs_) {
		ret.push_back(it.first);
	}
	return ret;
}

void OSXSandboxUserdirs::Remove(std::wstring const& dir)
{
	auto it = userdirs_.find(dir);
	if (it != userdirs_.cend()) {
		CFURLStopAccessingSecurityScopedResource(it->second.url.get());
		userdirs_.erase(it);
	}

	CInterProcessMutex mutex(MUTEX_MAC_SANDBOX_USERDIRS);

	Save();
}

struct OSXSandboxUserdirsDialog::impl
{
	wxListBox* dirs_{};
};

OSXSandboxUserdirsDialog::OSXSandboxUserdirsDialog()
	: impl_(std::make_unique<impl>())
{
}

OSXSandboxUserdirsDialog::~OSXSandboxUserdirsDialog()
{
}

void OSXSandboxUserdirsDialog::Run(wxWindow* parent, bool initial)
{
	if (!Create(parent, -1, _("Directory access permissions"))) {
		wxBell();
		return;
	}

	auto& lay = layout();
	auto * main = lay.createMain(this, 1);
	main->AddGrowableCol(0);
	main->AddGrowableRow(2);

	main->Add(new wxStaticText(this, -1, _("You need to grant FileZilla access to the directories you want to download files into or to upload files from.")));
	main->Add(new wxStaticText(this, -1, _("Please add the local directories you want to use FileZilla with.")));

	impl_->dirs_ = new wxListBox(this, -1);
	main->Add(impl_->dirs_, lay.grow)->SetMinSize(-1, lay.dlgUnits(100));

	auto * row = lay.createGrid(2);
	main->Add(row, lay.halign);

	auto add = new wxButton(this, -1, _("&Add directory..."));
	row->Add(add, lay.valign);
	auto remove = new wxButton(this, -1, _("&Remove selected"));
	row->Add(remove, lay.valign);

	auto * buttons = lay.createButtonSizer(this, main, true);

	auto ok = new wxButton(this, wxID_OK, _("&OK"));
	ok->SetDefault();
	buttons->AddButton(ok);

	auto cancel = new wxButton(this, wxID_CANCEL, _("Cancel"));
	buttons->AddButton(cancel);
	buttons->Realize();


	WrapRecursive(this, GetSizer(), ConvertDialogToPixels(wxSize(250, -1)).x);
	GetSizer()->Fit(this);

	add->Bind(wxEVT_BUTTON, &OSXSandboxUserdirsDialog::OnAdd, this);
	remove->Bind(wxEVT_BUTTON, &OSXSandboxUserdirsDialog::OnRemove, this);

	ok->Bind(wxEVT_BUTTON, [initial](wxCommandEvent& evt) {
		if (initial && OSXSandboxUserdirs::Get().GetDirs().empty()) {
			wxMessageBoxEx(_("Please add at least one directory you want to download files into or to upload files from."), _("No directory added"));
		}
		else {
			evt.Skip();
		}
	});

	DisplayCurrentDirs();

	ShowModal();
}

void OSXSandboxUserdirsDialog::OnAdd(wxCommandEvent&)
{
	OSXSandboxUserdirs::Get().Add();
	DisplayCurrentDirs();
}

void OSXSandboxUserdirsDialog::OnRemove(wxCommandEvent&)
{
	int pos = impl_->dirs_->GetSelection();
	if (pos != wxNOT_FOUND) {
		wxString sel = impl_->dirs_->GetString(pos);
		OSXSandboxUserdirs::Get().Remove(sel.ToStdWstring());
		DisplayCurrentDirs();
	}
}

void OSXSandboxUserdirsDialog::DisplayCurrentDirs()
{
	auto dirs = OSXSandboxUserdirs::Get().GetDirs();

	wxString sel;
	int pos = impl_->dirs_->GetSelection();
	if (pos != wxNOT_FOUND) {
		sel = impl_->dirs_->GetString(pos);
	}

	impl_->dirs_->Clear();

	for (auto const& dir : dirs) {
		impl_->dirs_->Append(dir);
	}

	impl_->dirs_->SetStringSelection(sel);
}
