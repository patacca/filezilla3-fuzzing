#include "filezilla.h"

#include <libfilezilla/event_loop.hpp>
#include <libfilezilla/format.hpp>
#include <libfilezilla/iputils.hpp>
#include <libfilezilla/translate.hpp>
#include <libfilezilla/util.hpp>

#include "../include/engine_context.h"
#include "../include/externalipresolver.h"

#include "dialogex.h"
#include "filezillaapp.h"
#include "netconfwizard.h"
#include "Options.h"
#include "xrc_helper.h"

wxDECLARE_EVENT(fzEVT_ON_EXTERNAL_IP_ADDRESS, wxCommandEvent);
wxDEFINE_EVENT(fzEVT_ON_EXTERNAL_IP_ADDRESS, wxCommandEvent);

BEGIN_EVENT_TABLE(CNetConfWizard, wxWizard)
EVT_WIZARD_PAGE_CHANGING(wxID_ANY, CNetConfWizard::OnPageChanging)
EVT_WIZARD_PAGE_CHANGED(wxID_ANY, CNetConfWizard::OnPageChanged)
EVT_BUTTON(XRCID("ID_RESTART"), CNetConfWizard::OnRestart)
EVT_WIZARD_FINISHED(wxID_ANY, CNetConfWizard::OnFinish)
EVT_TIMER(wxID_ANY, CNetConfWizard::OnTimer)
EVT_COMMAND(wxID_ANY, fzEVT_ON_EXTERNAL_IP_ADDRESS, CNetConfWizard::OnExternalIPAddress2)
END_EVENT_TABLE()

// Mark some strings used by wx as translatable
#if 0
fztranslate_mark("&Next >");
fztranslate_mark("< &Back");
#endif

CNetConfWizard::CNetConfWizard(wxWindow* parent, COptions* pOptions, CFileZillaEngineContext & engine_context)
	: fz::event_handler(engine_context.GetEventLoop())
	, engine_context_(engine_context)
	, m_parent(parent), m_pOptions(pOptions)
{
	m_timer.SetOwner(this);

	ResetTest();
}

CNetConfWizard::~CNetConfWizard()
{
	remove_handler();

	socket_.reset();
	delete m_pIPResolver;
	listen_socket_.reset();
	data_socket_.reset();
}

bool CNetConfWizard::Load()
{
}

bool CNetConfWizard::Run()
{
	return RunWizard(m_pages.front());
}

void CNetConfWizard::OnPageChanging(wxWizardEvent& event)
{
	if (event.GetPage() == m_pages[3]) {
		int mode = XRCCTRL(*this, "ID_ACTIVEMODE1", wxRadioButton)->GetValue() ? 0 : (XRCCTRL(*this, "ID_ACTIVEMODE2", wxRadioButton)->GetValue() ? 1 : 2);
		if (mode == 1) {
			wxTextCtrl* control = XRCCTRL(*this, "ID_ACTIVEIP", wxTextCtrl);
			std::wstring ip = control->GetValue().ToStdWstring();
			if (ip.empty()) {
				wxMessageBoxEx(_("Please enter your external IP address"));
				control->SetFocus();
				event.Veto();
				return;
			}
			if (fz::get_address_type(ip) != fz::address_type::ipv4) {
				wxMessageBoxEx(_("You have to enter a valid IPv4 address."));
				control->SetFocus();
				event.Veto();
				return;
			}
		}
		else if (mode == 2) {
			wxTextCtrl* pResolver = XRCCTRL(*this, "ID_ACTIVERESOLVER", wxTextCtrl);
			wxString address = pResolver->GetValue();
			if (address.empty()) {
				wxMessageBoxEx(_("Please enter an URL where to get your external address from"));
				pResolver->SetFocus();
				event.Veto();
				return;
			}
		}
	}
	else if (event.GetPage() == m_pages[4]) {
		int mode = XRCCTRL(*this, "ID_ACTIVE_PORTMODE1", wxRadioButton)->GetValue() ? 0 : 1;
		if (mode) {
			wxTextCtrl* pPortMin = XRCCTRL(*this, "ID_ACTIVE_PORTMIN", wxTextCtrl);
			wxTextCtrl* pPortMax = XRCCTRL(*this, "ID_ACTIVE_PORTMAX", wxTextCtrl);
			wxString portMin = pPortMin->GetValue();
			wxString portMax = pPortMax->GetValue();

			long min = 0, max = 0;
			if (!portMin.ToLong(&min) || !portMax.ToLong(&max) ||
				min < 1024 || max > 65535 || min > max)
			{
				wxMessageBoxEx(_("Please enter a valid portrange."));
				pPortMin->SetFocus();
				event.Veto();
				return;
			}
		}
	}
	else if (event.GetPage() == m_pages[5] && !event.GetDirection()) {
		auto pNext = dynamic_cast<wxButton*>(FindWindow(wxID_FORWARD));
		if (pNext) {
			pNext->SetLabel(m_nextLabelText);
		}
	}
	else if (event.GetPage() == m_pages[5] && event.GetDirection()) {
		if (m_testDidRun) {
			return;
		}

		m_testDidRun = true;

		auto pNext = dynamic_cast<wxButton*>(FindWindow(wxID_FORWARD));
		if (pNext) {
			pNext->Disable();
		}
		auto pPrev = dynamic_cast<wxButton*>(FindWindow(wxID_BACKWARD));
		if (pPrev) {
			pPrev->Disable();
		}
		event.Veto();

		PrintMessage(fz::sprintf(fztranslate("Connecting to %s"), L"probe.filezilla-project.org"), 0);
		socket_ = std::make_unique<fz::socket>(engine_context_.GetThreadPool(), static_cast<fz::event_handler*>(this));
		m_recvBufferPos = 0;

		int res = socket_->connect(fzT("probe.filezilla-project.org"), 21);
		if (res) {
			PrintMessage(fz::sprintf(fztranslate("Connect failed: %s"), fz::socket_error_description(res)), 1);
			CloseSocket();
		}
	}
}

void CNetConfWizard::OnPageChanged(wxWizardEvent& event)
{
	if (event.GetPage() == m_pages[5]) {
		auto pNext = dynamic_cast<wxButton*>(FindWindow(wxID_FORWARD));
		if (pNext) {
			m_nextLabelText = pNext->GetLabel();
			pNext->SetLabel(_("&Test"));
		}
	}
	else if (event.GetPage() == m_pages[6]) {
		auto pPrev = dynamic_cast<wxButton*>(FindWindow(wxID_BACKWARD));
		if (pPrev) {
			pPrev->Disable();
		}
		auto pNext = dynamic_cast<wxButton*>(FindWindow(wxID_FORWARD));
		if (pNext) {
			pNext->SetFocus();
		}
	}
}

void CNetConfWizard::DoOnSocketEvent(fz::socket_event_source* s, fz::socket_event_flag t, int error)
{
	if (s == socket_.get()) {
		if (error) {
			OnClose();
			return;
		}
		switch (t)
		{
		case fz::socket_event_flag::read:
			OnReceive();
			break;
		case fz::socket_event_flag::write:
			OnSend();
			break;
		case fz::socket_event_flag::connection:
			OnConnect();
			break;
		default:
			break;
		}
	}
	else if (s == listen_socket_.get()) {
		if (error) {
			PrintMessage(fztranslate("Listen socket closed"), 1);
			CloseSocket();
			return;
		}
		switch (t) {
		case fz::socket_event_flag::connection:
			OnAccept();
			break;
		default:
			break;
		}
	}
	else if (s == data_socket_.get()) {
		if (error) {
			OnDataClose();
			return;
		}
		switch (t)
		{
		case fz::socket_event_flag::read:
			OnDataReceive();
			break;
		default:
			break;
		}
	}
}


void CNetConfWizard::OnSend()
{
	if (!sendBuffer_) {
		return;
	}

	if (!socket_) {
		return;
	}

	int error;
	int const written = socket_->write(sendBuffer_.get(), static_cast<int>(sendBuffer_.size()), error);
	if (written < 0) {
		if (error != EAGAIN) {
			PrintMessage(fztranslate("Failed to send command."), 1);
			CloseSocket();
		}
		return;
	}
	sendBuffer_.consume(static_cast<size_t>(written));
}

void CNetConfWizard::OnClose()
{
	CloseSocket();
}

void CNetConfWizard::OnConnect()
{
	PrintMessage(fztranslate("Connection established, waiting for welcome message."), 0);
	m_connectSuccessful = true;
}

void CNetConfWizard::OnReceive()
{
	while (true) {
		int error;
		int const read = socket_->read(m_recvBuffer + m_recvBufferPos, NETCONFBUFFERSIZE - m_recvBufferPos, error);
		if (read < 0) {
			if (error != EAGAIN) {
				PrintMessage(fztranslate("Could not receive data from server."), 1);
				CloseSocket();
			}
			return;
		}
		if (!read) {
			PrintMessage(fztranslate("Connection lost"), 1);
			CloseSocket();
			return;
		}

		m_recvBufferPos += read;

		if (m_recvBufferPos < 3) {
			return;
		}

		for (int i = 0; i < m_recvBufferPos - 1; ++i) {
			if (m_recvBuffer[i] == '\n') {
				m_testResult = servererror;
				PrintMessage(fztranslate("Invalid data received"), 1);
				CloseSocket();
				return;
			}
			if (m_recvBuffer[i] != '\r') {
				continue;
			}

			if (m_recvBuffer[i + 1] != '\n') {
				m_testResult = servererror;
				PrintMessage(fztranslate("Invalid data received"), 1);
				CloseSocket();
				return;
			}
			m_recvBuffer[i] = 0;

			if (!*m_recvBuffer) {
				m_testResult = servererror;
				PrintMessage(fztranslate("Invalid data received"), 1);
				CloseSocket();
				return;
			}

			ParseResponse(m_recvBuffer);

			if (!socket_) {
				return;
			}

			memmove(m_recvBuffer, m_recvBuffer + i + 2, m_recvBufferPos - i - 2);
			m_recvBufferPos -= i + 2;
			i = -1;
		}

		if (m_recvBufferPos == 200) {
			m_testResult = servererror;
			PrintMessage(fztranslate("Invalid data received"), 1);
			CloseSocket();
			return;
		}
	}
}

void CNetConfWizard::ParseResponse(const char* line)
{
	if (m_timer.IsRunning()) {
		m_timer.Stop();
	}

	size_t len = strlen(line);
	std::wstring msg = fz::to_wstring_from_utf8(line);
	std::wstring str = fztranslate("Response:");
	str += L" ";
	str += msg;
	PrintMessage(str, 3);

	if (len < 3) {
		m_testResult = servererror;
		PrintMessage(fztranslate("Server sent unexpected reply."), 1);
		CloseSocket();
		return;
	}
	if (line[3] && line[3] != ' ') {
		m_testResult = servererror;
		PrintMessage(fztranslate("Server sent unexpected reply."), 1);
		CloseSocket();
		return;
	}

	if (line[0] == '1') {
		return;
	}

	switch (m_state)
	{
	case 3:
		if (line[0] == '2') {
			break;
		}

		if (line[1] == '0' && line[2] == '1') {
			PrintMessage(fztranslate("Communication tainted by router or firewall"), 1);
			m_testResult = tainted;
			CloseSocket();
			return;
		}
		else if (line[1] == '1' && line[2] == '0') {
			PrintMessage(fztranslate("Wrong external IP address"), 1);
			m_testResult = mismatch;
			CloseSocket();
			return;
		}
		else if (line[1] == '1' && line[2] == '1') {
			PrintMessage(fztranslate("Wrong external IP address"), 1);
			PrintMessage(fztranslate("Communication tainted by router or firewall"), 1);
			m_testResult = mismatchandtainted;
			CloseSocket();
			return;
		}
		else {
			m_testResult = servererror;
			PrintMessage(fztranslate("Server sent unexpected reply."), 1);
			CloseSocket();
			return;
		}
		break;
	case 4:
		if (line[0] != '2') {
			m_testResult = servererror;
			PrintMessage(fztranslate("Server sent unexpected reply."), 1);
			CloseSocket();
			return;
		}
		else {
			const char* p = line + len;
			while (*(--p) != ' ') {
				if (*p < '0' || *p > '9') {
					m_testResult = servererror;
					PrintMessage(fztranslate("Server sent unexpected reply."), 1);
					CloseSocket();
					return;
				}
			}
			m_data = 0;
			while (*++p) {
				m_data = m_data * 10 + *p - '0';
			}
		}
		break;
	case 5:
		if (line[0] == '2') {
			break;
		}

		if (line[0] == '5' && line[1] == '0' && (line[2] == '1' || line[2] == '2')) {
			m_testResult = tainted;
			PrintMessage(fztranslate("PORT command tainted by router or firewall."), 1);
			CloseSocket();
			return;
		}

		m_testResult = servererror;
		PrintMessage(fztranslate("Server sent unexpected reply."), 1);
		CloseSocket();
		return;
	case 6:
		if (line[0] != '2' && line[0] != '3') {
			m_testResult = servererror;
			PrintMessage(fztranslate("Server sent unexpected reply."), 1);
			CloseSocket();
			return;
		}
		if (data_socket_) {
			if (gotListReply) {
				m_testResult = servererror;
				PrintMessage(fztranslate("Server sent unexpected reply."), 1);
				CloseSocket();
			}
			gotListReply = true;
			return;
		}
		break;
	default:
		if (line[0] != '2' && line[0] != '3') {
			m_testResult = servererror;
			PrintMessage(fztranslate("Server sent unexpected reply."), 1);
			CloseSocket();
			return;
		}
		break;
	}

	++m_state;

	SendNextCommand();
}

void CNetConfWizard::PrintMessage(std::wstring const& msg, int)
{
	XRCCTRL(*this, "ID_RESULTS", wxTextCtrl)->AppendText(msg + L"\n");
}

void CNetConfWizard::CloseSocket()
{
}

bool CNetConfWizard::Send(std::wstring const& cmd)
{
	wxASSERT(!sendBuffer_);

	if (!socket_) {
		return false;
	}

	PrintMessage(cmd, 2);

	sendBuffer_.append(fz::to_utf8(cmd));
	sendBuffer_.append("\r\n");

	m_timer.Start(15000, true);
	OnSend();

	return socket_ != 0;
}

std::wstring CNetConfWizard::GetExternalIPAddress()
{
	std::wstring ret;

	wxASSERT(socket_);

	int mode = XRCCTRL(*this, "ID_ACTIVEMODE1", wxRadioButton)->GetValue() ? 0 : (XRCCTRL(*this, "ID_ACTIVEMODE2", wxRadioButton)->GetValue() ? 1 : 2);
	if (!mode) {
		ret = fz::to_wstring_from_utf8(socket_->local_ip());
		if (ret.empty()) {
			PrintMessage(fztranslate("Failed to retrieve local IP address, aborting."), 1);
			CloseSocket();
		}
	}
	else if (mode == 1) {
		wxTextCtrl* control = XRCCTRL(*this, "ID_ACTIVEIP", wxTextCtrl);
		ret = control->GetValue().ToStdWstring();
	}
	else if (mode == 2) {
		if (!m_pIPResolver) {
			wxTextCtrl* pResolver = XRCCTRL(*this, "ID_ACTIVERESOLVER", wxTextCtrl);
			std::wstring address = pResolver->GetValue().ToStdWstring();

			PrintMessage(fz::sprintf(fztranslate("Retrieving external IP address from %s"), address), 0);

			m_pIPResolver = new CExternalIPResolver(engine_context_.GetThreadPool(), *this);
			m_pIPResolver->GetExternalIP(address, fz::address_type::ipv4, true);
			if (!m_pIPResolver->Done()) {
				return ret;
			}
		}
		if (m_pIPResolver->Successful()) {
			ret = fz::to_wstring_from_utf8(m_pIPResolver->GetIP());
		}
		else {
			PrintMessage(fztranslate("Failed to retrieve external IP address, aborting."), 1);

			m_testResult = externalfailed;
			CloseSocket();
		}
		delete m_pIPResolver;
		m_pIPResolver = 0;
	}

	return ret;
}

void CNetConfWizard::OnExternalIPAddress2(wxCommandEvent&)
{
	if (!m_pIPResolver) {
		return;
	}

	if (m_state != 3) {
		return;
	}

	if (!m_pIPResolver->Done()) {
		return;
	}

	SendNextCommand();
}

void CNetConfWizard::SendNextCommand()
{
	switch (m_state)
	{
	case 1:
		if (!Send(L"USER " + fz::to_wstring_from_utf8(PACKAGE_NAME))) {
			return;
		}
		break;
	case 2:
		if (!Send(L"PASS " + fz::to_wstring_from_utf8(PACKAGE_VERSION))) {
			return;
		}
		break;
	case 3:
		{
			PrintMessage(fztranslate("Checking for correct external IP address"), 0);
			std::wstring ip = GetExternalIPAddress();
			if (ip.empty()) {
				return;
			}
			if (!fz::get_ipv6_long_form(ip).empty()) {
				PrintMessage(fztranslate("You appear to be using an IPv6-only host. This wizard does not support this environment."), 1);
				CloseSocket();
				return;
			}
			m_externalIP = ip;

			std::wstring hexIP = ip;
			for (unsigned int i = 0; i < hexIP.size(); ++i) {
				wchar_t & c = hexIP[i];
				if (c == '.') {
					c = '-';
				}
				else {
					c = c - '0' + 'a';
				}
			}

			if (!Send(L"IP " + ip + L" " + hexIP)) {
				return;
			}

		}
		break;
	case 4:
		{
			int port = CreateListenSocket();
			if (!port) {
				PrintMessage(fz::sprintf(fztranslate("Failed to create listen socket on port %d, aborting."), port), 1);
				CloseSocket();
				return;
			}
			m_listenPort = port;
			Send(fz::sprintf(L"PREP %d", port));
			break;
		}
	case 5:
		{
			std::wstring cmd = fz::sprintf(L"PORT %s,%d,%d", m_externalIP, m_listenPort / 256, m_listenPort % 256);
			fz::replace_substrings(cmd, L".", L",");
			Send(cmd);
		}
		break;
	case 6:
		Send(L"LIST");
		break;
	case 7:
		m_testResult = successful;
		Send(L"QUIT");
		break;
	case 8:
		CloseSocket();
		break;
	}
}

void CNetConfWizard::OnRestart(wxCommandEvent&)
{
	ResetTest();
	ShowPage(m_pages[0], false);
}

void CNetConfWizard::ResetTest()
{
	if (m_timer.IsRunning()) {
		m_timer.Stop();
	}

	m_state = 0;
	m_connectSuccessful = false;

	m_testDidRun = false;
	m_testResult = unknown;
	m_recvBufferPos = 0;
	gotListReply = false;

	if (!m_pages.empty()) {
		XRCCTRL(*this, "ID_RESULTS", wxTextCtrl)->SetLabel(_T(""));
	}
}

void CNetConfWizard::OnFinish(wxWizardEvent&)
{
	if (m_testResult != successful) {
		if (wxMessageBoxEx(_("The test did not succeed. Do you really want to save the settings?"), _("Save settings?"), wxYES_NO | wxICON_QUESTION) != wxYES) {
			return;
		}
	}

	m_pOptions->set(OPTION_USEPASV, XRCCTRL(*this, "ID_PASSIVE", wxRadioButton)->GetValue() ? 1 : 0);
	m_pOptions->set(OPTION_ALLOW_TRANSFERMODEFALLBACK, XRCCTRL(*this, "ID_FALLBACK", wxCheckBox)->GetValue() ? 1 : 0);

	m_pOptions->set(OPTION_PASVREPLYFALLBACKMODE, XRCCTRL(*this, "ID_PASSIVE_FALLBACK1", wxRadioButton)->GetValue() ? 0 : 1);

	if (XRCCTRL(*this, "ID_ACTIVEMODE1", wxRadioButton)->GetValue()) {
		m_pOptions->set(OPTION_EXTERNALIPMODE, 0);
	}
	else {
		m_pOptions->set(OPTION_EXTERNALIPMODE, XRCCTRL(*this, "ID_ACTIVEMODE2", wxRadioButton)->GetValue() ? 1 : 2);
	}

	m_pOptions->set(OPTION_LIMITPORTS, XRCCTRL(*this, "ID_ACTIVE_PORTMODE1", wxRadioButton)->GetValue() ? 0 : 1);

	long tmp;
	XRCCTRL(*this, "ID_ACTIVE_PORTMIN", wxTextCtrl)->GetValue().ToLong(&tmp); m_pOptions->set(OPTION_LIMITPORTS_LOW, tmp);
	XRCCTRL(*this, "ID_ACTIVE_PORTMAX", wxTextCtrl)->GetValue().ToLong(&tmp); m_pOptions->set(OPTION_LIMITPORTS_HIGH, tmp);

	m_pOptions->set(OPTION_EXTERNALIP, XRCCTRL(*this, "ID_ACTIVEIP", wxTextCtrl)->GetValue().ToStdWstring());
	m_pOptions->set(OPTION_EXTERNALIPRESOLVER, XRCCTRL(*this, "ID_ACTIVERESOLVER", wxTextCtrl)->GetValue().ToStdWstring());
	m_pOptions->set(OPTION_NOEXTERNALONLOCAL, XRCCTRL(*this, "ID_NOEXTERNALONLOCAL", wxCheckBox)->GetValue());
}

int CNetConfWizard::CreateListenSocket()
{
	if (listen_socket_) {
		return 0;
	}

	if (XRCCTRL(*this, "ID_ACTIVE_PORTMODE1", wxRadioButton)->GetValue()) {
		return CreateListenSocket(0);
	}
	else {
		long low;
		long high;
		XRCCTRL(*this, "ID_ACTIVE_PORTMIN", wxTextCtrl)->GetValue().ToLong(&low);
		XRCCTRL(*this, "ID_ACTIVE_PORTMAX", wxTextCtrl)->GetValue().ToLong(&high);

		int mid = fz::random_number(low, high);
		wxASSERT(mid >= low && mid <= high);

		for (int port = mid; port <= high; ++port) {
			if (CreateListenSocket(port)) {
				return port;
			}
		}
		for (int port = low; port < mid; ++port) {
			if (CreateListenSocket(port)) {
				return port;
			}
		}

		return 0;
	}
}

int CNetConfWizard::CreateListenSocket(unsigned int port)
{
	listen_socket_ = std::make_unique<fz::listen_socket>(engine_context_.GetThreadPool(), static_cast<fz::event_handler*>(this));
	int res = listen_socket_->listen(socket_ ? socket_->address_family() : fz::address_type::unknown, port);

	if (res < 0) {
		listen_socket_.reset();
		return 0;
	}

	if (port) {
		return port;
	}

	// Get port number from socket
	int error;
	res = listen_socket_->local_port(error);
	if (res <= 0) {
		listen_socket_.reset();
		return 0;
	}
	return res;
}

void CNetConfWizard::OnAccept()
{
	if (!socket_ || !listen_socket_) {
		return;
	}
	if (data_socket_) {
		return;
	}

	int error;
	data_socket_ = listen_socket_->accept(error);
	if (!data_socket_) {
		return;
	}
	data_socket_->set_event_handler(this);

	std::string peerAddr = socket_->peer_ip();
	std::string dataPeerAddr = data_socket_->peer_ip();
	if (peerAddr.empty()) {
		data_socket_.reset();
		PrintMessage(fztranslate("Failed to get peer address of control connection, connection closed."), 1);
		CloseSocket();
		return;
	}
	if (dataPeerAddr.empty()) {
		data_socket_.reset();
		PrintMessage(fztranslate("Failed to get peer address of data connection, connection closed."), 1);
		CloseSocket();
		return;
	}
	if (peerAddr != dataPeerAddr) {
		data_socket_.reset();
		PrintMessage(fztranslate("Warning, ignoring data connection from wrong IP."), 0);
		return;
	}
	listen_socket_.reset();
}

void CNetConfWizard::OnDataReceive()
{
	char buffer[100];
	int error;
	int const read = data_socket_->read(buffer, 99, error);
	if (!read) {
		PrintMessage(fztranslate("Data socket closed too early."), 1);
		CloseSocket();
		return;
	}
	if (read < 0) {
		if (error != EAGAIN) {
			PrintMessage(fztranslate("Could not read from data socket."), 1);
			CloseSocket();
		}
		return;
	}
	buffer[read] = 0;

	int data = 0;
	const char* p = buffer;
	while (*p && *p != ' ') {
		if (*p < '0' || *p > '9') {
			m_testResult = datatainted;
			PrintMessage(fztranslate("Received data tainted"), 1);
			CloseSocket();
			return;
		}
		data = data * 10 + *p++ - '0';
	}
	if (data != m_data) {
		m_testResult = datatainted;
		PrintMessage(fztranslate("Received data tainted"), 1);
		CloseSocket();
		return;
	}
	++p;
	if (p - buffer != read - 4) {
		PrintMessage(fztranslate("Failed to receive data"), 1);
		CloseSocket();
		return;
	}

	uint32_t ip = 0;
	for (auto const& c : m_externalIP) {
		if (c == '.') {
			ip *= 256;
		}
		else {
			ip = ip - (ip % 256) + (ip % 256) * 10 + c - '0';
		}
	}

	ip = wxUINT32_SWAP_ON_LE(ip);
	if (memcmp(&ip, p, 4)) {
		m_testResult = datatainted;
		PrintMessage(fztranslate("Received data tainted"), 1);
		CloseSocket();
		return;
	}

	data_socket_.reset();

	if (gotListReply) {
		++m_state;
		SendNextCommand();
	}
}

void CNetConfWizard::OnDataClose()
{
	OnDataReceive();
	if (data_socket_) {
		PrintMessage(fztranslate("Data socket closed too early."), 0);
		CloseSocket();
		return;
	}
	data_socket_.reset();

	if (gotListReply) {
		++m_state;
		SendNextCommand();
	}
}

void CNetConfWizard::OnTimer(wxTimerEvent& event)
{
	if (event.GetId() != m_timer.GetId()) {
		return;
	}

	PrintMessage(fztranslate("Connection timed out."), 0);
	CloseSocket();
}

void CNetConfWizard::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::socket_event, CExternalIPResolveEvent>(ev, this
		, &CNetConfWizard::OnSocketEvent
		, &CNetConfWizard::OnExternalIPAddress);
}

void CNetConfWizard::OnExternalIPAddress()
{
	QueueEvent(new wxCommandEvent(fzEVT_ON_EXTERNAL_IP_ADDRESS));
}

void CNetConfWizard::OnSocketEvent(fz::socket_event_source* s, fz::socket_event_flag t, int error)
{
	if (!s) {
		return;
	}

	CallAfter([=]{DoOnSocketEvent(s, t, error);});
}
