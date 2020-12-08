#include "../include/libfilezilla_engine.h"
#include "../engine/directorylistingparser.h"

#include "filezilla.h"
#include "recentserverlist.h"
#include "commandqueue.h"
#include "state.h"
#include "Options.h"
#include "loginmanager.h"
#include "Mainfrm.h"
#include "filezillaapp.h"
#include "textctrlex.h"
#include "themeprovider.h"

#include <libfilezilla/format.hpp>
#include <libfilezilla/util.hpp>

#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif
	
	unsigned char *aflBuf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
	
	
	while (__AFL_LOOP(10000)) {
		int aflBufLen = __AFL_FUZZ_TESTCASE_LEN;

		//~ CServer server;
		//~ server.SetType(DEFAULT);

		//~ CDirectoryListingParser parser(0, server);

		//~ char* data = new char[aflBufLen];
		//~ memcpy(data, aflBuf, aflBufLen);
		//~ parser.AddData(data, aflBufLen);

		//~ CDirectoryListing listing = parser.Parse(CServerPath());
		//~ printf("Data: %s  \n  Got:\n%s", aflBuf, listing[0].dump().c_str());
		

		//~ std::string msg = fz::sprintf("Data: %s, count: %u", entry.data, listing.size());
		//~ fz::replace_substrings(msg, "\r", std::string());
		//~ fz::replace_substrings(msg, "\n", std::string());

		//~ CPPUNIT_ASSERT_MESSAGE(msg, listing.size() == 1);

		//~ msg = fz::sprintf("Data: %s  Expected:\n%s\n  Got:\n%s", entry.data, entry.reference.dump(), listing[0].dump());
		//~ CPPUNIT_ASSERT_MESSAGE(msg, listing[0] == entry.reference);
		
		
		CMainFrame *m_pMainFrame = new CMainFrame();

		//~ m_pMainFrame->ProcessCommandLine();
		//~ m_pMainFrame->PostInitialize();

		//~ ShowStartupProfile();
		
		
		CState* pState = CContextManager::Get()->GetCurrentContext();
		if (!pState || !pState->engine_) {
			return;
		}

		std::wstring host = "sftp://test.rebex.net";
		std::wstring user = "demo";
		std::wstring pass = "password";
		std::wstring port = "22";

		Site site;

		std::wstring error;

		CServerPath path;
		if (!site.ParseUrl(host, port, user, pass, error, path)) {
			printf("Could not parse server address:\n%s", error);
			return;
		}

		host = site.Format(ServerFormat::host_only);
		ServerProtocol protocol = site.server.GetProtocol();
		switch (protocol)
		{
		case FTP:
		case UNKNOWN:
			if (CServer::GetProtocolFromPort(site.server.GetPort()) != FTP &&
				CServer::GetProtocolFromPort(site.server.GetPort()) != UNKNOWN)
			{
				host = _T("ftp://") + host;
			}
			break;
		default:
			{
				std::wstring const prefix = site.server.GetPrefixFromProtocol(protocol);
				if (!prefix.empty()) {
					host = prefix + _T("://") + host;
				}
			}
			break;
		}

		if (protocol == HTTP || protocol == HTTPS || protocol == S3) {
			printf("Syntax error Invalid protocol specified. Valid protocols are:\nftp:// for normal FTP with optional encryption,\nsftp:// for SSH file transfer protocol,\nftps:// for FTP over TLS (implicit) and\nftpes:// for FTP over TLS (explicit).");
			return;
		}

		//~ site.server.SetBypassProxy(true);

		//~ if (COptions::Get()->get_int(OPTION_DEFAULT_KIOSKMODE) && site.credentials.logonType_ == LogonType::normal) {
			//~ site.SetLogonType(LogonType::ask);
			//~ CLoginManager::Get().RememberPassword(site);
		//~ }
		Bookmark bm;
		bm.m_remoteDir = path;
		if (!m_pMainFrame->ConnectToSite(site, bm)) {
			return;
		}

		CRecentServerList::SetMostRecentServer(site);
	}
	
	return 0;
}
