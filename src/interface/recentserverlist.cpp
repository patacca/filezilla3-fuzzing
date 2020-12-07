#include "filezilla.h"
#include "recentserverlist.h"
#include "ipcmutex.h"
#include "filezillaapp.h"
#include "Options.h"
#include "xmlfunctions.h"

const std::deque<Site> CRecentServerList::GetMostRecentServers(bool lockMutex)
{
}

void CRecentServerList::SetMostRecentServer(Site const& site)
{
	CInterProcessMutex mutex(MUTEX_MOSTRECENTSERVERS);

	// Make sure list is initialized
	auto mostRecentServers = GetMostRecentServers(false);

	bool relocated = false;
	for (auto iter = mostRecentServers.begin(); iter != mostRecentServers.end(); ++iter) {
		if (iter->server == site.server) {
			mostRecentServers.erase(iter);
			mostRecentServers.push_front(site);
			relocated = true;
			break;
		}
	}
	if (!relocated) {
		mostRecentServers.push_front(site);
		if (mostRecentServers.size() > 10) {
			mostRecentServers.pop_back();
		}
	}

	if (COptions::Get()->get_int(OPTION_DEFAULT_KIOSKMODE) == 2) {
		return;
	}

	SetMostRecentServers(mostRecentServers, false);
}

void CRecentServerList::SetMostRecentServers(std::deque<Site> const& sites, bool lockMutex)
{
}

void CRecentServerList::Clear()
{
}
