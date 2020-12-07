#include "filezilla.h"
#include "loginmanager.h"

#include "dialogex.h"
#include "filezillaapp.h"
#include "Options.h"
#include "textctrlex.h"

#include <algorithm>

CLoginManager CLoginManager::m_theLoginManager;

std::list<CLoginManager::t_passwordcache>::iterator CLoginManager::FindItem(CServer const& server, std::wstring const& challenge)
{
	return std::find_if(m_passwordCache.begin(), m_passwordCache.end(), [&](t_passwordcache const& item)
		{
			return item.host == server.GetHost() && item.port == server.GetPort() && item.user == server.GetUser() && item.challenge == challenge;
		}
	);
}

bool CLoginManager::GetPassword(Site & site, bool silent)
{
	bool const needsUser = ProtocolHasUser(site.server.GetProtocol()) && site.server.GetUser().empty() && (site.credentials.logonType_ == LogonType::ask || site.credentials.logonType_ == LogonType::interactive);

	if (site.credentials.logonType_ != LogonType::ask && !site.credentials.encrypted_ && !needsUser) {
		return true;
	}

	if (site.credentials.encrypted_) {
		auto priv = GetDecryptor(site.credentials.encrypted_);
		if (priv) {
			return site.credentials.Unprotect(priv);
		}

		if (!silent) {
			return DisplayDialogForEncrypted(site);
		}
	}
	else {
		auto it = FindItem(site.server, std::wstring());
		if (it != m_passwordCache.end()) {
			site.credentials.SetPass(it->password);
			return true;
		}

		if (!silent) {
			return DisplayDialog(site, std::wstring(), true);
		}
	}

	return false;
}


bool CLoginManager::GetPassword(Site & site, bool silent, std::wstring const& challenge, bool canRemember)
{
	if (canRemember) {
		auto it = FindItem(site.server, challenge);
		if (it != m_passwordCache.end()) {
			site.credentials.SetPass(it->password);
			return true;
		}
	}
	if (silent) {
		return false;
	}

	return DisplayDialog(site, challenge, canRemember);
}

bool CLoginManager::DisplayDialogForEncrypted(Site & site)
{
}

bool CLoginManager::DisplayDialog(Site & site, std::wstring const& challenge, bool canRemember)
{
}

void CLoginManager::CachedPasswordFailed(CServer const& server, std::wstring const& challenge)
{
	auto it = FindItem(server, challenge);
	if (it != m_passwordCache.end()) {
		m_passwordCache.erase(it);
	}
}

void CLoginManager::RememberPassword(Site & site, std::wstring const& challenge)
{
	if (site.credentials.logonType_ == LogonType::anonymous) {
		return;
	}

	auto it = FindItem(site.server, challenge);
	if (it != m_passwordCache.end()) {
		it->password = site.credentials.GetPass();
	}
	else {
		t_passwordcache entry;
		entry.host = site.server.GetHost();
		entry.port = site.server.GetPort();
		entry.user = site.server.GetUser();
		entry.password = site.credentials.GetPass();
		entry.challenge = challenge;
		m_passwordCache.push_back(entry);
	}
}

bool CLoginManager::AskDecryptor(fz::public_key const& pub, bool allowForgotten, bool allowCancel)
{
}

fz::private_key CLoginManager::GetDecryptor(fz::public_key const& pub, bool * forgotten)
{
	auto it = decryptors_.find(pub);
	if (it != decryptors_.cend()) {
		if (!it->second && forgotten) {
			*forgotten = true;
		}
		return it->second;
	}

	for (auto const& pw : decryptorPasswords_) {
		auto priv = fz::private_key::from_password(pw, pub.salt_);
		if (priv && priv.pubkey() == pub) {
			decryptors_[pub] = priv;
			return priv;
		}
	}

	return fz::private_key();
}

void CLoginManager::Remember(const fz::private_key &key, std::string_view const& pass)
{
	decryptors_[key.pubkey()] = key;

	if (!pass.empty()) {
		for (auto const& pw : decryptorPasswords_) {
			if (pw == pass) {
				return;
			}
		}
		decryptorPasswords_.emplace_back(pass);
	}
}
