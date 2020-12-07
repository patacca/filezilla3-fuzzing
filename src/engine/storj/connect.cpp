#include "../filezilla.h"

#include "connect.h"
#include "event.h"
#include "input_thread.h"
#include "../proxy.h"

#include "../../include/engine_options.h"

#include <libfilezilla/hash.hpp>
#include <libfilezilla/process.hpp>
#include <libfilezilla/uri.hpp>

int CStorjConnectOpData::Send()
{
	switch (opState)
	{
	case connect_init:
		{
			log(logmsg::status, _("Connecting to %s..."), currentServer_.Format(ServerFormat::with_optional_port, controlSocket_.credentials_));

			// Since the encryption passphrase changes based on site content, add a disambiguation
			auto const passphraseHash = fz::hex_encode<std::wstring>(fz::hmac_sha256(fz::to_utf8(controlSocket_.currentServer_.GetUser()), fz::to_utf8(controlSocket_.credentials_.GetPass())));
			if (passphraseHash != controlSocket_.currentServer_.GetExtraParameter("passphrase_hash")) {
				controlSocket_.currentServer_.SetExtraParameter("passphrase_hash", passphraseHash);
			}
			controlSocket_.engine_.AddNotification(std::make_unique<ServerChangeNotification>(controlSocket_.currentServer_));

			auto executable = fz::to_native(engine_.GetOptions().get_string(OPTION_FZSTORJ_EXECUTABLE));
			if (executable.empty()) {
				executable = fzT("fzstorj");
			}
			log(logmsg::debug_verbose, L"Going to execute %s", executable);

			std::vector<fz::native_string> args;
			controlSocket_.process_ = std::make_unique<fz::process>();
			if (!controlSocket_.process_->spawn(executable, args)) {
				log(logmsg::debug_warning, L"Could not create process");
				return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
			}

			controlSocket_.input_thread_ = std::make_unique<CStorjInputThread>(controlSocket_, *controlSocket_.process_);
			if (!controlSocket_.input_thread_->spawn(engine_.GetThreadPool())) {
				log(logmsg::debug_warning, L"Thread creation failed");
				controlSocket_.input_thread_.reset();
				return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
			}
		}
		return FZ_REPLY_WOULDBLOCK;
	case connect_host:
		return controlSocket_.SendCommand(fz::sprintf(L"host %s", currentServer_.Format(ServerFormat::with_port)));
	case connect_user:
		return controlSocket_.SendCommand(fz::sprintf(L"key %s", currentServer_.GetUser()), fz::sprintf(L"key %s", std::wstring(currentServer_.GetUser().size(), '*')));
	case connect_pass:
		{
			std::wstring pass = controlSocket_.credentials_.GetPass();
			if (pass.empty()) {
				log(logmsg::error, _("Encryption passphrase is not set"));
				return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
			}
			return controlSocket_.SendCommand(fz::sprintf(L"pass %s", pass), fz::sprintf(L"pass %s", std::wstring(pass.size(), '*')));
		}
	default:
		log(logmsg::debug_warning, L"Unknown op state: %d", opState);
		break;
	}

	return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
}

int CStorjConnectOpData::ParseResponse()
{
	if (controlSocket_.result_ != FZ_REPLY_OK) {
		return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
	}

	switch (opState)
	{
	case connect_init:
		if (controlSocket_.response_ != fz::sprintf(L"fzStorj started, protocol_version=%d", FZSTORJ_PROTOCOL_VERSION)) {
			log(logmsg::error, _("fzstorj belongs to a different version of FileZilla"));
			return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
		}
		opState = connect_host;
		break;
	case connect_host:
		opState = connect_user;
		break;
	case connect_user:
		opState = connect_pass;
		break;
	case connect_pass:
		return FZ_REPLY_OK;
		break;
	default:
		log(logmsg::debug_warning, L"Unknown op state: %d", opState);
		return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
	}

	return FZ_REPLY_CONTINUE;
}
