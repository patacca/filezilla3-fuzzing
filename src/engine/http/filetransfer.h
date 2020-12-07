#ifndef FILEZILLA_ENGINE_HTTP_FILETRANSFER_HEADER
#define FILEZILLA_ENGINE_HTTP_FILETRANSFER_HEADER

#include "httpcontrolsocket.h"

#include <libfilezilla/file.hpp>

class CServerPath;

class CHttpFileTransferOpData final : public CFileTransferOpData, public CHttpOpData
{
public:
	CHttpFileTransferOpData(CHttpControlSocket & controlSocket, CFileTransferCommand const&);
	CHttpFileTransferOpData(CHttpControlSocket & controlSocket, fz::uri const& uri, std::string const& verb, std::string const& body, writer_factory_holder const& output_factory);

	virtual int Send() override;
	virtual int ParseResponse() override { return FZ_REPLY_INTERNALERROR; }
	virtual int SubcommandResult(int prevResult, COpData const& previousOperation) override;

private:
	int OnHeader();

	HttpRequestResponse rr_;
	writer_factory_holder output_factory_;

	int redirectCount_{};
};

#endif
