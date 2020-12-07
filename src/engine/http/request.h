#ifndef FILEZILLA_ENGINE_HTTP_REQUEST_HEADER
#define FILEZILLA_ENGINE_HTTP_REQUEST_HEADER

#include "httpcontrolsocket.h"

#include <libfilezilla/buffer.hpp>

class CServerPath;

enum requestStates
{
	request_done = 0,

	request_init = 1,
	request_wait_connect = 2,
	request_send = 4,
	request_send_wait_for_read = 8,
	request_reading = 16,

	request_send_mask = 0xf
};

class CHttpRequestOpData final : public COpData, public CHttpOpData, fz::event_handler
{
public:
	CHttpRequestOpData(CHttpControlSocket & controlSocket, std::shared_ptr<HttpRequestResponseInterface> const& request);
	CHttpRequestOpData(CHttpControlSocket & controlSocket, std::deque<std::shared_ptr<HttpRequestResponseInterface>> && requests);
	virtual ~CHttpRequestOpData();

	virtual int Send() override;
	virtual int ParseResponse() override { return FZ_REPLY_INTERNALERROR; }
	virtual int SubcommandResult(int prevResult, COpData const& previousOperation) override;
	virtual int Reset(int result) override;

	void AddRequest(std::shared_ptr<HttpRequestResponseInterface> const& rr);

	int OnReceive(bool repeatedProcessing);
	int OnReceive(writer_base* writer);

private:
	virtual void operator()(fz::event_base const& ev) override;
	void OnLocalData(reader_base * r);

	int ParseReceiveBuffer();
	int ParseHeader();
	int ProcessCompleteHeader();
	int ParseChunkedData();
	int ProcessData(unsigned char* data, size_t & len);
	int FinalizeResponseBody();

	std::deque<std::shared_ptr<HttpRequestResponseInterface>> requests_;

	size_t send_pos_{};


	enum transferEncodings
	{
		identity,
		chunked,
		unknown
	};

	fz::buffer recv_buffer_;
	struct read_state
	{
		transferEncodings transfer_encoding_{unknown};

		struct t_chunkData
		{
			bool getTrailer{};
			bool terminateChunk{};
			uint64_t size{};
		} chunk_data_;

		int64_t responseContentLength_{-1};
		int64_t receivedData_{};

		bool keep_alive_{};
		bool eof_{};
	};
	read_state read_state_;

	uint64_t dataToSend_{};
};

#endif
