#include "../include/libfilezilla_engine.h"
#include "../engine/directorylistingparser.h"

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

		CServer server;
		server.SetType(DEFAULT);

		CDirectoryListingParser parser(0, server);

		char* data = new char[aflBufLen];
		memcpy(data, aflBuf, aflBufLen);
		parser.AddData(data, aflBufLen);

		CDirectoryListing listing = parser.Parse(CServerPath());
		printf("Data: %s  \n  Got:\n%s", aflBuf, listing[0].dump().c_str());
		

		//~ std::string msg = fz::sprintf("Data: %s, count: %u", entry.data, listing.size());
		//~ fz::replace_substrings(msg, "\r", std::string());
		//~ fz::replace_substrings(msg, "\n", std::string());

		//~ CPPUNIT_ASSERT_MESSAGE(msg, listing.size() == 1);

		//~ msg = fz::sprintf("Data: %s  Expected:\n%s\n  Got:\n%s", entry.data, entry.reference.dump(), listing[0].dump());
		//~ CPPUNIT_ASSERT_MESSAGE(msg, listing[0] == entry.reference);
	}
	
	return 0;
}
