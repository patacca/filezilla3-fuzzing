#include "../include/libfilezilla_engine.h"
#include "../engine/directorylistingparser.h"

#include <libfilezilla/format.hpp>
#include <libfilezilla/util.hpp>

#include <string.h>

int main(int argc, char **argv)
{
	char entry[] = "xxx"

	CServer server;
	server.SetType(DEFAULT);

	CDirectoryListingParser parser(0, server);

	size_t len = 3;
	//~ char* data = new char[len];
	//~ memcpy(data, entry.data.c_str(), len);
	//~ parser.AddData(data, len);
	parser.AddData(entry, len);

	//~ CDirectoryListing listing = parser.Parse(CServerPath());

	//~ std::string msg = fz::sprintf("Data: %s, count: %u", entry.data, listing.size());
	//~ fz::replace_substrings(msg, "\r", std::string());
	//~ fz::replace_substrings(msg, "\n", std::string());

	//~ CPPUNIT_ASSERT_MESSAGE(msg, listing.size() == 1);

	//~ msg = fz::sprintf("Data: %s  Expected:\n%s\n  Got:\n%s", entry.data, entry.reference.dump(), listing[0].dump());
	//~ CPPUNIT_ASSERT_MESSAGE(msg, listing[0] == entry.reference);
	
	return 0;
}
