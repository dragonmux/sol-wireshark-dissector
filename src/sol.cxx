// SPDX-License-Identifier: BSD-3-Clause
#include <epan/packet.h>

#include "frameReassembly.hxx"
#include "frameDissector.hxx"
#include "packetDissector.hxx"

extern "C"
{
	extern const char *const plugin_version WS_DLL_PUBLIC_DEF;
	extern const int plugin_want_major WS_DLL_PUBLIC_DEF;
	extern const int plugin_want_minor WS_DLL_PUBLIC_DEF;
	WS_DLL_PUBLIC void plugin_register();
}

const char *const plugin_version = "0.0.1";
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

// Register the native wireshark plugin
void plugin_register()
{
	// Define the internal plugin variables for the dissectors
	static proto_plugin framingDissector;
	static proto_plugin frameDissector;
	static proto_plugin packetDissector;

	framingDissector.register_protoinfo = sol::frameReassembly::registerProtoInfo;
	framingDissector.register_handoff = sol::frameReassembly::registerHandoff;
	proto_register_plugin(&framingDissector);

	frameDissector.register_protoinfo = sol::frameDissector::registerProtoInfo;
	frameDissector.register_handoff = sol::frameDissector::registerHandoff;
	proto_register_plugin(&frameDissector);

	packetDissector.register_protoinfo = sol::packetDissector::registerProtoInfo;
	packetDissector.register_handoff = sol::packetDissector::registerHandoff;
	proto_register_plugin(&packetDissector);
}
