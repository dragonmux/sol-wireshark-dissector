// SPDX-License-Identifier: BSD-3-Clause
#ifndef SOL_FRAME_DISSECTOR_HXX
#define SOL_FRAME_DISSECTOR_HXX

#include <epan/packet.h>

namespace sol::frameDissector
{
	extern dissector_handle_t solAnalyzerFrameDissector;

	void registerProtoInfo();
	void registerHandoff();
} // namespace sol::frameDissector

#endif /*SOL_FRAME_DISSECTOR_HXX*/
