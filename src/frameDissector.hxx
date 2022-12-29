// SPDX-License-Identifier: BSD-3-Clause
// SPDX-License-Identifier: BSD-3-Clause
#ifndef SOL_FRAME_DISSECTOR_HXX
#define SOL_FRAME_DISSECTOR_HXX

#include <cstdint>

namespace sol::frameDissector
{
	static int32_t solAnalyzerFrameProtocol{-1};

	void registerProtoInfo();
	void registerHandoff();
} // namespace sol::frameDissector

#endif /*SOL_FRAME_DISSECTOR_HXX*/
