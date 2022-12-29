// SPDX-License-Identifier: BSD-3-Clause
#ifndef SOL_FRAME_DISSECTOR_INTERNAL_HXX
#define SOL_FRAME_DISSECTOR_INTERNAL_HXX

#include <cstdint>
#include <substrate/utility>

namespace sol::frameDissector::internal
{
	static int32_t solAnalyzerFrameProtocol{-1};

	static int32_t ettSOLAnalyzerFrame{-1};

	static auto ett
	{
		substrate::make_array({
			&ettSOLAnalyzerFrame,
		})
	};
} // namespace sol::frameDissector::internal

#endif /*SOL_FRAME_DISSECTOR_INTERNAL_HXX*/
