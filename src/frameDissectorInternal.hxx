// SPDX-License-Identifier: BSD-3-Clause
#ifndef SOL_FRAME_DISSECTOR_INTERNAL_HXX
#define SOL_FRAME_DISSECTOR_INTERNAL_HXX

#include <cstdint>
#include <substrate/utility>
#include <epan/packet.h>

namespace sol::frameDissector::internal
{
	static int32_t solAnalyzerFrameProtocol{-1};

	static int32_t ettSOLAnalyzerFrame{-1};

	static int32_t hfFrameLength{-1};
	static int32_t hfFrameData{-1};

	static auto ett
	{
		substrate::make_array
		({
			&ettSOLAnalyzerFrame,
		})
	};

	static auto fields
	{
		substrate::make_array<hf_register_info>
		({
			{
				&hfFrameLength,
				{
					"Length", "sol.analyzer.frame.length", FT_UINT16, BASE_DEC_HEX,
					nullptr, 0, "SOL USB Analyzer frame length", HFILL
				}
			},
			{
				&hfFrameData,
				{
					"Data", "sol.analyzer.frame.data", FT_BYTES, BASE_NONE,
					nullptr, 0, "SOL USB Analyzer frame data", HFILL
				}
			},
		})
	};
} // namespace sol::frameDissector::internal

#endif /*SOL_FRAME_DISSECTOR_INTERNAL_HXX*/
