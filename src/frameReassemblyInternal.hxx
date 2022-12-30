// SPDX-License-Identifier: BSD-3-Clause
#ifndef SOL_PACKET_DISSECTOR_INTERNAL_HXX
#define SOL_PACKET_DISSECTOR_INTERNAL_HXX

#include <cstdint>
#include <substrate/utility>

extern "C"
{
#include <epan/reassemble.h>
}

namespace sol::frameReassembly::internal
{
	static int32_t solAnalyzerFrameProtocol{-1};

	struct frameFragment_t final
	{
		uint32_t totalLength;
		uint32_t fragmentLength;
		uint32_t frameNumber;
		uint32_t *frameNumberPtr;

		frameFragment_t(const uint32_t frameLength, const uint32_t fragLength, const uint32_t frameNum) noexcept :
			totalLength{frameLength}, fragmentLength{fragLength}, frameNumber{frameNum},
			frameNumberPtr
			{
				[](const uint32_t frameNumber)
				{
					auto *const result{g_new0(uint32_t, 1)};
					*result = frameNumber;
					return result;
				}(frameNum)
			} { }
	};

	static int32_t ettFrames{-1};

	static int32_t hfFrameData{-1};

	static int32_t ettFrameFragment{-1};
	static int32_t ettFrameFragments{-1};

	static int32_t hfFrameFragment{-1};
	static int32_t hfFrameFragments{-1};
	static int32_t hfFrameFragmentOverlap{-1};
	static int32_t hfFrameFragmentOverlapConflict{-1};
	static int32_t hfFrameMultipleTails{-1};
	static int32_t hfFrameTooLongFragment{-1};
	static int32_t hfFrameFragmentError{-1};
	static int32_t hfFrameFragmentCount{-1};
	static int32_t hfFrameReassembledIn{-1};
	static int32_t hfFrameReassembledLength{-1};
	static int32_t hfFrameReassembledData{-1};

	static auto ett
	{
		substrate::make_array
		({
			&ettFrames,
			&ettFrameFragment,
			&ettFrameFragments,
		})
	};

	static auto fields
	{
		substrate::make_array<hf_register_info>
		({
			{
				&hfFrameData,
				{
					"Frame Data", "sol.analyzer.framing.frame_data",
					FT_BYTES, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame data", HFILL
				},
			},

			{
				&hfFrameFragment,
				{
					"SOL USB Analayzer Frame Fragment", "sol.analyzer.framing.frag",
					FT_FRAMENUM, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame fragment", HFILL
				}
			},
			{
				&hfFrameFragments,
				{
					"SOL USB Analayzer Frame Fragments", "sol.analyzer.framing.fragments",
					FT_NONE, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame fragments", HFILL
				}
			},
			{
				&hfFrameFragmentOverlap,
				{
					"Segment overlap", "sol.analyzer.framing.frag.overlap",
					FT_BOOLEAN, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame fragments overlap", HFILL
				}
			},
			{
				&hfFrameFragmentOverlapConflict,
				{
					"Conflicting data in segment overlap", "sol.analyzer.framing.frag.overlap.conflict",
					FT_BOOLEAN, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame fragment overlap conflict", HFILL
				}
			},
			{
				&hfFrameMultipleTails,
				{
					"Multiple tail segments found", "sol.analyzer.framing.frag.multiple_tails",
					FT_BOOLEAN, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame fragment multiple tails", HFILL
				}
			},
			{
				&hfFrameTooLongFragment,
				{
					"Segment too long", "sol.analyzer.framing.frag.too_long_fragment",
					FT_BOOLEAN, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame fragment is too long", HFILL
				}
			},
			{
				&hfFrameFragmentError,
				{
					"Reassembling error", "sol.analyzer.framing.frag.error",
					FT_FRAMENUM, BASE_NONE, nullptr, 0, "SOL USB Analyzer Frame fragment error", HFILL
				}
			},
			{
				&hfFrameFragmentCount,
				{
					"SOL USB Analayzer Frame Fragment Count", "sol.analyzer.framing.fragment_count",
					FT_UINT32, BASE_DEC, nullptr, 0, "SOL USB Analyzer frame fragment count", HFILL
				}
			},

			{
				&hfFrameReassembledIn,
				{
					"Reassembled frame in segment", "sol.analyzer.framing.reassembled_in",
					FT_FRAMENUM, BASE_NONE, nullptr, 0, "SOL USB Analyzer frame reassembled in", HFILL
				}
			},
			{
				&hfFrameReassembledLength,
				{
					"Reassembled frame length", "sol.analyzer.framing.reassembled.length",
					FT_UINT32, BASE_HEX_DEC, nullptr, 0, "SOL USB Analyzer reassembled frame length", HFILL
				}
			},
			{
				&hfFrameReassembledData,
				{
					"Reassembled frame data", "sol.analyzer.framing.reassembled.data",
					FT_BYTES, BASE_NONE, nullptr, 0, "SOL USB Analyzer reassembled frame data", HFILL
				}
			},
		})
	};

	static const fragment_items solAnalyzerFrameItems =
	{
		&ettFrameFragment,
		&ettFrameFragments,

		&hfFrameFragments,
		&hfFrameFragment,
		&hfFrameFragmentOverlap,
		&hfFrameFragmentOverlapConflict,
		&hfFrameMultipleTails,
		&hfFrameTooLongFragment,
		&hfFrameFragmentError,
		&hfFrameFragmentCount,

		&hfFrameReassembledIn,
		&hfFrameReassembledLength,
		&hfFrameReassembledData,

		"Frame fragments"
	};
} // namespace sol::frameReassembly::internal

#endif /*SOL_PACKET_DISSECTOR_INTERNAL_HXX*/
