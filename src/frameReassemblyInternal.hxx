// SPDX-License-Identifier: BSD-3-Clause
#ifndef SOL_PACKET_DISSECTOR_INTERNAL_HXX
#define SOL_PACKET_DISSECTOR_INTERNAL_HXX

#include <cstdint>

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
					auto *const result = g_new0(uint32_t, 1);
					*result = frameNumber;
					return result;
				}(frameNum)
			} { }
	};
} // namespace sol::frameReassembly::internal

#endif /*SOL_PACKET_DISSECTOR_INTERNAL_HXX*/
