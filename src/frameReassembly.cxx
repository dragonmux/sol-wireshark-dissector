// SPDX-License-Identifier: BSD-3-Clause
#include <optional>
#include <epan/packet.h>
#include <epan/proto_data.h>

#include "frameReassembly.hxx"
#include "frameReassemblyInternal.hxx"
#include "frameDissector.hxx"

namespace sol::frameReassembly
{
	using namespace internal;
	std::optional<frameFragment_t> frameFragment{};
	reassembly_table frameReassemblyTable{};
	uint32_t processedFrames{};

	static int processFrames(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree)
	{
		uint32_t bufferLength = tvb_captured_length(buffer);
		uint32_t offset{};
		for (; offset < bufferLength; )
		{
			// ntohs == be16toHost
			const auto frameLength = tvb_get_ntohs(buffer, offset) + 2U;
			const int32_t remainder = bufferLength - (offset + frameLength);
			// Fragment, needs reassembly.
			if (remainder < 0)
			{
				frameFragment_t frame{frameLength, bufferLength - offset, processedFrames};
				frameFragment = frame;
				fragment_add(&frameReassemblyTable, buffer, offset, pinfo, processedFrames, nullptr, 0,
					frame.fragmentLength, TRUE);
				break;
			}
			// Not a fragment, excellent! Process it up to the frame dissector.
			auto *const frameBuffer = tvb_new_subset_length(buffer, offset, frameLength);
			call_dissector(sol::frameDissector::solAnalyzerFrameDissector, frameBuffer, pinfo, tree);
			++processedFrames;
			offset += frameLength;
		}
		return offset;
	}

	static int dissectFraming(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
	{
		// Skip zero length or mismatched length packets
		uint32_t len = tvb_captured_length(buffer);
		if (!len || len != tvb_reported_length(buffer))
			return 0;

		// Return the fragment header for a reassembled frame if this frame has been reassembled, otherwise it's nullptr
		auto *fragment
		{
			[=]() noexcept -> fragment_head *
			{
				// If the frame has not been reassembled or visited, early exit
				if (!PINFO_FD_VISITED(pinfo))
					return nullptr;
				// If we've been visited, look up the frame number from the pinfo protocol specific data in slot 0
				auto *const frameNumber{p_get_proto_data(wmem_file_scope(), pinfo, solAnalyzerFrameProtocol, 0)};
				if (!frameNumber)
					return nullptr;
				// This frame has been reassembled, get it from the reassembly table
				return fragment_get_reassembled_id(&frameReassemblyTable, pinfo, *static_cast<uint32_t *>(frameNumber));
			}()
		};

		// If the frame has been reassembled
		if (fragment)
		{
			//
		}
		// If we're in the middle of reassembly, and have a valid frame
		else if (frameFragment)
		{
			return 0;
		}

		if (PINFO_FD_VISITED(pinfo))
			return len;

		// The possible states we can be in for the following block of code are as follows:
		// 1: We are in the second pass and have a fully reassembled frame OR
		// 2: We are in the second pass and the frame did not require and reassembly OR
		// 3: We are in the first pass and we have just completed reassembly OR
		// 4: We are in the first pass and have no clue if the packet needs reassembly or not

		return processFrames(buffer, pinfo, tree);
	}

	void registerProtoInfo()
	{
		solAnalyzerFrameProtocol = proto_register_protocol(
			"SOL USB Analyzer Protocol Framing",
			"SOL USB Analyzer Framing",
			"sol.analyzer.framing"
		);

		proto_register_field_array(solAnalyzerFrameProtocol, fields.data(), fields.size());
		// Generate subtree indices
		proto_register_subtree_array(ett.data(), ett.size());

		reassembly_table_register(&frameReassemblyTable, &addresses_ports_reassembly_table_functions);
	}

	void registerHandoff()
	{
		auto handle = register_dissector("sol.analyzer.reassembly", dissectFraming, solAnalyzerFrameProtocol);
		// Register for EP1 IN against the device-level dissector table
		dissector_add_uint("sol.analyzer.ep", 0x81U, handle);
	}
} // namespace sol::frameReassembly
