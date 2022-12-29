// SPDX-License-Identifier: BSD-3-Clause
#include <optional>
#include <epan/packet.h>
#include <epan/proto_data.h>

#include "frameReassembly.hxx"
#include "frameReassemblyInternal.hxx"

namespace sol::frameReassembly
{
	using namespace internal;
	std::optional<frameFragment_t> frameFragment{};
	reassembly_table frameReassemblyTable{};

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
		}

		return 0;
	}

	void registerProtoInfo()
	{
		solAnalyzerFrameProtocol = proto_register_protocol(
			"SOL USB Analyzer Protocol Framing",
			"SOL_USB_Analyzer_Framing",
			"sol.analyzer.frame"
		);

		reassembly_table_register(&frameReassemblyTable, &addresses_ports_reassembly_table_functions);
	}

	void registerHandoff()
	{
		auto handle = register_dissector("sol.analyzer.frame", dissectFraming, solAnalyzerFrameProtocol);
		// Register for interface class 0xffU (application-defined)
		dissector_add_uint("usb.bulk", 0xffU, handle);
	}
} // namespace sol::frameReassembly
