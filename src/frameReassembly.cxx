// SPDX-License-Identifier: BSD-3-Clause
#include <epan/packet.h>
extern "C"
{
#include <epan/reassemble.h>
}

#include "frameReassembly.hxx"
#include "frameReassemblyInternal.hxx"

namespace sol::frameReassembly
{
	using namespace internal;
	reassembly_table frameReassemblyTable{};

	static int dissectFraming(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
	{
		/* Skip zero length or mismatched length packets */
		uint32_t len = tvb_captured_length(buffer);
		if (!len || len != tvb_reported_length(buffer))
			return 0;

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
		/* Register for interface class 0xffU (application-defined) */
		dissector_add_uint("usb.bulk", 0xffU, handle);
	}
} // namespace sol::frameReassembly
