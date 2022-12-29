// SPDX-License-Identifier: BSD-3-Clause
#include <epan/packet.h>

#include "frameDissector.hxx"
#include "frameDissectorInternal.hxx"

namespace sol::frameDissector
{
	using namespace internal;

	int dissectFrame(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
	{
		return 0;
	}

	void registerProtoInfo()
	{
		solAnalyzerFrameProtocol = proto_register_protocol(
			"SOL USB Analyzer Protocol",
			"SOL_USB_Analyzer",
			"sol.analyzer"
		);
	}

	void registerHandoff()
	{
		auto handle = register_dissector("sol.analyzer.frame", dissectFrame, solAnalyzerFrameProtocol);
	}
} // namespace sol::frameDissector
