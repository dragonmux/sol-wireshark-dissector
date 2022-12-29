// SPDX-License-Identifier: BSD-3-Clause
#include <epan/packet.h>

#include "frameDissector.hxx"
#include "frameDissectorInternal.hxx"

namespace sol::frameDissector
{
	using namespace internal;

	int dissectFrame(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
	{
		proto_item *protocol{};
		auto *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettSOLAnalyzerFrame, &protocol,
			"SOL Analyzer Frame");
		return 0;
	}

	void registerProtoInfo()
	{
		solAnalyzerFrameProtocol = proto_register_protocol(
			"SOL USB Analyzer Protocol",
			"SOL_USB_Analyzer",
			"sol.analyzer"
		);

		proto_register_subtree_array(ett.data(), ett.size());
	}

	void registerHandoff()
	{
		auto handle = register_dissector("sol.analyzer.frame", dissectFrame, solAnalyzerFrameProtocol);
	}
} // namespace sol::frameDissector
