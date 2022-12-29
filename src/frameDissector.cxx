// SPDX-License-Identifier: BSD-3-Clause
#include <epan/packet.h>

#include "frameDissector.hxx"
#include "frameDissectorInternal.hxx"

namespace sol::frameDissector
{
	using namespace internal;

	dissector_handle_t solAnalyzerFrameDissector{nullptr};

	static int dissectFrame(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
	{
		proto_item *protocol{};
		auto *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettSOLAnalyzerFrame, &protocol,
			"SOL Analyzer Frame");
		uint32_t frameLength;
		proto_tree_add_item_ret_uint(subtree, hfFrameLength, buffer, 0, 2, ENC_BIG_ENDIAN, &frameLength);
		return 0;
	}

	void registerProtoInfo()
	{
		solAnalyzerFrameProtocol = proto_register_protocol(
			"SOL USB Analyzer Protocol",
			"SOL USB Analyzer Proto",
			"sol.analyzer.frame"
		);

		proto_register_field_array(solAnalyzerFrameProtocol, fields.data(), fields.size());
		proto_register_subtree_array(ett.data(), ett.size());
	}

	void registerHandoff()
	{
		solAnalyzerFrameDissector = register_dissector("sol.analyzer.frame", dissectFrame, solAnalyzerFrameProtocol);
	}
} // namespace sol::frameDissector
