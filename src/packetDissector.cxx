// SPDX-License-Identifier: BSD-3-Clause
#include <epan/packet.h>

#include "packetDissector.hxx"

namespace sol::packetDissector
{
	int dissectPacket(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
	{
		return 0;
	}

	void registerProtoInfo()
	{
		usbPacketProtocol = proto_register_protocol(
			"SOL USB Protocol",
			"SOL_USB_Proto",
			"sol.analyzer.usb"
		);
	}

	void registerHandoff()
	{
		auto handle = register_dissector("sol.analyzer.usb.packet", dissectPacket, usbPacketProtocol);
	}
} // namespace sol::packetDissector
