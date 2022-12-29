// SPDX-License-Identifier: BSD-3-Clause
#ifndef SOL_PACKET_DISSECTOR_HXX
#define SOL_PACKET_DISSECTOR_HXX

#include <cstdint>

namespace sol::packetDissector
{
	static int32_t usbPacketProtocol{-1};

	void registerProtoInfo();
	void registerHandoff();
} // namespace sol::packetDissector

#endif /*SOL_PACKET_DISSECTOR_HXX*/
