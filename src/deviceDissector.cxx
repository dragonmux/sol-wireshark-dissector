// SPDX-License-Identifier: BSD-3-Clause
#include <cstdint>
#include <stdexcept>
#include <epan/address_types.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-usb.h>

#include "deviceDissector.hxx"

namespace sol::deviceDissector
{
	static int32_t solAnalyzerDevice;
	static int32_t usbAddressType;
	dissector_table_t deviceDissectorTable;

	static int dissectDevice(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
	{
		if (pinfo->src.type != usbAddressType || pinfo->dst.type != usbAddressType)
			return 0;

		const auto *const srcAddress = static_cast<const usb_address_t *>(pinfo->src.data);
		const auto *const dstAddress = static_cast<const usb_address_t *>(pinfo->dst.data);

		const uint8_t endpoint
		{
			[=]() -> uint8_t
			{
				if (srcAddress->device != UINT32_MAX)
					return static_cast<uint8_t>(GUINT32_FROM_LE(srcAddress->endpoint)) | 0x80U;
				if (dstAddress->device != UINT32_MAX)
					return static_cast<uint8_t>(GUINT32_FROM_LE(dstAddress->endpoint));
				throw std::runtime_error{"Neither address was valid"};
			}()
		};

		return dissector_try_uint(deviceDissectorTable, endpoint, buffer, pinfo, tree);
	}

	void registerProtoInfo()
	{
		solAnalyzerDevice = proto_register_protocol(
			"SOL USB Analyzer",
			"SOL USB Analyzer",
			"sol.analyzer"
		);

		deviceDissectorTable = register_dissector_table("sol.analyzer.ep", "SOL USB Analyzer endpoint",
			solAnalyzerDevice, FT_UINT32, BASE_HEX);
		usbAddressType = address_type_get_by_name("AT_USB");
	}

	void registerHandoff()
	{
		const auto handle = register_dissector("sol.analyzer.device", dissectDevice, solAnalyzerDevice);
		// Register for the product 1d50:615b which is the analyser
		dissector_add_uint("usb.product", 0x1d50'615bU, handle);
	}
} // namespace sol::deviceDissector
