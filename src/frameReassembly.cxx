// SPDX-License-Identifier: BSD-3-Clause
#include <optional>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <substrate/console>

#include "frameReassembly.hxx"
#include "frameReassemblyInternal.hxx"
#include "frameDissector.hxx"

using namespace std::literals::string_view_literals;
using substrate::console;

namespace sol::frameReassembly
{
	using namespace internal;
	std::optional<frameFragment_t> frameFragment{};
	reassembly_table frameReassemblyTable{};
	uint32_t processedFrames{};

	static void beginReassembly(tvbuff_t *buffer, packet_info *const pinfo, const uint32_t frameLength,
		const uint32_t bufferLength, const uint32_t offset, const uint32_t frameNumber)
	{
		if (!PINFO_FD_VISITED(pinfo))
		{
			frameFragment_t frame{frameLength, bufferLength - offset, frameNumber};
			frameFragment = frame;
			fragment_add(&frameReassemblyTable, buffer, offset, pinfo, frameNumber, nullptr, 0,
				frame.fragmentLength, TRUE);
		}
	}

	static int processFrames(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, const bool fragment)
	{
		// Get any possible frame information from the proto-specific data in slot 1
		const auto *const startingFrameNumber{static_cast<const uint32_t *>(p_get_proto_data(wmem_file_scope(),
			pinfo, solAnalyzerFrameProtocol, 1))};
		if (!startingFrameNumber)
		{
			// Set up a new starting frame number for this frame if we've never processed it before.
			auto *const frameNumber{g_new(uint32_t, 1)};
			*frameNumber = processedFrames;
			p_add_proto_data(wmem_file_scope(), pinfo, solAnalyzerFrameProtocol, 1, frameNumber);
		}
		auto frameNumber
		{
			[=]()
			{
				const auto *const fragmentFrameNumber{p_get_proto_data(wmem_file_scope(), pinfo,
					solAnalyzerFrameProtocol, 0)};
				if (fragment || !fragmentFrameNumber)
				{
					if (startingFrameNumber)
						return *startingFrameNumber;
					return processedFrames;
				}
				return *static_cast<const uint32_t *>(fragmentFrameNumber) + 1U;
			}()
		};

		uint32_t bufferLength = tvb_captured_length(buffer);
		for (uint32_t offset{}; offset < bufferLength;)
		{
			// ntohs == be16toHost
			const auto frameLength{tvb_get_ntohs(buffer, offset) + 2U};
			const int32_t remainder = bufferLength - (offset + frameLength);
			// Fragment, needs reassembly.
			if (remainder < 0)
			{
				beginReassembly(buffer, pinfo, frameLength, bufferLength, offset, frameNumber);
				break;
			}
			// Not a fragment, excellent! Process it up to the frame dissector.
			auto *const frameBuffer{tvb_new_subset_length(buffer, offset, frameLength)};
			call_dissector(sol::frameDissector::solAnalyzerFrameDissector, frameBuffer, pinfo, tree);
			++frameNumber;
			offset += frameLength;
			// If there is a single-byte fragment left over, it will need reassembly (special-cased)
			if (remainder == 1)
			{
				const auto frameByte{tvb_get_guint8(buffer, offset)};
				beginReassembly(buffer, pinfo, (uint16_t{frameByte} << 8U) | 2U, bufferLength, offset, frameNumber);
				offset += remainder;
			}
		}
		if (!startingFrameNumber || *startingFrameNumber + 1U == processedFrames)
			processedFrames = frameNumber;
		if (PINFO_FD_VISITED(pinfo) && !fragment && startingFrameNumber)
			col_append_fstr(pinfo->cinfo, COL_INFO, "[Frames #%u-#%u]", *startingFrameNumber, frameNumber - 1U);
		return bufferLength;
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

		proto_item *item{};
		auto *const subtree{proto_tree_add_subtree(tree, buffer, 0, -1, ettFrames, &item, "SOL USB Analyzer frames")};
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SOL USB Analyzer");

		// If the frame has been involved in reassemblembly
		if (fragment)
		{
			const auto frameNumber{*static_cast<uint32_t *>(p_get_proto_data(wmem_file_scope(), pinfo,
				solAnalyzerFrameProtocol, 0))};

			// If this packet is not the final reassembled frame
			if (fragment->reassembled_in != pinfo->num)
			{
				col_add_fstr(pinfo->cinfo, COL_INFO, "[Fragmented Frame #%u] Size %u", frameNumber, fragment->len);

				// Add the raw buffer data to the tree
				proto_tree_add_item(tree, hfFrameData, fragment->tvb_data, 0, -1, ENC_NA);
				// And output the frame reassembly hyperlink in tree due to this not being the
				// final frame in the assembly sequence
				process_reassembled_data(fragment->tvb_data, 0, pinfo, "Reassembled Analyser Data Frame",
					fragment, &solAnalyzerFrameItems, NULL, tree);
				return len;
			}

			auto *const frameBuffer{process_reassembled_data(buffer, 0, pinfo, "Reassembled Analyzer Data Frame",
				fragment, &solAnalyzerFrameItems, NULL, tree)};
			const auto fragmentLength
			{
				[](const fragment_head *const fragmentHead)
				{
					const fragment_item *fragmentItem{fragmentHead->next};
					while (fragmentItem->next)
						fragmentItem = fragmentItem->next;
					return fragmentItem->len;
				}(fragment)
			};
			// Process the reassembled part of the frame
			if (fragmentLength < len)
			{
				processFrames(frameBuffer, pinfo, subtree, true);
				buffer = tvb_new_subset_length(buffer, fragmentLength, len - fragmentLength);
			}
			else
				buffer = frameBuffer;
			// Now handle the rest

			// Set the info column text appropriately
			col_add_fstr(pinfo->cinfo, COL_INFO, "[Defragmented Frame #%u (%u)]", frameNumber, fragment->datalen);
		}
		// If we're in the middle of reassembly, and have a valid unvisited frame
		else if (frameFragment && !PINFO_FD_VISITED(pinfo))
		{
			// Extract the frame reference
			auto &frame{*frameFragment};
			// Handle the special-case of the previous chunk of the fragment being just one byte
			if (frame.fragmentLength == 1U)
			{
				const auto frameByte{tvb_get_guint8(buffer, 0)};
				frame.totalLength += frameByte;
			}
			// frame.fragmentLength is the mount of data seen thus far, not the total length of the frame
			// thus is the same as an offset into the total frame
			const auto offset{frame.fragmentLength};
			// Add the frame pointer into the protocol specific data's slot 0
			p_add_proto_data(wmem_file_scope(), pinfo, solAnalyzerFrameProtocol, 0, frame.frameNumberPtr);
			// If this packet does not complete the frame reassembly
			if (offset + len < frame.totalLength)
			{
				col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented frame, Size %u", len);
				// Accumulate total length
				frame.fragmentLength += len;
				// Append the buffer to the frame reassembly table
				fragment_add(&frameReassemblyTable, buffer, 0, pinfo, frame.frameNumber, nullptr, offset, len, TRUE);
				// Add raw frame data to tree
				proto_tree_add_item(tree, hfFrameData, buffer, 0, -1, ENC_NA);
				// Signal to the device disector that we've completed processing this packet
				return len;
			}

			// Append column info with the total length of the reassembled frame
			col_add_fstr(pinfo->cinfo, COL_INFO, "Frame, Size %u", frame.totalLength);
			// fragment_add doesn't deal with completed reassembly, therefore we need to use the check version
			// the FALSE indicates that the call will add the fully reassembled frame to the reassembled section
			// of the reassembly table.
			fragment = fragment_add_check(&frameReassemblyTable, buffer, 0, pinfo, frame.frameNumber, NULL, offset,
				frame.totalLength - offset, FALSE);
			// Finally, reset the frame reassembly state having grabbed the frame number
			const auto frameNumber{frame.frameNumber};
			frameFragment.reset();

			// If we have a valid reassembled frame
			if (fragment)
			{
				auto *const frameBuffer{process_reassembled_data(buffer, 0, pinfo, "Reassembled Analyzer Data Frame",
					fragment, &solAnalyzerFrameItems, NULL, tree)};
				// If the frame did not consume the entire incomming buffer, process the reassembled frame specially
				if (offset + len > frame.totalLength)
				{
					processFrames(frameBuffer, pinfo, subtree, true);
					const auto fragmentLength{frame.totalLength - offset};
					buffer = tvb_new_subset_length(buffer, fragmentLength, len - fragmentLength);
				}
				else
					buffer = frameBuffer;
			}
			else
			{
				// For some reason the fragment check return failed, properly print an error
				console.error("fragment_add_check() returned nullptr for frame reassembly ("sv, frameNumber, ")"sv);
				// Then grab whatever's left of this frame to process below.
				const auto frameOffset{frame.totalLength - offset};
				const auto frameLength{len - frameOffset};
				buffer = tvb_new_subset_length(buffer, frameOffset, frameLength);
			}

			// If we are in an invalid state, abort
			if (!buffer)
			{
				console.error("sol::frameReassembly::dissectFraming("sv, frameNumber,
					"): buffer is invalid, dazed and confused"sv);
				return len;
			}
		}
		else if (PINFO_FD_VISITED(pinfo))
			col_set_str(pinfo->cinfo, COL_INFO, "");

		// The possible states we can be in for the following block of code are as follows:
		// 1: We are in the second pass and have a fully reassembled frame OR
		// 2: We are in the second pass and the frame did not require and reassembly OR
		// 3: We are in the first pass and we have just completed reassembly OR
		// 4: We are in the first pass and have no clue if the packet needs reassembly or not

		return processFrames(buffer, pinfo, subtree, false);
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
