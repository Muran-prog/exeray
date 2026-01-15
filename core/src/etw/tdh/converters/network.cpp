/// @file network.cpp
/// @brief TDH to Network event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_network(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* /*strings*/
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Network);
    result.payload.category = event::Category::Network;
    
    switch (tdh_event.event_id) {
        case 10:
        case 26:
            result.operation = static_cast<uint8_t>(event::NetworkOp::Send);
            break;
        case 11:
        case 27:
            result.operation = static_cast<uint8_t>(event::NetworkOp::Receive);
            break;
        case 12:
        case 28:
        case 13:
        case 29:
            result.operation = static_cast<uint8_t>(event::NetworkOp::Connect);
            break;
        default:
            result.valid = false;
            return result;
    }
    
    result.payload.network.local_port = static_cast<uint16_t>(
        get_uint32_prop(tdh_event, L"sport"));
    result.payload.network.remote_port = static_cast<uint16_t>(
        get_uint32_prop(tdh_event, L"dport"));
    result.payload.network.local_addr = get_uint32_prop(tdh_event, L"saddr");
    result.payload.network.remote_addr = get_uint32_prop(tdh_event, L"daddr");
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
