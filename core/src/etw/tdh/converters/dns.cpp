/// @file dns.cpp
/// @brief TDH to DNS event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_dns(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Dns);
    result.payload.category = event::Category::Dns;
    
    switch (tdh_event.event_id) {
        case 3006: result.operation = static_cast<uint8_t>(event::DnsOp::Response); break;
        case 3008: 
            result.operation = static_cast<uint8_t>(event::DnsOp::Failure);
            result.status = event::Status::Error;
            break;
        default:
            result.valid = false;
            return result;
    }
    
    std::wstring query_name = get_wstring_prop(tdh_event, L"QueryName");
    if (!query_name.empty() && strings != nullptr) {
        result.payload.dns.domain = strings->intern_wide(query_name);
    } else {
        result.payload.dns.domain = event::INVALID_STRING;
    }
    
    result.payload.dns.query_type = get_uint32_prop(tdh_event, L"QueryType");
    result.payload.dns.resolved_ip = get_uint32_prop(tdh_event, L"QueryResults");
    result.payload.dns.is_suspicious = 0;
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
