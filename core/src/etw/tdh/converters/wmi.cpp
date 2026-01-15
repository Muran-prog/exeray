/// @file wmi.cpp
/// @brief TDH to WMI event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_wmi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Wmi);
    result.payload.category = event::Category::Wmi;
    
    switch (tdh_event.event_id) {
        case 5: result.operation = static_cast<uint8_t>(event::WmiOp::Connect); break;
        case 11: result.operation = static_cast<uint8_t>(event::WmiOp::Query); break;
        case 22: result.operation = static_cast<uint8_t>(event::WmiOp::Subscribe); break;
        case 23: result.operation = static_cast<uint8_t>(event::WmiOp::ExecMethod); break;
        default:
            result.valid = false;
            return result;
    }
    
    std::wstring ns = get_wstring_prop(tdh_event, L"NamespaceName");
    if (!ns.empty() && strings != nullptr) {
        result.payload.wmi.wmi_namespace = strings->intern_wide(ns);
    } else {
        result.payload.wmi.wmi_namespace = event::INVALID_STRING;
    }
    
    std::wstring query = get_wstring_prop(tdh_event, L"Query");
    if (query.empty()) {
        query = get_wstring_prop(tdh_event, L"ClassName");
    }
    if (!query.empty() && strings != nullptr) {
        result.payload.wmi.query = strings->intern_wide(query);
    } else {
        result.payload.wmi.query = event::INVALID_STRING;
    }
    
    result.payload.wmi.is_remote = false;
    result.payload.wmi.is_suspicious = (tdh_event.event_id == 22);
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
