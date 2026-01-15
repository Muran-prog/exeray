/// @file registry.cpp
/// @brief TDH to Registry event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_registry(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Registry);
    result.payload.category = event::Category::Registry;
    
    switch (tdh_event.event_id) {
        case 1: result.operation = static_cast<uint8_t>(event::RegistryOp::CreateKey); break;
        case 2: result.operation = static_cast<uint8_t>(event::RegistryOp::QueryValue); break;
        case 5: result.operation = static_cast<uint8_t>(event::RegistryOp::SetValue); break;
        case 6: result.operation = static_cast<uint8_t>(event::RegistryOp::DeleteValue); break;
        default:
            result.valid = false;
            return result;
    }
    
    std::wstring key_name = get_wstring_prop(tdh_event, L"KeyName");
    if (key_name.empty()) {
        key_name = get_wstring_prop(tdh_event, L"RelativeName");
    }
    if (!key_name.empty() && strings != nullptr) {
        result.payload.registry.key_path = strings->intern_wide(key_name);
    } else {
        result.payload.registry.key_path = event::INVALID_STRING;
    }
    
    std::wstring value_name = get_wstring_prop(tdh_event, L"ValueName");
    if (!value_name.empty() && strings != nullptr) {
        result.payload.registry.value_name = strings->intern_wide(value_name);
    } else {
        result.payload.registry.value_name = event::INVALID_STRING;
    }
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
