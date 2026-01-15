/// @file amsi.cpp
/// @brief TDH to AMSI event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_amsi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Amsi;
    result.payload.category = event::Category::Amsi;
    result.operation = static_cast<uint8_t>(event::AmsiOp::Scan);
    
    std::wstring app_name = get_wstring_prop(tdh_event, L"appname");
    if (!app_name.empty() && strings != nullptr) {
        result.payload.amsi.app_name = strings->intern_wide(app_name);
    } else {
        result.payload.amsi.app_name = event::INVALID_STRING;
    }
    
    std::wstring content = get_wstring_prop(tdh_event, L"content");
    if (!content.empty() && strings != nullptr) {
        result.payload.amsi.content = strings->intern_wide(content);
    } else {
        result.payload.amsi.content = event::INVALID_STRING;
    }
    
    result.payload.amsi.scan_result = get_uint32_prop(tdh_event, L"scanResult");
    result.payload.amsi.content_size = get_uint32_prop(tdh_event, L"contentSize");
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
