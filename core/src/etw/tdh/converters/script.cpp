/// @file script.cpp
/// @brief TDH to Script event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_script(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Script);
    result.payload.category = event::Category::Script;
    
    switch (tdh_event.event_id) {
        case 4103: result.operation = static_cast<uint8_t>(event::ScriptOp::Module); break;
        case 4104: result.operation = static_cast<uint8_t>(event::ScriptOp::Execute); break;
        default:
            result.valid = false;
            return result;
    }
    
    std::wstring content = get_wstring_prop(tdh_event, L"ScriptBlockText");
    if (content.empty()) {
        content = get_wstring_prop(tdh_event, L"ContextInfo");
    }
    if (!content.empty() && strings != nullptr) {
        result.payload.script.script_block = strings->intern_wide(content);
    } else {
        result.payload.script.script_block = event::INVALID_STRING;
    }
    
    result.payload.script.context = event::INVALID_STRING;
    result.payload.script.is_suspicious = 0;
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
