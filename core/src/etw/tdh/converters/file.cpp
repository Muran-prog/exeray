/// @file file.cpp
/// @brief TDH to File event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_file(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::FileSystem;
    result.payload.category = event::Category::FileSystem;
    
    switch (tdh_event.event_id) {
        case 10: result.operation = static_cast<uint8_t>(event::FileOp::Create); break;
        case 11: result.operation = static_cast<uint8_t>(event::FileOp::Create); break;
        case 14: result.operation = static_cast<uint8_t>(event::FileOp::Read); break;
        case 15: result.operation = static_cast<uint8_t>(event::FileOp::Write); break;
        case 26: result.operation = static_cast<uint8_t>(event::FileOp::Delete); break;
        default:
            result.valid = false;
            return result;
    }
    
    std::wstring path = get_wstring_prop(tdh_event, L"FileName");
    if (path.empty()) {
        path = get_wstring_prop(tdh_event, L"OpenPath");
    }
    if (!path.empty() && strings != nullptr) {
        result.payload.file.path = strings->intern_wide(path);
    } else {
        result.payload.file.path = event::INVALID_STRING;
    }
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
