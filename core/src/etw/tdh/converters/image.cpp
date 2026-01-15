/// @file image.cpp
/// @brief TDH to Image event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_image(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Image);
    result.payload.category = event::Category::Image;
    
    switch (tdh_event.event_id) {
        case 10: result.operation = static_cast<uint8_t>(event::ImageOp::Load); break;
        case 2: result.operation = static_cast<uint8_t>(event::ImageOp::Unload); break;
        default:
            result.valid = false;
            return result;
    }
    
    result.payload.image.base_address = get_uint64_prop(tdh_event, L"ImageBase");
    result.payload.image.size = static_cast<uint32_t>(get_uint64_prop(tdh_event, L"ImageSize"));
    result.payload.image.process_id = get_uint32_prop(tdh_event, L"ProcessId");
    
    std::wstring path = get_wstring_prop(tdh_event, L"FileName");
    if (path.empty()) {
        path = get_wstring_prop(tdh_event, L"ImageFileName");
    }
    if (!path.empty() && strings != nullptr) {
        result.payload.image.image_path = strings->intern_wide(path);
    } else {
        result.payload.image.image_path = event::INVALID_STRING;
    }
    
    result.payload.image.is_suspicious = 0;
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
