/// @file process.cpp
/// @brief TDH to Process event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_process(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Process);
    result.payload.category = event::Category::Process;
    
    switch (tdh_event.event_id) {
        case 1: result.operation = static_cast<uint8_t>(event::ProcessOp::Create); break;
        case 2: result.operation = static_cast<uint8_t>(event::ProcessOp::Terminate); break;
        case 5: result.operation = static_cast<uint8_t>(event::ProcessOp::LoadLibrary); break;
        default: 
            result.valid = false;
            return result;
    }
    
    result.payload.process.pid = get_uint32_prop(tdh_event, L"ProcessId");
    if (result.payload.process.pid == 0) {
        result.payload.process.pid = get_uint32_prop(tdh_event, L"ProcessID");
    }
    
    result.payload.process.parent_pid = get_uint32_prop(tdh_event, L"ParentId");
    if (result.payload.process.parent_pid == 0) {
        result.payload.process.parent_pid = get_uint32_prop(tdh_event, L"ParentProcessId");
    }
    
    std::wstring image_name = get_wstring_prop(tdh_event, L"ImageFileName");
    if (image_name.empty()) {
        image_name = get_wstring_prop(tdh_event, L"ImageName");
    }
    if (!image_name.empty() && strings != nullptr) {
        result.payload.process.image_path = strings->intern_wide(image_name);
    } else {
        result.payload.process.image_path = event::INVALID_STRING;
    }
    
    std::wstring cmd_line = get_wstring_prop(tdh_event, L"CommandLine");
    if (!cmd_line.empty() && strings != nullptr) {
        result.payload.process.command_line = strings->intern_wide(cmd_line);
    } else {
        result.payload.process.command_line = event::INVALID_STRING;
    }
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
