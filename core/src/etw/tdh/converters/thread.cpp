/// @file thread.cpp
/// @brief TDH to Thread event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_thread(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* /*strings*/
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Thread);
    result.payload.category = event::Category::Thread;
    
    switch (tdh_event.event_id) {
        case 1: result.operation = static_cast<uint8_t>(event::ThreadOp::Start); break;
        case 2: result.operation = static_cast<uint8_t>(event::ThreadOp::End); break;
        case 3: result.operation = static_cast<uint8_t>(event::ThreadOp::DCStart); break;
        case 4: result.operation = static_cast<uint8_t>(event::ThreadOp::DCEnd); break;
        default:
            result.valid = false;
            return result;
    }
    
    result.payload.thread.thread_id = get_uint32_prop(tdh_event, L"TThreadId");
    if (result.payload.thread.thread_id == 0) {
        result.payload.thread.thread_id = get_uint32_prop(tdh_event, L"ThreadId");
    }
    result.payload.thread.process_id = get_uint32_prop(tdh_event, L"ProcessId");
    result.payload.thread.creator_pid = get_uint32_prop(tdh_event, L"StackProcess");
    result.payload.thread.start_address = get_uint64_prop(tdh_event, L"Win32StartAddr");
    
    result.payload.thread.is_remote = 
        (result.payload.thread.creator_pid != 0 &&
         result.payload.thread.process_id != result.payload.thread.creator_pid) ? 1 : 0;
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
