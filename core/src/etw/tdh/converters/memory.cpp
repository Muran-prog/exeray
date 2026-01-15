/// @file memory.cpp
/// @brief TDH to Memory event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_memory(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* /*strings*/
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Memory;
    result.payload.category = event::Category::Memory;
    
    switch (tdh_event.event_id) {
        case 98: result.operation = static_cast<uint8_t>(event::MemoryOp::Alloc); break;
        case 99: result.operation = static_cast<uint8_t>(event::MemoryOp::Free); break;
        default:
            result.valid = false;
            return result;
    }
    
    result.payload.memory.base_address = get_uint64_prop(tdh_event, L"BaseAddress");
    result.payload.memory.region_size = static_cast<uint32_t>(
        get_uint64_prop(tdh_event, L"RegionSize"));
    result.payload.memory.process_id = get_uint32_prop(tdh_event, L"ProcessId");
    result.payload.memory.protection = get_uint32_prop(tdh_event, L"Flags");
    
    constexpr uint32_t kPageExecuteReadWrite = 0x40;
    constexpr uint32_t kPageExecuteWriteCopy = 0x80;
    result.payload.memory.is_suspicious = 
        (result.payload.memory.protection == kPageExecuteReadWrite ||
         result.payload.memory.protection == kPageExecuteWriteCopy) ? 1 : 0;
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
