/// @file dispatcher.cpp
/// @brief CLR event dispatcher implementation.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

#include "constants.hpp"
#include "assembly_parser.hpp"
#include "jit_parser.hpp"

namespace exeray::etw {

ParsedEvent parse_clr_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<clr::ClrEventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case clr::ClrEventId::AssemblyLoadStart:
        case clr::ClrEventId::AssemblyLoadStop:
            return clr::parse_assembly_event(record, strings, event::ClrOp::AssemblyLoad);
        case clr::ClrEventId::AssemblyUnload:
            return clr::parse_assembly_event(record, strings, event::ClrOp::AssemblyUnload);
        case clr::ClrEventId::MethodJitStart:
            return clr::parse_jit_event(record, strings);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_clr(*tdh_result, record, strings);
            }
            return ParsedEvent{.valid = false};
    }
}

}  // namespace exeray::etw

#else  // !_WIN32

// Empty translation unit for non-Windows
namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
