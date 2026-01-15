/// @file dispatcher.cpp
/// @brief DNS event dispatcher.

#ifdef _WIN32

#include "constants.hpp"
#include "query_parser.hpp"

#include "exeray/etw/parser.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

ParsedEvent parse_dns_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<dns::EventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case dns::EventId::QueryCompleted:
            return dns::parse_query_completed(record, strings);
        case dns::EventId::QueryFailed:
            return dns::parse_query_failed(record, strings);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_dns(*tdh_result, record, strings);
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
