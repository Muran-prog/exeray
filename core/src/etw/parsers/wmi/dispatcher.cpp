/// @file dispatcher.cpp
/// @brief WMI event dispatcher.

#ifdef _WIN32

#include "constants.hpp"
#include "parser.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

ParsedEvent parse_wmi_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<wmi::WmiEventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case wmi::WmiEventId::ExecQuery:
            return wmi::parse_wmi_operation(record, strings, event::WmiOp::Query);
        case wmi::WmiEventId::ExecMethod:
            return wmi::parse_wmi_operation(record, strings, event::WmiOp::ExecMethod);
        case wmi::WmiEventId::ExecNotificationQuery:
            return wmi::parse_wmi_operation(record, strings, event::WmiOp::Subscribe);
        case wmi::WmiEventId::NamespaceConnect:
            return wmi::parse_wmi_operation(record, strings, event::WmiOp::Connect);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_wmi(*tdh_result, record, strings);
            }
            return ParsedEvent{.valid = false};
    }
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
