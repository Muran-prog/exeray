/// @file dispatcher.cpp
/// @brief Main dispatcher for security events.

#ifdef _WIN32

#include "constants.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw::security {

// Forward declarations for parser functions
ParsedEvent parse_logon_success(const EVENT_RECORD* record, event::StringPool* strings);
ParsedEvent parse_logon_failed(const EVENT_RECORD* record, event::StringPool* strings);
ParsedEvent parse_process_create(const EVENT_RECORD* record, event::StringPool* strings);
ParsedEvent parse_process_terminate(const EVENT_RECORD* record, event::StringPool* strings);
ParsedEvent parse_service_install(const EVENT_RECORD* record, event::StringPool* strings);
ParsedEvent parse_token_rights(const EVENT_RECORD* record, event::StringPool* strings);

}  // namespace exeray::etw::security

namespace exeray::etw {

ParsedEvent parse_security_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }
    
    const auto event_id = static_cast<security::SecurityEventId>(
        record->EventHeader.EventDescriptor.Id);
    
    switch (event_id) {
        case security::SecurityEventId::LogonSuccess:
            return security::parse_logon_success(record, strings);
        case security::SecurityEventId::LogonFailed:
            return security::parse_logon_failed(record, strings);
        case security::SecurityEventId::ProcessCreate:
            return security::parse_process_create(record, strings);
        case security::SecurityEventId::ProcessTerminate:
            return security::parse_process_terminate(record, strings);
        case security::SecurityEventId::ServiceInstall:
            return security::parse_service_install(record, strings);
        case security::SecurityEventId::TokenRights:
            return security::parse_token_rights(record, strings);
        default:
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_security(*tdh_result, record, strings);
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
