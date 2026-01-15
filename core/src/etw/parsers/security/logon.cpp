/// @file logon.cpp
/// @brief Logon event parsers (4624, 4625).

#ifdef _WIN32

#include "helpers.hpp"
#include "constants.hpp"
#include "brute_force_tracker.hpp"
#include "exeray/event/string_pool.hpp"

#include <cstring>
#include <cstdio>

namespace exeray::etw::security {

ParsedEvent parse_logon_success(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    exeray::etw::extract_common(record, result, event::Category::Security);
    result.category = event::Category::Security;
    result.operation = static_cast<uint8_t>(event::SecurityOp::Logon);
    result.payload.category = event::Category::Security;
    
    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;
    
    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }
    
    size_t offset = 0;
    std::wstring_view subject_user = extract_wstring(data + offset, len - offset);
    offset += (subject_user.size() + 1) * sizeof(wchar_t);
    
    std::wstring_view target_user = extract_wstring(data + offset, len - offset);
    offset += (target_user.size() + 1) * sizeof(wchar_t);
    
    uint32_t logon_type = 0;
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&logon_type, data + offset, sizeof(uint32_t));
    }
    
    bool suspicious = (logon_type == logon_types::REMOTE_INTERACTIVE);
    
    if (strings != nullptr) {
        result.payload.security.subject_user = subject_user.empty() ?
            event::INVALID_STRING : strings->intern_wide(subject_user);
        result.payload.security.target_user = target_user.empty() ?
            event::INVALID_STRING : strings->intern_wide(target_user);
    } else {
        result.payload.security.subject_user = event::INVALID_STRING;
        result.payload.security.target_user = event::INVALID_STRING;
    }
    result.payload.security.command_line = event::INVALID_STRING;
    result.payload.security.logon_type = logon_type;
    result.payload.security.process_id = result.pid;
    result.payload.security.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.security._pad, 0, sizeof(result.payload.security._pad));
    
    if (suspicious) {
        result.status = event::Status::Suspicious;
    }
    
    char details[64];
    std::snprintf(details, sizeof(details), "type=%s", logon_type_name(logon_type));
    log_security_event("Logon Success", result.pid, target_user, suspicious, details);
    
    result.valid = true;
    return result;
}

ParsedEvent parse_logon_failed(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    exeray::etw::extract_common(record, result, event::Category::Security);
    result.category = event::Category::Security;
    result.operation = static_cast<uint8_t>(event::SecurityOp::LogonFailed);
    result.payload.category = event::Category::Security;
    
    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;
    
    if (data == nullptr || len < 8) {
        result.valid = false;
        return result;
    }
    
    size_t offset = 0;
    std::wstring_view target_user = extract_wstring(data + offset, len - offset);
    offset += (target_user.size() + 1) * sizeof(wchar_t);
    
    uint32_t logon_type = 0;
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&logon_type, data + offset, sizeof(uint32_t));
    }
    
    bool brute_force = get_brute_force_tracker().check_and_record(target_user);
    
    if (strings != nullptr && !target_user.empty()) {
        result.payload.security.target_user = strings->intern_wide(target_user);
    } else {
        result.payload.security.target_user = event::INVALID_STRING;
    }
    result.payload.security.subject_user = event::INVALID_STRING;
    result.payload.security.command_line = event::INVALID_STRING;
    result.payload.security.logon_type = logon_type;
    result.payload.security.process_id = 0;
    result.payload.security.is_suspicious = brute_force ? 1 : 0;
    std::memset(result.payload.security._pad, 0, sizeof(result.payload.security._pad));
    
    result.status = brute_force ? event::Status::Suspicious : event::Status::Denied;
    
    char details[128];
    std::snprintf(details, sizeof(details), "type=%s%s",
                  logon_type_name(logon_type),
                  brute_force ? " [BRUTE FORCE DETECTED]" : "");
    log_security_event("Logon Failed", result.pid, target_user, brute_force, details);
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw::security

#endif  // _WIN32
