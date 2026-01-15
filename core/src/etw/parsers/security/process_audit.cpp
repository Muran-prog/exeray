/// @file process_audit.cpp
/// @brief Process audit event parsers (4688, 4689).

#ifdef _WIN32

#include "helpers.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/logging.hpp"

#include <cstring>

namespace exeray::etw::security {

ParsedEvent parse_process_create(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Security;
    result.operation = static_cast<uint8_t>(event::SecurityOp::ProcessCreate);
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
    
    std::wstring_view domain = extract_wstring(data + offset, len - offset);
    offset += (domain.size() + 1) * sizeof(wchar_t);
    
    std::wstring_view process_name = extract_wstring(data + offset, len - offset);
    offset += (process_name.size() + 1) * sizeof(wchar_t);
    
    std::wstring_view command_line = extract_wstring(data + offset, len - offset);
    
    uint32_t new_pid = 0;
    
    if (strings != nullptr) {
        result.payload.security.subject_user = subject_user.empty() ?
            event::INVALID_STRING : strings->intern_wide(subject_user);
        result.payload.security.target_user = event::INVALID_STRING;
        result.payload.security.command_line = command_line.empty() ?
            event::INVALID_STRING : strings->intern_wide(command_line);
    } else {
        result.payload.security.subject_user = event::INVALID_STRING;
        result.payload.security.target_user = event::INVALID_STRING;
        result.payload.security.command_line = event::INVALID_STRING;
    }
    result.payload.security.logon_type = 0;
    result.payload.security.process_id = new_pid;
    result.payload.security.is_suspicious = 0;
    std::memset(result.payload.security._pad, 0, sizeof(result.payload.security._pad));
    
    std::string user_str = wstring_to_narrow(subject_user);
    std::string cmdline_str = wstring_to_narrow(command_line);
    EXERAY_TRACE("Process Create: user={}, cmdline={}", user_str, cmdline_str);
    
    result.valid = true;
    return result;
}

ParsedEvent parse_process_terminate(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Security;
    result.operation = static_cast<uint8_t>(event::SecurityOp::ProcessTerminate);
    result.payload.category = event::Category::Security;
    
    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;
    
    if (data == nullptr || len < 8) {
        result.valid = false;
        return result;
    }
    
    size_t offset = 0;
    std::wstring_view subject_user = extract_wstring(data + offset, len - offset);
    offset += (subject_user.size() + 1) * sizeof(wchar_t);
    
    std::wstring_view process_name = extract_wstring(data + offset, len - offset);
    
    if (strings != nullptr) {
        result.payload.security.subject_user = subject_user.empty() ?
            event::INVALID_STRING : strings->intern_wide(subject_user);
    } else {
        result.payload.security.subject_user = event::INVALID_STRING;
    }
    result.payload.security.target_user = event::INVALID_STRING;
    result.payload.security.command_line = event::INVALID_STRING;
    result.payload.security.logon_type = 0;
    result.payload.security.process_id = result.pid;
    result.payload.security.is_suspicious = 0;
    std::memset(result.payload.security._pad, 0, sizeof(result.payload.security._pad));
    
    std::string process_str = wstring_to_narrow(process_name);
    EXERAY_TRACE("Process Terminate: pid={}, process={}", result.pid, process_str);
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw::security

#endif  // _WIN32
