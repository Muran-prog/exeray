/// @file token.cpp
/// @brief Token rights adjustment event parser (4703).

#ifdef _WIN32

#include "helpers.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/logging.hpp"

#include <cstring>

namespace exeray::etw::security {

ParsedEvent parse_token_rights(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Security;
    result.operation = static_cast<uint8_t>(event::SecurityOp::PrivilegeAdjust);
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
    
    std::wstring_view domain = extract_wstring(data + offset, len - offset);
    offset += (domain.size() + 1) * sizeof(wchar_t);
    
    std::wstring_view enabled_privs = extract_wstring(data + offset, len - offset);
    
    bool suspicious = has_dangerous_privilege(enabled_privs);
    
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
    result.payload.security.logon_type = 0;
    result.payload.security.process_id = result.pid;
    result.payload.security.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.security._pad, 0, sizeof(result.payload.security._pad));
    
    if (suspicious) {
        result.status = event::Status::Suspicious;
        std::string user_str = wstring_to_narrow(subject_user);
        std::string privs_str = wstring_to_narrow(enabled_privs);
        EXERAY_WARN("Token Rights (DANGEROUS PRIVILEGE!): user={}, privs={}",
                    user_str, privs_str);
    }
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw::security

#endif  // _WIN32
