/// @file parser_security.cpp
/// @brief ETW parser for Microsoft-Windows-Security-Auditing events.
///
/// Parses Security Auditing events for forensics and privilege escalation detection.
/// Implements brute force detection, SeDebugPrivilege monitoring, and persistence tracking.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/event/string_pool.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <chrono>
#include <mutex>

namespace exeray::etw {

namespace {

/// Security Auditing event IDs from Microsoft-Windows-Security-Auditing provider.
enum class SecurityEventId : uint16_t {
    LogonSuccess = 4624,       ///< Successful logon
    LogonFailed = 4625,        ///< Failed logon attempt
    ProcessCreate = 4688,      ///< New process created
    ProcessTerminate = 4689,   ///< Process terminated
    ServiceInstall = 4697,     ///< Service installed
    TokenRights = 4703         ///< Token rights adjusted
};

/// Logon type values for Event 4624/4625.
namespace logon_types {
    constexpr uint32_t INTERACTIVE = 2;          ///< Local keyboard logon
    constexpr uint32_t NETWORK = 3;              ///< Network (SMB, etc.)
    constexpr uint32_t BATCH = 4;                ///< Scheduled task
    constexpr uint32_t SERVICE = 5;              ///< Service account
    constexpr uint32_t UNLOCK = 7;               ///< Screen unlock
    constexpr uint32_t NETWORK_CLEARTEXT = 8;    ///< IIS basic auth
    constexpr uint32_t NEW_CREDENTIALS = 9;      ///< RunAs /netonly
    constexpr uint32_t REMOTE_INTERACTIVE = 10;  ///< RDP
    constexpr uint32_t CACHED_INTERACTIVE = 11;  ///< Cached domain credentials
}  // namespace logon_types

/// Service start types for Event 4697.
namespace service_start_types {
    constexpr uint32_t BOOT_START = 0x0;
    constexpr uint32_t SYSTEM_START = 0x1;
    constexpr uint32_t AUTO_START = 0x2;      ///< Persistence indicator!
    constexpr uint32_t DEMAND_START = 0x3;
    constexpr uint32_t DISABLED = 0x4;
}  // namespace service_start_types

/// Dangerous privileges that indicate privilege escalation.
constexpr const wchar_t* DANGEROUS_PRIVILEGES[] = {
    L"SeDebugPrivilege",           ///< Debug any process (injection)
    L"SeTcbPrivilege",             ///< Act as part of OS
    L"SeImpersonatePrivilege",     ///< Impersonate client (potato attacks)
    L"SeAssignPrimaryTokenPrivilege", ///< Assign primary token
    L"SeLoadDriverPrivilege",      ///< Load kernel drivers
    L"SeRestorePrivilege",         ///< Restore files/registry
    L"SeBackupPrivilege",          ///< Backup files/registry
    L"SeTakeOwnershipPrivilege"    ///< Take ownership of objects
};

/// Brute force detection state.
struct BruteForceTracker {
    std::mutex mutex;
    std::unordered_map<std::wstring, std::vector<std::chrono::steady_clock::time_point>> failures;
    
    static constexpr size_t THRESHOLD = 5;
    static constexpr std::chrono::seconds WINDOW{60};
    
    /// @brief Check if this represents a brute force attempt.
    bool check_and_record(std::wstring_view user) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto now = std::chrono::steady_clock::now();
        std::wstring key(user);
        auto& times = failures[key];
        
        // Remove old entries outside the window
        auto cutoff = now - WINDOW;
        times.erase(std::remove_if(times.begin(), times.end(),
            [cutoff](auto& t) { return t < cutoff; }), times.end());
        
        // Add current failure
        times.push_back(now);
        
        // Check if threshold exceeded
        return times.size() >= THRESHOLD;
    }
};

/// Global brute force tracker instance.
BruteForceTracker g_brute_force_tracker;

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.pid = record->EventHeader.ProcessId;
}

/// @brief Extract null-terminated wide string from event data.
std::wstring_view extract_wstring(const uint8_t* data, size_t max_len) {
    if (data == nullptr || max_len < 2) {
        return {};
    }
    const auto* wdata = reinterpret_cast<const wchar_t*>(data);
    size_t max_chars = max_len / sizeof(wchar_t);
    size_t len = 0;
    while (len < max_chars && wdata[len] != L'\0') {
        ++len;
    }
    return {wdata, len};
}

/// @brief Check if a privilege list contains dangerous privileges.
bool has_dangerous_privilege(std::wstring_view privileges) {
    for (const auto* priv : DANGEROUS_PRIVILEGES) {
        if (privileges.find(priv) != std::wstring_view::npos) {
            return true;
        }
    }
    return false;
}

/// @brief Get human-readable logon type name.
const char* logon_type_name(uint32_t type) {
    switch (type) {
        case logon_types::INTERACTIVE: return "Interactive";
        case logon_types::NETWORK: return "Network";
        case logon_types::BATCH: return "Batch";
        case logon_types::SERVICE: return "Service";
        case logon_types::UNLOCK: return "Unlock";
        case logon_types::NETWORK_CLEARTEXT: return "NetworkCleartext";
        case logon_types::NEW_CREDENTIALS: return "NewCredentials";
        case logon_types::REMOTE_INTERACTIVE: return "RemoteInteractive";
        case logon_types::CACHED_INTERACTIVE: return "CachedInteractive";
        default: return "Unknown";
    }
}

/// @brief Log security event to stderr.
void log_security_event(const char* event_type, uint32_t pid, 
                        std::wstring_view user, bool suspicious,
                        const char* details = nullptr) {
    if (suspicious) {
        std::fprintf(stderr, "[ALERT] %s: PID=%u, user=", event_type, pid);
    } else {
        std::fprintf(stderr, "[TRACE] %s: PID=%u, user=", event_type, pid);
    }
    for (wchar_t c : user) {
        std::fputc(static_cast<char>(c & 0x7F), stderr);
    }
    if (details) {
        std::fprintf(stderr, ", %s", details);
    }
    if (suspicious) {
        std::fprintf(stderr, " [SUSPICIOUS]");
    }
    std::fputc('\n', stderr);
}

/// @brief Parse Event 4624 - Logon Success.
ParsedEvent parse_logon_success(const EVENT_RECORD* record, 
                                 event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Security;
    result.operation = static_cast<uint8_t>(event::SecurityOp::Logon);
    result.payload.category = event::Category::Security;
    
    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;
    
    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }
    
    // Security Auditing events use TDH for proper parsing, but we'll do
    // offset-based parsing for now. Layout varies by event version.
    // Typical fields: SubjectUserSid, SubjectUserName, SubjectDomainName, etc.
    
    // For simplicity, extract first few wide strings
    size_t offset = 0;
    
    // Skip SIDs (variable length) - look for first string
    std::wstring_view subject_user = extract_wstring(data + offset, len - offset);
    offset += (subject_user.size() + 1) * sizeof(wchar_t);
    
    std::wstring_view target_user = extract_wstring(data + offset, len - offset);
    offset += (target_user.size() + 1) * sizeof(wchar_t);
    
    // Extract logon type (approximate offset)
    uint32_t logon_type = 0;
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&logon_type, data + offset, sizeof(uint32_t));
    }
    
    // Flag remote interactive (RDP) as worth noting
    bool suspicious = (logon_type == logon_types::REMOTE_INTERACTIVE);
    
    // Set payload
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

/// @brief Parse Event 4625 - Logon Failed.
ParsedEvent parse_logon_failed(const EVENT_RECORD* record,
                                event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
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
    
    // Extract target user
    std::wstring_view target_user = extract_wstring(data + offset, len - offset);
    offset += (target_user.size() + 1) * sizeof(wchar_t);
    
    // Extract logon type
    uint32_t logon_type = 0;
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&logon_type, data + offset, sizeof(uint32_t));
    }
    
    // Check for brute force
    bool brute_force = g_brute_force_tracker.check_and_record(target_user);
    
    // Set payload
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

/// @brief Parse Event 4688 - Process Create.
ParsedEvent parse_process_create(const EVENT_RECORD* record,
                                  event::StringPool* strings) {
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
    
    // Extract strings - approximate layout:
    // SubjectUserSid, SubjectUserName, SubjectDomainName, LogonId,
    // NewProcessId, NewProcessName, TokenElevationType, CommandLine
    
    std::wstring_view subject_user = extract_wstring(data + offset, len - offset);
    offset += (subject_user.size() + 1) * sizeof(wchar_t);
    
    // Skip domain
    std::wstring_view domain = extract_wstring(data + offset, len - offset);
    offset += (domain.size() + 1) * sizeof(wchar_t);
    
    // Extract process name
    std::wstring_view process_name = extract_wstring(data + offset, len - offset);
    offset += (process_name.size() + 1) * sizeof(wchar_t);
    
    // Extract command line (important for forensics!)
    std::wstring_view command_line = extract_wstring(data + offset, len - offset);
    
    // Extract new process ID (approximate)
    uint32_t new_pid = 0;
    // PID is typically hex pointer in event data
    
    // Set payload - store full command line
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
    
    std::fprintf(stderr, "[TRACE] Process Create: user=");
    for (wchar_t c : subject_user) {
        std::fputc(static_cast<char>(c & 0x7F), stderr);
    }
    std::fprintf(stderr, ", cmdline=");
    // Truncate long command lines for logging
    size_t log_len = std::min(command_line.size(), size_t(100));
    for (size_t i = 0; i < log_len; ++i) {
        std::fputc(static_cast<char>(command_line[i] & 0x7F), stderr);
    }
    if (command_line.size() > 100) {
        std::fprintf(stderr, "...");
    }
    std::fputc('\n', stderr);
    
    result.valid = true;
    return result;
}

/// @brief Parse Event 4689 - Process Terminate.
ParsedEvent parse_process_terminate(const EVENT_RECORD* record,
                                     event::StringPool* strings) {
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
    
    // Set payload
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
    
    std::fprintf(stderr, "[TRACE] Process Terminate: PID=%u, process=", result.pid);
    for (wchar_t c : process_name) {
        std::fputc(static_cast<char>(c & 0x7F), stderr);
    }
    std::fputc('\n', stderr);
    
    result.valid = true;
    return result;
}

/// @brief Parse Event 4697 - Service Installation.
ParsedEvent parse_service_install(const EVENT_RECORD* record,
                                   event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Service;
    result.operation = static_cast<uint8_t>(event::ServiceOp::Install);
    result.payload.category = event::Category::Service;
    
    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;
    
    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }
    
    size_t offset = 0;
    
    // Extract service name
    std::wstring_view service_name = extract_wstring(data + offset, len - offset);
    offset += (service_name.size() + 1) * sizeof(wchar_t);
    
    // Extract service path
    std::wstring_view service_path = extract_wstring(data + offset, len - offset);
    offset += (service_path.size() + 1) * sizeof(wchar_t);
    
    // Extract service type and start type (approximate)
    uint32_t service_type = 0;
    uint32_t start_type = 0;
    
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&service_type, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
    }
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&start_type, data + offset, sizeof(uint32_t));
    }
    
    // Flag AUTO_START as suspicious (persistence mechanism!)
    bool suspicious = (start_type == service_start_types::AUTO_START);
    
    // Set payload
    if (strings != nullptr) {
        result.payload.service.service_name = service_name.empty() ?
            event::INVALID_STRING : strings->intern_wide(service_name);
        result.payload.service.service_path = service_path.empty() ?
            event::INVALID_STRING : strings->intern_wide(service_path);
    } else {
        result.payload.service.service_name = event::INVALID_STRING;
        result.payload.service.service_path = event::INVALID_STRING;
    }
    result.payload.service.service_type = service_type;
    result.payload.service.start_type = start_type;
    result.payload.service.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.service._pad, 0, sizeof(result.payload.service._pad));
    
    if (suspicious) {
        result.status = event::Status::Suspicious;
    }
    
    // Log
    if (suspicious) {
        std::fprintf(stderr, "[ALERT] Service Install (AUTO_START - Persistence!): ");
    } else {
        std::fprintf(stderr, "[TRACE] Service Install: ");
    }
    std::fprintf(stderr, "name=");
    for (wchar_t c : service_name) {
        std::fputc(static_cast<char>(c & 0x7F), stderr);
    }
    std::fprintf(stderr, ", path=");
    size_t log_len = std::min(service_path.size(), size_t(80));
    for (size_t i = 0; i < log_len; ++i) {
        std::fputc(static_cast<char>(service_path[i] & 0x7F), stderr);
    }
    if (service_path.size() > 80) {
        std::fprintf(stderr, "...");
    }
    std::fputc('\n', stderr);
    
    result.valid = true;
    return result;
}

/// @brief Parse Event 4703 - Token Rights Adjusted.
ParsedEvent parse_token_rights(const EVENT_RECORD* record,
                                event::StringPool* strings) {
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
    
    // Extract subject user
    std::wstring_view subject_user = extract_wstring(data + offset, len - offset);
    offset += (subject_user.size() + 1) * sizeof(wchar_t);
    
    // Skip target user/domain
    std::wstring_view target_user = extract_wstring(data + offset, len - offset);
    offset += (target_user.size() + 1) * sizeof(wchar_t);
    
    // Skip to EnabledPrivilegeList
    std::wstring_view domain = extract_wstring(data + offset, len - offset);
    offset += (domain.size() + 1) * sizeof(wchar_t);
    
    // Extract enabled privileges
    std::wstring_view enabled_privs = extract_wstring(data + offset, len - offset);
    
    // Check for dangerous privileges
    bool suspicious = has_dangerous_privilege(enabled_privs);
    
    // Set payload
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
        std::fprintf(stderr, "[ALERT] Token Rights (DANGEROUS PRIVILEGE!): user=");
        for (wchar_t c : subject_user) {
            std::fputc(static_cast<char>(c & 0x7F), stderr);
        }
        std::fprintf(stderr, ", privs=");
        size_t log_len = std::min(enabled_privs.size(), size_t(100));
        for (size_t i = 0; i < log_len; ++i) {
            std::fputc(static_cast<char>(enabled_privs[i] & 0x7F), stderr);
        }
        std::fputc('\n', stderr);
    }
    
    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_security_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }
    
    const auto event_id = static_cast<SecurityEventId>(
        record->EventHeader.EventDescriptor.Id);
    
    switch (event_id) {
        case SecurityEventId::LogonSuccess:
            return parse_logon_success(record, strings);
        case SecurityEventId::LogonFailed:
            return parse_logon_failed(record, strings);
        case SecurityEventId::ProcessCreate:
            return parse_process_create(record, strings);
        case SecurityEventId::ProcessTerminate:
            return parse_process_terminate(record, strings);
        case SecurityEventId::ServiceInstall:
            return parse_service_install(record, strings);
        case SecurityEventId::TokenRights:
            return parse_token_rights(record, strings);
        default:
            // Unknown security event ID - return invalid
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
