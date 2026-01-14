/// @file parser_wmi.cpp
/// @brief ETW parser for Microsoft-Windows-WMI-Activity events.
///
/// Parses WMI operations for attack detection including:
/// - Lateral movement via remote WMI connections
/// - Persistence via WMI Event Subscriptions
/// - Fileless execution via Win32_Process.Create

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/event/string_pool.hpp"

#include <cstring>
#include <string>
#include <string_view>

#include "exeray/logging.hpp"

namespace exeray::etw {

namespace {

/// WMI Activity event IDs from Microsoft-Windows-WMI-Activity provider.
enum class WmiEventId : uint16_t {
    NamespaceConnect = 5,           ///< IWbemLocator::ConnectServer
    ExecQuery = 11,                 ///< IWbemServices::ExecQuery
    ExecNotificationQuery = 22,     ///< IWbemServices::ExecNotificationQuery
    ExecMethod = 23                 ///< IWbemServices::ExecMethod
};

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Wmi;
    out.pid = record->EventHeader.ProcessId;
}

/// @brief Extract wide string from event data.
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

/// @brief Case-insensitive wide string contains check.
bool contains_icase(std::wstring_view haystack, const wchar_t* needle) {
    if (haystack.empty() || needle == nullptr || needle[0] == L'\0') {
        return false;
    }

    size_t needle_len = wcslen(needle);
    if (needle_len > haystack.size()) {
        return false;
    }

    for (size_t i = 0; i <= haystack.size() - needle_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle_len; ++j) {
            wchar_t h = haystack[i + j];
            wchar_t n = needle[j];
            // Fold to lowercase
            if (h >= L'A' && h <= L'Z') h = h - L'A' + L'a';
            if (n >= L'A' && n <= L'Z') n = n - L'A' + L'a';
            if (h != n) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// @brief Check if WMI query/method indicates suspicious activity.
///
/// Suspicious patterns:
/// - Win32_Process + Create method (fileless execution)
/// - __EventConsumer, __EventFilter, __FilterToConsumerBinding (persistence)
/// - CommandLineEventConsumer (persistence backdoor)
/// - ActiveScriptEventConsumer (script persistence)
/// - PowerShell via WMI
bool is_suspicious_wmi_activity(std::wstring_view query_or_method,
                                 std::wstring_view wmi_namespace) {
    // Check for process creation (fileless execution)
    if (contains_icase(query_or_method, L"Win32_Process") &&
        contains_icase(query_or_method, L"Create")) {
        return true;
    }

    // Check for WMI event subscription persistence
    if (contains_icase(query_or_method, L"__EventConsumer") ||
        contains_icase(query_or_method, L"__EventFilter") ||
        contains_icase(query_or_method, L"__FilterToConsumerBinding") ||
        contains_icase(query_or_method, L"CommandLineEventConsumer") ||
        contains_icase(query_or_method, L"ActiveScriptEventConsumer")) {
        return true;
    }

    // Check for PowerShell execution via WMI
    if (contains_icase(query_or_method, L"powershell") ||
        contains_icase(query_or_method, L"pwsh")) {
        return true;
    }

    // Check for subscription namespace (common for persistence)
    if (contains_icase(wmi_namespace, L"subscription")) {
        return true;
    }

    return false;
}

/// @brief Check if target host indicates remote WMI.
bool is_remote_host(std::wstring_view host) {
    if (host.empty()) return false;

    // Local indicators
    if (host == L"." || host == L"localhost" ||
        contains_icase(host, L"127.0.0.1") ||
        contains_icase(host, L"::1")) {
        return false;
    }

    return true;
}

/// @brief Convert wide string to narrow for logging.
std::string wstring_to_narrow(std::wstring_view wstr, size_t max_len = 80) {
    std::string result;
    result.reserve(std::min(wstr.size(), max_len));
    for (size_t i = 0; i < wstr.size() && i < max_len; ++i) {
        result.push_back(static_cast<char>(wstr[i] & 0x7F));
    }
    if (wstr.size() > max_len) {
        result += "...";
    }
    return result;
}

/// @brief Log WMI operation.
void log_wmi_operation(uint32_t pid, event::WmiOp op,
                       std::wstring_view ns, std::wstring_view query,
                       std::wstring_view host, bool is_suspicious) {
    const char* op_name = "Unknown";
    switch (op) {
        case event::WmiOp::Query: op_name = "Query"; break;
        case event::WmiOp::ExecMethod: op_name = "ExecMethod"; break;
        case event::WmiOp::Subscribe: op_name = "Subscribe"; break;
        case event::WmiOp::Connect: op_name = "Connect"; break;
    }

    std::string ns_str = wstring_to_narrow(ns);
    std::string query_str = wstring_to_narrow(query);
    std::string host_str = wstring_to_narrow(host);

    if (is_suspicious) {
        if (!host.empty()) {
            EXERAY_WARN("Suspicious WMI {}: pid={}, ns={}, query={}, host={}",
                        op_name, pid, ns_str, query_str, host_str);
        } else {
            EXERAY_WARN("Suspicious WMI {}: pid={}, ns={}, query={}",
                        op_name, pid, ns_str, query_str);
        }
    } else {
        if (!host.empty()) {
            EXERAY_TRACE("WMI {}: pid={}, ns={}, query={}, host={}",
                         op_name, pid, ns_str, query_str, host_str);
        } else {
            EXERAY_TRACE("WMI {}: pid={}, ns={}, query={}",
                         op_name, pid, ns_str, query_str);
        }
    }
}

/// @brief Parse WMI operation event.
///
/// Common event data layout:
///   Namespace: WSTRING
///   Query/MethodName: WSTRING
///   TargetHost: WSTRING (optional, for remote)
ParsedEvent parse_wmi_operation(const EVENT_RECORD* record,
                                 event::StringPool* strings,
                                 event::WmiOp op) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(op);
    result.payload.category = event::Category::Wmi;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 4) {
        result.valid = false;
        return result;
    }

    size_t offset = 0;

    // Extract WMI namespace
    std::wstring_view wmi_namespace = extract_wstring(data + offset, len - offset);
    offset += (wmi_namespace.size() + 1) * sizeof(wchar_t);

    // Extract query or method name
    std::wstring_view query;
    if (offset < len) {
        query = extract_wstring(data + offset, len - offset);
        offset += (query.size() + 1) * sizeof(wchar_t);
    }

    // Extract target host (if present)
    std::wstring_view target_host;
    if (offset < len) {
        target_host = extract_wstring(data + offset, len - offset);
    }

    // Check for suspicious patterns
    bool suspicious = is_suspicious_wmi_activity(query, wmi_namespace);
    bool remote = is_remote_host(target_host);

    // Remote WMI is always suspicious (lateral movement)
    if (remote) {
        suspicious = true;
    }

    // Set payload with interned strings
    if (strings != nullptr) {
        if (!wmi_namespace.empty()) {
            result.payload.wmi.wmi_namespace = strings->intern_wide(wmi_namespace);
        } else {
            result.payload.wmi.wmi_namespace = event::INVALID_STRING;
        }
        if (!query.empty()) {
            result.payload.wmi.query = strings->intern_wide(query);
        } else {
            result.payload.wmi.query = event::INVALID_STRING;
        }
        if (!target_host.empty()) {
            result.payload.wmi.target_host = strings->intern_wide(target_host);
        } else {
            result.payload.wmi.target_host = event::INVALID_STRING;
        }
    } else {
        result.payload.wmi.wmi_namespace = event::INVALID_STRING;
        result.payload.wmi.query = event::INVALID_STRING;
        result.payload.wmi.target_host = event::INVALID_STRING;
    }

    result.payload.wmi.is_remote = remote ? 1 : 0;
    result.payload.wmi.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.wmi._pad, 0, sizeof(result.payload.wmi._pad));

    // Set status
    result.status = suspicious ? event::Status::Suspicious : event::Status::Success;

    // Log the operation
    log_wmi_operation(result.pid, op, wmi_namespace, query, target_host, suspicious);

    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_wmi_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<WmiEventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case WmiEventId::ExecQuery:
            return parse_wmi_operation(record, strings, event::WmiOp::Query);
        case WmiEventId::ExecMethod:
            return parse_wmi_operation(record, strings, event::WmiOp::ExecMethod);
        case WmiEventId::ExecNotificationQuery:
            return parse_wmi_operation(record, strings, event::WmiOp::Subscribe);
        case WmiEventId::NamespaceConnect:
            return parse_wmi_operation(record, strings, event::WmiOp::Connect);
        default:
            // Unknown event ID - return invalid
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
