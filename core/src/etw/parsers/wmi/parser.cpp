/// @file parser.cpp
/// @brief WMI operation parser implementation.

#ifdef _WIN32

#include "constants.hpp"
#include "detection.hpp"
#include "helpers.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/event/string_pool.hpp"

#include <cstring>

namespace exeray::etw::wmi {

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

}  // namespace exeray::etw::wmi

#endif  // _WIN32
