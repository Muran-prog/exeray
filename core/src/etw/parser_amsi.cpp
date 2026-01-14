/// @file parser_amsi.cpp
/// @brief ETW parser for Microsoft-Antimalware-Scan-Interface events.
///
/// Parses AmsiScanBuffer events (Event ID 1101) for malware detection
/// and AMSI bypass attempt detection.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

#include <cstring>
#include <string>
#include <string_view>

#include "exeray/logging.hpp"

namespace exeray::etw {

namespace {

/// AMSI event IDs from Microsoft-Antimalware-Scan-Interface provider.
enum class AmsiEventId : uint16_t {
    ScanBuffer = 1101  ///< AmsiScanBuffer called
};

/// @brief AMSI scan result values.
///
/// Based on AMSI_RESULT enumeration from amsi.h.
/// Values >= 32768 are considered malware.
enum class AmsiResult : uint32_t {
    Clean = 0,                    ///< No threat detected, fully clean
    NotDetected = 1,              ///< No threat detected (may be uncertain)
    BlockedByAdminStart = 0x4000, ///< Start of admin-blocked range
    BlockedByAdminEnd = 0x4FFF,   ///< End of admin-blocked range
    Malware = 0x8000              ///< Malware detected (threshold)
};

/// @brief Check if AMSI result indicates malware.
/// @param result The AMSI_RESULT value.
/// @return true if result indicates malware detection.
constexpr bool is_malware(uint32_t result) {
    return result >= static_cast<uint32_t>(AmsiResult::Malware);
}

/// @brief Check if AMSI result indicates admin block.
/// @param result The AMSI_RESULT value.
/// @return true if result is in admin-blocked range.
constexpr bool is_blocked_by_admin(uint32_t result) {
    return result >= static_cast<uint32_t>(AmsiResult::BlockedByAdminStart) &&
           result <= static_cast<uint32_t>(AmsiResult::BlockedByAdminEnd);
}

/// @brief Get human-readable name for AMSI result.
const char* amsi_result_name(uint32_t result) {
    if (is_malware(result)) {
        return "MALWARE";
    }
    if (is_blocked_by_admin(result)) {
        return "BLOCKED_BY_ADMIN";
    }
    switch (result) {
        case 0: return "CLEAN";
        case 1: return "NOT_DETECTED";
        default: return "SUSPICIOUS";
    }
}

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Amsi;
    out.pid = record->EventHeader.ProcessId;
}

/// @brief Extract wide string from event data.
/// @param data Pointer to start of string.
/// @param max_len Maximum bytes to read.
/// @return String view (empty if null or invalid).
std::wstring_view extract_wstring(const uint8_t* data, size_t max_len) {
    if (data == nullptr || max_len < 2) {
        return {};
    }

    // Find null terminator
    const auto* wdata = reinterpret_cast<const wchar_t*>(data);
    size_t max_chars = max_len / sizeof(wchar_t);
    size_t len = 0;
    while (len < max_chars && wdata[len] != L'\0') {
        ++len;
    }
    return {wdata, len};
}

/// @brief Check if scan appears to be an AMSI bypass attempt.
///
/// AMSI bypass is detected when:
/// - Content is empty or very small
/// - Application is PowerShell (common bypass target)
bool is_bypass_attempt(uint32_t content_size, std::wstring_view app_name) {
    // Empty content after PowerShell is suspicious
    if (content_size == 0) {
        // Check if app name contains PowerShell
        for (size_t i = 0; i + 9 < app_name.size(); ++i) {
            if ((app_name[i] == L'P' || app_name[i] == L'p') &&
                (app_name[i+1] == L'o' || app_name[i+1] == L'O') &&
                (app_name[i+2] == L'w' || app_name[i+2] == L'W') &&
                (app_name[i+3] == L'e' || app_name[i+3] == L'E') &&
                (app_name[i+4] == L'r' || app_name[i+4] == L'R') &&
                (app_name[i+5] == L's' || app_name[i+5] == L'S') &&
                (app_name[i+6] == L'h' || app_name[i+6] == L'H') &&
                (app_name[i+7] == L'e' || app_name[i+7] == L'E') &&
                (app_name[i+8] == L'l' || app_name[i+8] == L'L') &&
                (app_name[i+9] == L'l' || app_name[i+9] == L'L')) {
                return true;
            }
        }
    }
    return false;
}

/// @brief Log AMSI scan event.
void log_amsi_scan(uint32_t pid, uint32_t result, uint32_t content_size,
                   bool is_bypass) {
    const char* result_name = amsi_result_name(result);
    if (is_bypass) {
        EXERAY_WARN("AMSI bypass attempt: pid={}, empty content from PowerShell", pid);
    } else if (is_malware(result)) {
        EXERAY_WARN("AMSI malware detected: pid={}, result={} (0x{:X}), size={}",
                    pid, result_name, result, content_size);
    } else if (is_blocked_by_admin(result)) {
        EXERAY_INFO("AMSI blocked by admin: pid={}, size={}", pid, content_size);
    } else {
        EXERAY_TRACE("AMSI scan: pid={}, result={}, size={}",
                     pid, result_name, content_size);
    }
}

/// @brief Parse AmsiScanBuffer event (Event ID 1101).
///
/// Event Data Layout (approximate):
///   session: UINT64 (AMSI session handle)
///   scanStatus: UINT32 (HRESULT)
///   scanResult: UINT32 (AMSI_RESULT_*)
///   appName: WSTRING (requesting application)
///   contentName: WSTRING (optional, e.g., script name)
///   contentSize: UINT32
///   content: WSTRING/BINARY (scanned content, may be truncated)
ParsedEvent parse_scan_buffer_event(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::AmsiOp::Scan);
    result.payload.category = event::Category::Amsi;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }

    // Parse event data - offsets are approximate and may vary
    size_t offset = 0;

    // Skip session handle (8 bytes)
    offset += 8;

    // Skip scan status HRESULT (4 bytes)
    offset += 4;

    // Extract scan result (4 bytes)
    uint32_t scan_result = 0;
    if (offset + 4 <= len) {
        std::memcpy(&scan_result, data + offset, sizeof(uint32_t));
        offset += 4;
    }

    // Extract app name (wide string)
    std::wstring_view app_name;
    if (offset < len) {
        app_name = extract_wstring(data + offset, len - offset);
        offset += (app_name.size() + 1) * sizeof(wchar_t);
    }

    // Skip content name (wide string)
    if (offset < len) {
        std::wstring_view content_name = extract_wstring(data + offset, len - offset);
        offset += (content_name.size() + 1) * sizeof(wchar_t);
    }

    // Extract content size (4 bytes)
    uint32_t content_size = 0;
    if (offset + 4 <= len) {
        std::memcpy(&content_size, data + offset, sizeof(uint32_t));
    }

    // Check for bypass attempt
    bool bypass_detected = is_bypass_attempt(content_size, app_name);

    // Set payload with interned strings
    result.payload.amsi.content = event::INVALID_STRING;  // Content often binary/large
    if (strings != nullptr && !app_name.empty()) {
        result.payload.amsi.app_name = strings->intern_wide(app_name);
    } else {
        result.payload.amsi.app_name = event::INVALID_STRING;
    }
    result.payload.amsi.scan_result = scan_result;
    result.payload.amsi.content_size = content_size;

    // Set status based on result
    if (bypass_detected) {
        result.status = event::Status::Suspicious;
    } else if (is_malware(scan_result) || is_blocked_by_admin(scan_result)) {
        result.status = event::Status::Denied;
    } else {
        result.status = event::Status::Success;
    }

    // Log the scan
    log_amsi_scan(result.pid, scan_result, content_size, bypass_detected);

    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_amsi_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<AmsiEventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case AmsiEventId::ScanBuffer:
            return parse_scan_buffer_event(record, strings);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_amsi(*tdh_result, record, strings);
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
