/// @file parser_powershell.cpp
/// @brief ETW parser for Microsoft-Windows-PowerShell events.
///
/// Parses Script Block Logging (Event 4104) and Module Logging (Event 4103)
/// for fileless malware detection.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace exeray::etw {

namespace {

/// PowerShell event IDs from Microsoft-Windows-PowerShell provider.
enum class PowerShellEventId : uint16_t {
    ModuleLogging = 4103,      ///< Module/Cmdlet logging
    ScriptBlockLogging = 4104  ///< Script Block Logging (critical!)
};

/// @brief Suspicious PowerShell patterns for fileless malware detection.
///
/// These patterns are commonly used by malware for:
/// - Code execution (IEX, Invoke-Expression)
/// - Encoded commands (base64)
/// - Download cradles (WebClient)
/// - Evasion techniques (bypass, hidden)
struct SuspiciousPattern {
    std::string_view pattern;
    std::string_view description;
};

/// Patterns to detect. Case-insensitive matching is done on lowercased input.
constexpr SuspiciousPattern SUSPICIOUS_PATTERNS[] = {
    {"iex",                   "Invoke-Expression shorthand"},
    {"invoke-expression",     "Code execution"},
    {"-encodedcommand",       "Base64 encoded command"},
    {"-enc ",                 "Encoded command shorthand"},
    {"downloadstring",        "Download cradle"},
    {"downloadfile",          "File download"},
    {"downloaddata",          "Data download"},
    {"net.webclient",         "WebClient creation"},
    {"bitstransfer",          "BITS download"},
    {"frombase64string",      "Base64 decoding"},
    {"convertto-securestring","Credential manipulation"},
    {"-executionpolicy",      "Execution policy change"},
    {"bypass",                "Security bypass"},
    {"-windowstyle hidden",   "Hidden window execution"},
    {"start-process -hidden", "Hidden process"},
    {"reflection.assembly",   "Reflective loading"},
    {"gettype",               "Reflection usage"},
    {"system.runtime",        "Runtime access"},
    {"amsiutils",             "AMSI bypass attempt"},
    {"mimikatz",              "Credential theft tool"},
    {"powersploit",           "Offensive framework"},
    {"empire",                "C2 framework"},
    {"invoke-shellcode",      "Shellcode injection"},
    {"invoke-mimikatz",       "Credential theft"},
};

/// Number of suspicious patterns.
constexpr size_t PATTERN_COUNT = sizeof(SUSPICIOUS_PATTERNS) / sizeof(SUSPICIOUS_PATTERNS[0]);

/// @brief Convert string to lowercase for case-insensitive matching.
std::string to_lower(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (char c : input) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

/// @brief Check if script contains suspicious patterns.
/// @param script The script content to analyze.
/// @return true if any suspicious pattern is found.
bool contains_suspicious_pattern(std::string_view script) {
    if (script.empty()) {
        return false;
    }

    // Convert to lowercase for case-insensitive matching
    std::string lower_script = to_lower(script);

    for (size_t i = 0; i < PATTERN_COUNT; ++i) {
        if (lower_script.find(SUSPICIOUS_PATTERNS[i].pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

/// @brief Log suspicious script detection to stderr.
void log_suspicious_script(uint32_t pid, std::string_view matched_pattern) {
    std::fprintf(stderr,
        "[ALERT] Suspicious PowerShell detected: PID=%u, pattern='%.*s'\n",
        pid,
        static_cast<int>(matched_pattern.size()),
        matched_pattern.data());
}

/// @brief Get the first matched suspicious pattern from script.
std::string_view get_matched_pattern(std::string_view script) {
    if (script.empty()) {
        return {};
    }

    std::string lower_script = to_lower(script);

    for (size_t i = 0; i < PATTERN_COUNT; ++i) {
        if (lower_script.find(SUSPICIOUS_PATTERNS[i].pattern) != std::string::npos) {
            return SUSPICIOUS_PATTERNS[i].pattern;
        }
    }
    return {};
}

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Script;
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

/// @brief Convert wide string to narrow string for pattern matching.
std::string wstring_to_string(std::wstring_view wstr) {
    std::string result;
    result.reserve(wstr.size());
    for (wchar_t wc : wstr) {
        // Simple ASCII conversion - sufficient for pattern matching
        if (wc < 128) {
            result.push_back(static_cast<char>(wc));
        }
    }
    return result;
}

/// @brief Parse Script Block Logging event (Event ID 4104).
///
/// This is the critical event for fileless malware detection.
/// Contains the actual PowerShell script content being executed.
///
/// Event Data Layout (approximate - varies by PowerShell version):
///   MessageNumber: UINT32 (sequence for multi-part scripts)
///   MessageTotal:  UINT32 (total parts in multi-part script)
///   ScriptBlockText: WSTRING (actual script content)
///   ScriptBlockId: GUID
///   Path: WSTRING (optional script file path)
ParsedEvent parse_script_block_event(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::ScriptOp::Execute);
    result.payload.category = event::Category::Script;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }

    // Extract sequence number (first UINT32)
    uint32_t sequence = 0;
    std::memcpy(&sequence, data, sizeof(uint32_t));
    result.payload.script.sequence = sequence;

    // Skip MessageNumber (4) + MessageTotal (4) = 8 bytes
    // Script content starts after these fields
    size_t offset = 8;
    if (offset >= len) {
        result.valid = false;
        return result;
    }

    // Extract script block text (wide string)
    std::wstring_view wscript = extract_wstring(data + offset, len - offset);
    std::string script = wstring_to_string(wscript);

    // Check for suspicious patterns
    if (contains_suspicious_pattern(script)) {
        result.payload.script.is_suspicious = 1;
        result.status = event::Status::Suspicious;

        // Log alert with matched pattern
        std::string_view pattern = get_matched_pattern(script);
        log_suspicious_script(result.pid, pattern);
    } else {
        result.payload.script.is_suspicious = 0;
    }

    // Note: script_block and context StringIds would need to be interned
    // via StringPool. For now, we leave them as INVALID_STRING since
    // we don't have access to the StringPool in the parser layer.
    // The consumer layer should handle string interning.
    result.payload.script.script_block = event::INVALID_STRING;
    result.payload.script.context = event::INVALID_STRING;

    result.valid = true;
    return result;
}

/// @brief Parse Module Logging event (Event ID 4103).
///
/// Logs cmdlet and module invocations. Less detailed than Script Block
/// Logging but still useful for tracking command execution.
ParsedEvent parse_module_event(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::ScriptOp::Module);
    result.payload.category = event::Category::Script;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 8) {
        result.valid = false;
        return result;
    }

    // Module logging has simpler structure
    result.payload.script.sequence = 0;
    result.payload.script.is_suspicious = 0;
    result.payload.script.script_block = event::INVALID_STRING;
    result.payload.script.context = event::INVALID_STRING;

    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_powershell_event(const EVENT_RECORD* record) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<PowerShellEventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case PowerShellEventId::ScriptBlockLogging:
            return parse_script_block_event(record);
        case PowerShellEventId::ModuleLogging:
            return parse_module_event(record);
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
