/// @file parser_clr.cpp
/// @brief ETW parser for Microsoft-Windows-DotNETRuntime events.
///
/// Parses CLR runtime events for malware detection including:
/// - In-memory assembly loading (dynamic assemblies without files)
/// - Assembly loading from suspicious paths (TEMP, AppData)
/// - Obfuscated method names during JIT compilation

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

/// CLR Runtime event IDs from Microsoft-Windows-DotNETRuntime provider.
enum class ClrEventId : uint16_t {
    AssemblyLoadStart = 152,   ///< Assembly load started
    AssemblyLoadStop  = 153,   ///< Assembly load completed
    AssemblyUnload    = 154,   ///< Assembly unloaded
    MethodJitStart    = 155    ///< Method JIT compilation started
};

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Clr;
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

/// @brief Check if assembly comes from a suspicious path.
///
/// Suspicious locations:
/// - %TEMP% and %TMP% directories
/// - %APPDATA% and %LOCALAPPDATA%
/// - Downloads folder
bool is_suspicious_path(std::wstring_view path) {
    if (path.empty()) return false;

    if (contains_icase(path, L"\\temp\\") ||
        contains_icase(path, L"\\tmp\\") ||
        contains_icase(path, L"\\appdata\\") ||
        contains_icase(path, L"\\downloads\\")) {
        return true;
    }
    return false;
}

/// @brief Check if a method name looks obfuscated.
///
/// Heuristics:
/// - Very short names (< 3 chars)
/// - Names with high non-alpha ratio (> 50%)
/// - Names starting with special characters
bool is_obfuscated_name(std::wstring_view name) {
    if (name.empty()) return false;

    // Very short method names
    if (name.size() < 3) return true;

    // Check for high ratio of non-alphanumeric characters
    size_t non_alpha = 0;
    for (wchar_t c : name) {
        if (!((c >= L'a' && c <= L'z') ||
              (c >= L'A' && c <= L'Z') ||
              (c >= L'0' && c <= L'9') ||
              c == L'_' || c == L'.')) {
            ++non_alpha;
        }
    }

    // > 50% non-alphanumeric is suspicious
    return (non_alpha * 2 > name.size());
}

/// @brief Convert wide string to narrow for logging.
std::string wstring_to_narrow(std::wstring_view wstr, size_t max_len = 60) {
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

/// @brief Log CLR operation.
void log_clr_operation(uint32_t pid, event::ClrOp op,
                       std::wstring_view assembly, std::wstring_view method,
                       bool is_dynamic, bool is_suspicious) {
    const char* op_name = "Unknown";
    switch (op) {
        case event::ClrOp::AssemblyLoad:   op_name = "AssemblyLoad"; break;
        case event::ClrOp::AssemblyUnload: op_name = "AssemblyUnload"; break;
        case event::ClrOp::MethodJit:      op_name = "MethodJit"; break;
    }

    std::string asm_str = wstring_to_narrow(assembly);
    std::string method_str = wstring_to_narrow(method);

    if (is_suspicious) {
        if (is_dynamic) {
            EXERAY_WARN("Suspicious CLR {} [DYNAMIC/IN-MEMORY]: pid={}, asm={}, method={}",
                        op_name, pid, asm_str, method_str);
        } else {
            EXERAY_WARN("Suspicious CLR {}: pid={}, asm={}, method={}",
                        op_name, pid, asm_str, method_str);
        }
    } else {
        if (is_dynamic) {
            EXERAY_TRACE("CLR {} [DYNAMIC/IN-MEMORY]: pid={}, asm={}, method={}",
                         op_name, pid, asm_str, method_str);
        } else {
            EXERAY_TRACE("CLR {}: pid={}, asm={}, method={}",
                         op_name, pid, asm_str, method_str);
        }
    }
}

/// @brief Parse assembly load/unload event.
///
/// Assembly event data layout (approximate for AssemblyLoad_V1):
///   ClrInstanceID: uint16
///   AssemblyID: uint64
///   AppDomainID: uint64
///   BindingID: uint64
///   AssemblyFlags: uint32
///   FullyQualifiedAssemblyName: WSTRING
ParsedEvent parse_assembly_event(const EVENT_RECORD* record,
                                  event::StringPool* strings,
                                  event::ClrOp op) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(op);
    result.payload.category = event::Category::Clr;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 32) {
        result.valid = false;
        return result;
    }

    // Skip ClrInstanceID(2) + AssemblyID(8) + AppDomainID(8) + BindingID(8)
    size_t offset = 2 + 8 + 8 + 8;

    // AssemblyFlags - bit 0x2 indicates dynamic assembly
    uint32_t flags = 0;
    if (offset + 4 <= len) {
        std::memcpy(&flags, data + offset, sizeof(flags));
        offset += 4;
    }

    bool is_dynamic = (flags & 0x2) != 0;

    // Extract assembly name
    std::wstring_view assembly_name;
    if (offset < len) {
        assembly_name = extract_wstring(data + offset, len - offset);
    }

    // No file path means loaded from memory
    if (assembly_name.empty()) {
        is_dynamic = true;
    }

    // Suspicious detection
    bool suspicious = is_dynamic || is_suspicious_path(assembly_name);

    // Populate payload
    if (strings != nullptr && !assembly_name.empty()) {
        result.payload.clr.assembly_name = strings->intern_wide(assembly_name);
    } else {
        result.payload.clr.assembly_name = event::INVALID_STRING;
    }
    result.payload.clr.method_name = event::INVALID_STRING;
    result.payload.clr.load_address = 0;
    result.payload.clr.is_dynamic = is_dynamic ? 1 : 0;
    result.payload.clr.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.clr._pad, 0, sizeof(result.payload.clr._pad));

    result.status = suspicious ? event::Status::Suspicious : event::Status::Success;

    log_clr_operation(result.pid, op, assembly_name, {}, is_dynamic, suspicious);

    result.valid = true;
    return result;
}

/// @brief Parse JIT compilation event.
///
/// MethodJitStart event data layout:
///   MethodID: uint64
///   ModuleID: uint64
///   MethodToken: uint32
///   MethodILSize: uint32
///   MethodNamespace: WSTRING
///   MethodName: WSTRING
///   MethodSignature: WSTRING
ParsedEvent parse_jit_event(const EVENT_RECORD* record,
                             event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::ClrOp::MethodJit);
    result.payload.category = event::Category::Clr;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 24) {
        result.valid = false;
        return result;
    }

    // Skip MethodID(8) + ModuleID(8) + MethodToken(4) + MethodILSize(4)
    size_t offset = 8 + 8 + 4 + 4;

    // Extract method namespace
    std::wstring_view method_ns;
    if (offset < len) {
        method_ns = extract_wstring(data + offset, len - offset);
        offset += (method_ns.size() + 1) * sizeof(wchar_t);
    }

    // Extract method name
    std::wstring_view method_name;
    if (offset < len) {
        method_name = extract_wstring(data + offset, len - offset);
    }

    // Check for obfuscated names
    bool suspicious = is_obfuscated_name(method_name) ||
                      is_obfuscated_name(method_ns);

    // Build full method name (namespace.method)
    std::wstring full_name;
    if (!method_ns.empty()) {
        full_name = std::wstring(method_ns) + L"." + std::wstring(method_name);
    } else if (!method_name.empty()) {
        full_name = std::wstring(method_name);
    }

    // Populate payload
    result.payload.clr.assembly_name = event::INVALID_STRING;
    if (strings != nullptr && !full_name.empty()) {
        result.payload.clr.method_name = strings->intern_wide(full_name);
    } else {
        result.payload.clr.method_name = event::INVALID_STRING;
    }
    result.payload.clr.load_address = 0;
    result.payload.clr.is_dynamic = 0;
    result.payload.clr.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.clr._pad, 0, sizeof(result.payload.clr._pad));

    result.status = suspicious ? event::Status::Suspicious : event::Status::Success;

    log_clr_operation(result.pid, event::ClrOp::MethodJit, {}, full_name,
                      false, suspicious);

    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_clr_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<ClrEventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case ClrEventId::AssemblyLoadStart:
        case ClrEventId::AssemblyLoadStop:
            return parse_assembly_event(record, strings, event::ClrOp::AssemblyLoad);
        case ClrEventId::AssemblyUnload:
            return parse_assembly_event(record, strings, event::ClrOp::AssemblyUnload);
        case ClrEventId::MethodJitStart:
            return parse_jit_event(record, strings);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_clr(*tdh_result, record, strings);
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
