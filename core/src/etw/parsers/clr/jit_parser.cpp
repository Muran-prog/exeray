/// @file jit_parser.cpp
/// @brief CLR JIT compilation event parser implementation.

#ifdef _WIN32

#include "jit_parser.hpp"
#include "detection.hpp"
#include "helpers.hpp"

#include <cstring>
#include <string>

namespace exeray::etw::clr {

ParsedEvent parse_jit_event(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    exeray::etw::extract_common(record, result, event::Category::Clr);
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

}  // namespace exeray::etw::clr

#endif  // _WIN32
