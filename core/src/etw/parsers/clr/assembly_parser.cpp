/// @file assembly_parser.cpp
/// @brief CLR assembly event parser implementation.

#ifdef _WIN32

#include "assembly_parser.hpp"
#include "detection.hpp"
#include "helpers.hpp"

#include <cstring>

namespace exeray::etw::clr {

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

}  // namespace exeray::etw::clr

#endif  // _WIN32
