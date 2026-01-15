/// @file parser_registry.cpp
/// @brief ETW parser for Microsoft-Windows-Kernel-Registry events.

#ifdef _WIN32

#include "exeray/etw/event_ids.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

#include <cstring>

namespace exeray::etw {

namespace {

/// @brief Initialize registry payload with defaults.
void init_registry_payload(ParsedEvent& result) {
    result.payload.category = event::Category::Registry;
    result.payload.registry.key_path = event::INVALID_STRING;
    result.payload.registry.value_name = event::INVALID_STRING;
    result.payload.registry.value_type = 0;
    result.payload.registry.data_size = 0;
}

/// @brief Parse registry key events (CreateKey, OpenKey).
///
/// UserData layout:
///   BaseObject: PVOID
///   KeyObject: PVOID
///   Status: NTSTATUS (UINT32)
///   Disposition: UINT32 (for CreateKey)
///   BaseName: UINT32 (offset)
///   RelativeName: Unicode string
ParsedEvent parse_key_event(const EVENT_RECORD* record, event::RegistryOp op, event::StringPool* /*strings*/) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Registry);
    result.operation = static_cast<uint8_t>(op);
    init_registry_payload(result);

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 12) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Skip BaseObject, KeyObject
    size_t offset = ptr_size * 2;

    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }

    // Extract Status (NTSTATUS)
    int32_t ntstatus = 0;
    std::memcpy(&ntstatus, data + offset, sizeof(int32_t));
    result.status = (ntstatus >= 0) ? event::Status::Success : event::Status::Error;

    result.valid = true;
    return result;
}

/// @brief Parse registry value events (SetValue, DeleteValue).
///
/// UserData layout:
///   KeyObject: PVOID
///   Status: NTSTATUS (UINT32)
///   Type: UINT32 (for SetValue)
///   DataSize: UINT32 (for SetValue)
///   KeyName: Unicode string
///   ValueName: Unicode string
ParsedEvent parse_value_event(const EVENT_RECORD* record, event::RegistryOp op, event::StringPool* /*strings*/) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Registry);
    result.operation = static_cast<uint8_t>(op);
    init_registry_payload(result);

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 8) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Skip KeyObject
    size_t offset = ptr_size;

    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }

    // Extract Status
    int32_t ntstatus = 0;
    std::memcpy(&ntstatus, data + offset, sizeof(int32_t));
    result.status = (ntstatus >= 0) ? event::Status::Success : event::Status::Error;
    offset += sizeof(int32_t);

    // For SetValue, extract Type and DataSize
    if (op == event::RegistryOp::SetValue && offset + 8 <= len) {
        uint32_t value_type = 0;
        uint32_t data_size = 0;
        std::memcpy(&value_type, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        std::memcpy(&data_size, data + offset, sizeof(uint32_t));

        result.payload.registry.value_type = value_type;
        result.payload.registry.data_size = data_size;
    }

    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_registry_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = record->EventHeader.EventDescriptor.Id;

    switch (event_id) {
        case ids::registry::CREATE_KEY:
            return parse_key_event(record, event::RegistryOp::CreateKey, strings);
        case ids::registry::OPEN_KEY:
            return parse_key_event(record, event::RegistryOp::QueryValue, strings);
        case ids::registry::SET_VALUE:
            return parse_value_event(record, event::RegistryOp::SetValue, strings);
        case ids::registry::DELETE_VALUE:
            return parse_value_event(record, event::RegistryOp::DeleteValue, strings);
        default:
            // Unknown event - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_registry(*tdh_result, record, strings);
            }
            return ParsedEvent{.valid = false};
    }
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
