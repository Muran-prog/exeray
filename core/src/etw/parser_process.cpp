/// @file parser_process.cpp
/// @brief ETW parser for Microsoft-Windows-Kernel-Process events.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"

#include <cstring>

namespace exeray::etw {

namespace {

/// Process event IDs from Microsoft-Windows-Kernel-Process provider.
enum class ProcessEventId : uint16_t {
    ProcessStart = 1,
    ProcessStop = 2,
    ImageLoad = 5
};

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.pid = record->EventHeader.ProcessId;
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Process;
}

/// @brief Parse ProcessStart event (Event ID 1).
///
/// UserData layout (version 3+):
///   UniqueProcessKey: PVOID
///   ProcessId: UINT32
///   ParentId: UINT32
///   SessionId: UINT32
///   ExitStatus: INT32
///   DirectoryTableBase: PVOID
///   Flags: UINT32
///   UserSID: SID (variable)
///   ImageFileName: ANSI string (null-terminated)
///   CommandLine: Unicode string (null-terminated)
ParsedEvent parse_process_start(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::ProcessOp::Create);
    result.payload.category = event::Category::Process;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 24) {
        result.valid = false;
        return result;
    }

    // Determine pointer size from event flags
    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    size_t offset = ptr_size;  // Skip UniqueProcessKey

    if (offset + 8 > len) {
        result.valid = false;
        return result;
    }

    // Extract ProcessId and ParentId
    uint32_t process_id = 0;
    uint32_t parent_id = 0;
    std::memcpy(&process_id, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    std::memcpy(&parent_id, data + offset, sizeof(uint32_t));

    result.payload.process.pid = process_id;
    result.payload.process.parent_pid = parent_id;
    result.payload.process.image_path = event::INVALID_STRING;
    result.payload.process.command_line = event::INVALID_STRING;

    result.valid = true;
    return result;
}

/// @brief Parse ProcessStop event (Event ID 2).
ParsedEvent parse_process_stop(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::ProcessOp::Terminate);
    result.payload.category = event::Category::Process;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    size_t offset = ptr_size;  // Skip UniqueProcessKey

    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }

    uint32_t process_id = 0;
    std::memcpy(&process_id, data + offset, sizeof(uint32_t));

    result.payload.process.pid = process_id;
    result.payload.process.parent_pid = 0;
    result.payload.process.image_path = event::INVALID_STRING;
    result.payload.process.command_line = event::INVALID_STRING;

    result.valid = true;
    return result;
}

/// @brief Parse ImageLoad event (Event ID 5).
///
/// UserData layout:
///   ImageBase: PVOID
///   ImageSize: PVOID
///   ProcessId: UINT32
///   ImageChecksum: UINT32
///   TimeDateStamp: UINT32
///   SignatureLevel: UINT8
///   SignatureType: UINT8
///   Reserved0: UINT16
///   DefaultBase: PVOID
///   Reserved1-4: UINT32 each
///   FileName: Unicode string
ParsedEvent parse_image_load(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::ProcessOp::LoadLibrary);
    result.payload.category = event::Category::Process;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 20) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Skip ImageBase and ImageSize
    size_t offset = ptr_size * 2;

    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }

    uint32_t process_id = 0;
    std::memcpy(&process_id, data + offset, sizeof(uint32_t));

    result.payload.process.pid = process_id;
    result.payload.process.parent_pid = 0;
    result.payload.process.image_path = event::INVALID_STRING;
    result.payload.process.command_line = event::INVALID_STRING;

    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_process_event(const EVENT_RECORD* record) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<ProcessEventId>(record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case ProcessEventId::ProcessStart:
            return parse_process_start(record);
        case ProcessEventId::ProcessStop:
            return parse_process_stop(record);
        case ProcessEventId::ImageLoad:
            return parse_image_load(record);
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
