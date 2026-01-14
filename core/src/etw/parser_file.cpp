/// @file parser_file.cpp
/// @brief ETW parser for Microsoft-Windows-Kernel-File events.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"

#include <cstring>

namespace exeray::etw {

namespace {

/// File event IDs from Microsoft-Windows-Kernel-File provider.
enum class FileEventId : uint16_t {
    Create = 10,
    Cleanup = 11,
    Read = 14,
    Write = 15,
    Delete = 26
};

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.pid = record->EventHeader.ProcessId;
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::FileSystem;
}

/// @brief Initialize file payload with defaults.
void init_file_payload(ParsedEvent& result) {
    result.payload.category = event::Category::FileSystem;
    result.payload.file.path = event::INVALID_STRING;
    result.payload.file.size = 0;
    result.payload.file.attributes = 0;
    result.payload.file._pad = 0;
}

/// @brief Parse file Create event (Event ID 10).
///
/// UserData layout:
///   Irp: PVOID
///   FileObject: PVOID
///   TTID: UINT32
///   CreateOptions: UINT32
///   FileAttributes: UINT32
///   ShareAccess: UINT32
///   OpenPath: Unicode string
ParsedEvent parse_file_create(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::FileOp::Create);
    init_file_payload(result);

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Skip Irp, FileObject
    size_t offset = ptr_size * 2;

    // Skip TTID
    offset += sizeof(uint32_t);

    if (offset + 8 > len) {
        result.valid = false;
        return result;
    }

    // Skip CreateOptions, read FileAttributes
    offset += sizeof(uint32_t);
    uint32_t attrs = 0;
    std::memcpy(&attrs, data + offset, sizeof(uint32_t));
    result.payload.file.attributes = attrs;

    result.valid = true;
    return result;
}

/// @brief Parse file Cleanup event (Event ID 11).
ParsedEvent parse_file_cleanup(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    // Cleanup maps to Create with status info (file close)
    result.operation = static_cast<uint8_t>(event::FileOp::Create);
    result.status = event::Status::Success;
    init_file_payload(result);
    result.valid = true;
    return result;
}

/// @brief Parse file Read event (Event ID 14).
///
/// UserData layout:
///   Offset: UINT64
///   Irp: PVOID
///   FileObject: PVOID
///   FileKey: PVOID
///   TTID: UINT32
///   IoSize: UINT32
///   IoFlags: UINT32
ParsedEvent parse_file_read(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::FileOp::Read);
    init_file_payload(result);

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 24) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Skip Offset (8) + Irp + FileObject + FileKey + TTID (4)
    size_t offset = 8 + ptr_size * 3 + sizeof(uint32_t);

    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }

    uint32_t io_size = 0;
    std::memcpy(&io_size, data + offset, sizeof(uint32_t));
    result.payload.file.size = io_size;

    result.valid = true;
    return result;
}

/// @brief Parse file Write event (Event ID 15).
ParsedEvent parse_file_write(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::FileOp::Write);
    init_file_payload(result);

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 24) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Same layout as Read
    size_t offset = 8 + ptr_size * 3 + sizeof(uint32_t);

    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }

    uint32_t io_size = 0;
    std::memcpy(&io_size, data + offset, sizeof(uint32_t));
    result.payload.file.size = io_size;

    result.valid = true;
    return result;
}

/// @brief Parse file Delete event (Event ID 26).
ParsedEvent parse_file_delete(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::FileOp::Delete);
    init_file_payload(result);
    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_file_event(const EVENT_RECORD* record) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<FileEventId>(record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case FileEventId::Create:
            return parse_file_create(record);
        case FileEventId::Cleanup:
            return parse_file_cleanup(record);
        case FileEventId::Read:
            return parse_file_read(record);
        case FileEventId::Write:
            return parse_file_write(record);
        case FileEventId::Delete:
            return parse_file_delete(record);
        default:
            return ParsedEvent{.valid = false};
    }
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
