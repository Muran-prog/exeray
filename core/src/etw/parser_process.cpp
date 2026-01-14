/// @file parser_process.cpp
/// @brief ETW parser for Microsoft-Windows-Kernel-Process events.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/event/string_pool.hpp"

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
ParsedEvent parse_process_start(const EVENT_RECORD* record, event::StringPool* strings) {
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
    offset += sizeof(uint32_t);

    result.payload.process.pid = process_id;
    result.payload.process.parent_pid = parent_id;

    // Skip SessionId, ExitStatus, DirectoryTableBase, Flags
    offset += sizeof(uint32_t) * 2;  // SessionId, ExitStatus
    offset += ptr_size;               // DirectoryTableBase
    offset += sizeof(uint32_t);       // Flags

    // Skip SID (variable length) - look for ANSI string after
    // SID format: Revision(1) + SubAuthorityCount(1) + Authority(6) + SubAuthorities(4*count)
    if (offset < len) {
        uint8_t sub_auth_count = (offset + 1 < len) ? data[offset + 1] : 0;
        offset += 8 + (4 * sub_auth_count);  // SID header + subauthorities
    }

    // Extract ImageFileName (ANSI null-terminated)
    if (offset < len && strings != nullptr) {
        const char* image_name = reinterpret_cast<const char*>(data + offset);
        size_t max_len = len - offset;
        size_t str_len = 0;
        while (str_len < max_len && image_name[str_len] != '\0') {
            ++str_len;
        }
        if (str_len > 0) {
            result.payload.process.image_path = strings->intern({image_name, str_len});
        } else {
            result.payload.process.image_path = event::INVALID_STRING;
        }
        offset += str_len + 1;  // Skip past null terminator
    } else {
        result.payload.process.image_path = event::INVALID_STRING;
    }

    // Extract CommandLine (Unicode null-terminated)
    if (offset < len && strings != nullptr) {
        const wchar_t* cmd_line = reinterpret_cast<const wchar_t*>(data + offset);
        size_t max_chars = (len - offset) / sizeof(wchar_t);
        size_t wstr_len = 0;
        while (wstr_len < max_chars && cmd_line[wstr_len] != L'\0') {
            ++wstr_len;
        }
        if (wstr_len > 0) {
            result.payload.process.command_line = strings->intern_wide({cmd_line, wstr_len});
        } else {
            result.payload.process.command_line = event::INVALID_STRING;
        }
    } else {
        result.payload.process.command_line = event::INVALID_STRING;
    }

    result.valid = true;
    return result;
}

/// @brief Parse ProcessStop event (Event ID 2).
ParsedEvent parse_process_stop(const EVENT_RECORD* record, event::StringPool* /*strings*/) {
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
ParsedEvent parse_image_load(const EVENT_RECORD* record, event::StringPool* /*strings*/) {
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

ParsedEvent parse_process_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<ProcessEventId>(record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case ProcessEventId::ProcessStart:
            return parse_process_start(record, strings);
        case ProcessEventId::ProcessStop:
            return parse_process_stop(record, strings);
        case ProcessEventId::ImageLoad:
            return parse_image_load(record, strings);
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
