/// @file parser_image.cpp
/// @brief ETW parser for Image Load/Unload events.
///
/// Parses events from the classic NT Kernel Logger Image provider.
/// Used to detect DLL/EXE loading for process injection monitoring.

#ifdef _WIN32

#include "exeray/etw/event_ids.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

#include <cstring>
#include <cwchar>

namespace exeray::etw {

namespace {

/// @brief Check if a path is suspicious (temp/appdata directories).
///
/// DLLs loaded from temporary locations are often used for injection attacks.
/// @param path Wide string path to check.
/// @param len Length of path in characters.
/// @return true if path contains suspicious patterns.
bool is_suspicious_path(const wchar_t* path, size_t len) {
    if (path == nullptr || len == 0) {
        return false;
    }

    // Convert to lowercase for case-insensitive matching
    // Check for common suspicious patterns
    const wchar_t* suspicious_patterns[] = {
        L"\\temp\\",
        L"\\tmp\\",
        L"\\appdata\\local\\temp\\",
        L"\\appdata\\roaming\\",
        L"\\users\\public\\",
        L"\\programdata\\"
    };

    // Simple substring search (case-insensitive would require more code)
    for (const auto* pattern : suspicious_patterns) {
        if (wcsstr(path, pattern) != nullptr) {
            return true;
        }
    }

    return false;
}

/// @brief Parse Image Load event (Event ID 10).
///
/// UserData layout (64-bit systems):
///   ImageBase: PVOID (8 bytes)
///   ImageSize: PVOID (8 bytes)
///   ProcessId: UINT32 (4 bytes)
///   ImageChecksum: UINT32 (4 bytes)
///   TimeDateStamp: UINT32 (4 bytes)
///   Reserved0: UINT32 (4 bytes)
///   DefaultBase: PVOID (8 bytes)
///   Reserved1-4: UINT32 * 4 (16 bytes)
///   FileName: Unicode string (null-terminated)
ParsedEvent parse_image_load(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Image);
    result.operation = static_cast<uint8_t>(event::ImageOp::Load);
    result.payload.category = event::Category::Image;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 32) {
        result.valid = false;
        return result;
    }

    // Determine pointer size from event flags
    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    size_t offset = 0;

    // Extract ImageBase
    uint64_t image_base = 0;
    if (is64bit) {
        std::memcpy(&image_base, data + offset, sizeof(uint64_t));
    } else {
        uint32_t base32 = 0;
        std::memcpy(&base32, data + offset, sizeof(uint32_t));
        image_base = base32;
    }
    offset += ptr_size;

    // Extract ImageSize
    uint64_t image_size = 0;
    if (is64bit) {
        std::memcpy(&image_size, data + offset, sizeof(uint64_t));
    } else {
        uint32_t size32 = 0;
        std::memcpy(&size32, data + offset, sizeof(uint32_t));
        image_size = size32;
    }
    offset += ptr_size;

    // Extract ProcessId
    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }
    uint32_t process_id = 0;
    std::memcpy(&process_id, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // Skip ImageChecksum, TimeDateStamp, Reserved0
    offset += 3 * sizeof(uint32_t);

    // Skip DefaultBase
    offset += ptr_size;

    // Skip Reserved1-4
    offset += 4 * sizeof(uint32_t);

    // FileName starts here (null-terminated Unicode string)
    const wchar_t* filename = nullptr;
    size_t filename_len = 0;
    if (offset < len) {
        filename = reinterpret_cast<const wchar_t*>(data + offset);
        size_t max_chars = (len - offset) / sizeof(wchar_t);
        while (filename_len < max_chars && filename[filename_len] != L'\0') {
            ++filename_len;
        }
    }

    // Populate payload
    if (strings != nullptr && filename_len > 0) {
        result.payload.image.image_path = strings->intern_wide({filename, filename_len});
    } else {
        result.payload.image.image_path = event::INVALID_STRING;
    }
    result.payload.image.process_id = process_id;
    result.payload.image.base_address = image_base;
    result.payload.image.size = static_cast<uint32_t>(image_size);
    result.payload.image.is_suspicious = is_suspicious_path(filename, filename_len) ? 1 : 0;

    result.valid = true;
    return result;
}

/// @brief Parse Image Unload event (Event ID 2).
ParsedEvent parse_image_unload(const EVENT_RECORD* record, event::StringPool* /*strings*/) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Image);
    result.operation = static_cast<uint8_t>(event::ImageOp::Unload);
    result.payload.category = event::Category::Image;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }

    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    size_t offset = 0;

    // Extract ImageBase
    uint64_t image_base = 0;
    if (is64bit) {
        std::memcpy(&image_base, data + offset, sizeof(uint64_t));
    } else {
        uint32_t base32 = 0;
        std::memcpy(&base32, data + offset, sizeof(uint32_t));
        image_base = base32;
    }
    offset += ptr_size;

    // Extract ImageSize
    uint64_t image_size = 0;
    if (is64bit) {
        std::memcpy(&image_size, data + offset, sizeof(uint64_t));
    } else {
        uint32_t size32 = 0;
        std::memcpy(&size32, data + offset, sizeof(uint32_t));
        image_size = size32;
    }
    offset += ptr_size;

    // Extract ProcessId
    if (offset + 4 > len) {
        result.valid = false;
        return result;
    }
    uint32_t process_id = 0;
    std::memcpy(&process_id, data + offset, sizeof(uint32_t));

    // Populate payload
    result.payload.image.image_path = event::INVALID_STRING;
    result.payload.image.process_id = process_id;
    result.payload.image.base_address = image_base;
    result.payload.image.size = static_cast<uint32_t>(image_size);
    result.payload.image.is_suspicious = 0;

    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_image_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = record->EventHeader.EventDescriptor.Id;

    switch (event_id) {
        case ids::image::LOAD:
            return parse_image_load(record, strings);
        case ids::image::UNLOAD:
            return parse_image_unload(record, strings);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_image(*tdh_result, record, strings);
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
