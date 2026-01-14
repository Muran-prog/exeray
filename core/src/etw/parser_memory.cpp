/// @file parser_memory.cpp
/// @brief ETW parser for Virtual Memory events with RWX shellcode detection.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"

#include <cstdio>
#include <cstring>

namespace exeray::etw {

namespace {

/// Virtual memory event IDs from PageFault_VirtualAlloc class.
enum class MemoryEventId : uint16_t {
    VirtualAlloc = 98,  ///< VirtualAlloc/VirtualAllocEx
    VirtualFree = 99    ///< VirtualFree
};

// Memory protection constants (values from WinNT.h)
// These indicate executable + writable memory - suspicious for shellcode
// Note: We use custom names to avoid conflicts with Windows macros
constexpr uint32_t RWX_PAGE_EXECUTE_READWRITE = 0x40;
constexpr uint32_t RWX_PAGE_EXECUTE_WRITECOPY = 0x80;

// Threshold for "large" allocations (1MB)
constexpr uint64_t LARGE_ALLOC_THRESHOLD = 1024 * 1024;

/// @brief Check if protection flags indicate RWX memory.
///
/// RWX (Read-Write-Execute) memory is commonly used by shellcode and
/// fileless malware. Normal applications rarely allocate RWX memory.
///
/// @param protection PAGE_* protection flags.
/// @return true if RWX protection detected.
bool is_rwx_protection(uint32_t protection) {
    return (protection == RWX_PAGE_EXECUTE_READWRITE) ||
           (protection == RWX_PAGE_EXECUTE_WRITECOPY);
}

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Memory;
}

/// @brief Parse VirtualAlloc event (Event ID 98).
///
/// UserData layout (PageFault_VirtualAlloc):
///   BaseAddress: PVOID (pointer-sized)
///   RegionSize:  SIZE_T (pointer-sized)
///   ProcessId:   UINT32
///   Flags:       UINT32 (protection/allocation type)
ParsedEvent parse_virtual_alloc(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::MemoryOp::Alloc);
    result.payload.category = event::Category::Memory;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }

    // Determine pointer size from event flags
    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Minimum required: BaseAddress + RegionSize + ProcessId + Flags
    const size_t min_len = (2 * ptr_size) + 8;
    if (len < min_len) {
        result.valid = false;
        return result;
    }

    // Extract BaseAddress (pointer-sized)
    uint64_t base_address = 0;
    if (is64bit) {
        std::memcpy(&base_address, data, sizeof(uint64_t));
    } else {
        uint32_t addr32 = 0;
        std::memcpy(&addr32, data, sizeof(uint32_t));
        base_address = addr32;
    }

    // Extract RegionSize (pointer-sized, but we store max 4GB)
    uint64_t region_size_raw = 0;
    if (is64bit) {
        std::memcpy(&region_size_raw, data + ptr_size, sizeof(uint64_t));
    } else {
        uint32_t size32 = 0;
        std::memcpy(&size32, data + ptr_size, sizeof(uint32_t));
        region_size_raw = size32;
    }
    // Clamp to uint32_t max
    uint32_t region_size = (region_size_raw > UINT32_MAX)
        ? UINT32_MAX : static_cast<uint32_t>(region_size_raw);

    // Extract ProcessId and Flags (always uint32_t)
    const size_t pid_offset = 2 * ptr_size;
    uint32_t process_id = 0;
    uint32_t flags = 0;
    std::memcpy(&process_id, data + pid_offset, sizeof(uint32_t));
    std::memcpy(&flags, data + pid_offset + sizeof(uint32_t), sizeof(uint32_t));

    // Populate payload
    result.payload.memory.base_address = base_address;
    result.payload.memory.region_size = region_size;
    result.payload.memory.process_id = process_id;
    result.payload.memory.protection = flags;

    // RWX detection
    if (is_rwx_protection(flags)) {
        result.payload.memory.is_suspicious = 1;
        result.status = event::Status::Suspicious;

        // Extra warning for large RWX allocations
        if (region_size > LARGE_ALLOC_THRESHOLD) {
            std::fprintf(stderr,
                "[ALERT] Large RWX allocation: PID=%u, addr=0x%llx, size=%llu bytes\n",
                process_id,
                static_cast<unsigned long long>(base_address),
                static_cast<unsigned long long>(region_size));
        }
    } else {
        result.payload.memory.is_suspicious = 0;
    }

    result.pid = process_id;
    result.valid = true;
    return result;
}

/// @brief Parse VirtualFree event (Event ID 99).
/// Same structure as VirtualAlloc.
ParsedEvent parse_virtual_free(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::MemoryOp::Free);
    result.payload.category = event::Category::Memory;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }

    // Determine pointer size from event flags
    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    const size_t min_len = (2 * ptr_size) + 8;
    if (len < min_len) {
        result.valid = false;
        return result;
    }

    // Extract BaseAddress
    uint64_t base_address = 0;
    if (is64bit) {
        std::memcpy(&base_address, data, sizeof(uint64_t));
    } else {
        uint32_t addr32 = 0;
        std::memcpy(&addr32, data, sizeof(uint32_t));
        base_address = addr32;
    }

    // Extract RegionSize (pointer-sized, we store max 4GB)
    uint64_t region_size_raw = 0;
    if (is64bit) {
        std::memcpy(&region_size_raw, data + ptr_size, sizeof(uint64_t));
    } else {
        uint32_t size32 = 0;
        std::memcpy(&size32, data + ptr_size, sizeof(uint32_t));
        region_size_raw = size32;
    }
    uint32_t region_size = (region_size_raw > UINT32_MAX)
        ? UINT32_MAX : static_cast<uint32_t>(region_size_raw);

    // Extract ProcessId
    const size_t pid_offset = 2 * ptr_size;
    uint32_t process_id = 0;
    std::memcpy(&process_id, data + pid_offset, sizeof(uint32_t));

    result.payload.memory.base_address = base_address;
    result.payload.memory.region_size = region_size;
    result.payload.memory.process_id = process_id;
    result.payload.memory.protection = 0;
    result.payload.memory.is_suspicious = 0;

    result.pid = process_id;
    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_memory_event(const EVENT_RECORD* record) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<MemoryEventId>(record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case MemoryEventId::VirtualAlloc:
            return parse_virtual_alloc(record);
        case MemoryEventId::VirtualFree:
            return parse_virtual_free(record);
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
