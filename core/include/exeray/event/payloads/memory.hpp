#pragma once

/**
 * @file memory.hpp
 * @brief Virtual memory operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for virtual memory operations.
 *
 * Contains allocation details for VirtualAlloc/VirtualFree detection.
 * Used for detecting RWX shellcode allocations (fileless malware).
 */
struct MemoryPayload {
    uint64_t base_address;   ///< Allocated memory base address
    uint32_t region_size;    ///< Size of allocation in bytes (max 4GB)
    uint32_t process_id;     ///< Target process ID
    uint32_t protection;     ///< PAGE_* protection flags
    uint8_t is_suspicious;   ///< 1 if RWX allocation detected
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

}  // namespace exeray::event
