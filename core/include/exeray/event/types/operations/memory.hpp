#pragma once

/**
 * @file memory.hpp
 * @brief Virtual memory operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Virtual memory operation types.
 *
 * Tracks VirtualAlloc/VirtualProtect for RWX shellcode detection.
 */
enum class MemoryOp : std::uint8_t {
    Alloc,    ///< VirtualAlloc
    Free      ///< VirtualFree
};

}  // namespace exeray::event
