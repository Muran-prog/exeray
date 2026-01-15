#pragma once

/**
 * @file clr.hpp
 * @brief .NET CLR runtime operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief .NET CLR runtime operation types.
 *
 * Tracks assembly loading and JIT compilation for in-memory malware detection.
 */
enum class ClrOp : std::uint8_t {
    AssemblyLoad,    ///< Assembly loaded (Event 152/153)
    AssemblyUnload,  ///< Assembly unloaded (Event 154)
    MethodJit        ///< Method JIT compiled (Event 155)
};

}  // namespace exeray::event
