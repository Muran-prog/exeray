/// @file constants.hpp
/// @brief CLR Runtime event constants.

#pragma once

#ifdef _WIN32

#include <cstdint>

namespace exeray::etw::clr {

/// CLR Runtime event IDs from Microsoft-Windows-DotNETRuntime provider.
enum class ClrEventId : uint16_t {
    AssemblyLoadStart = 152,   ///< Assembly load started
    AssemblyLoadStop  = 153,   ///< Assembly load completed
    AssemblyUnload    = 154,   ///< Assembly unloaded
    MethodJitStart    = 155    ///< Method JIT compilation started
};

}  // namespace exeray::etw::clr

#endif  // _WIN32
