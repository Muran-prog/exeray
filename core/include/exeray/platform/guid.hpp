/// @file platform/guid.hpp
/// @brief Cross-platform GUID type definition.
///
/// On Windows, includes the native GUID type from windows.h.
/// On other platforms, defines a compatible stub structure.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#else  // !_WIN32

#include <cstdint>

namespace exeray {

/// @brief Stub GUID structure for non-Windows platforms.
/// Compatible layout with Windows GUID.
struct GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
};

}  // namespace exeray

// Bring GUID into global namespace to match Windows behavior
using GUID = exeray::GUID;

#endif  // _WIN32
