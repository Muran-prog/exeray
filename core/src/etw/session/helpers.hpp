#pragma once

/// @file helpers.hpp
/// @brief Session helper function declarations.

#ifdef _WIN32

#include <cstddef>
#include <windows.h>
#include <evntrace.h>

namespace exeray::etw::session {

/// @brief Log a Windows error to stderr.
/// @param context Descriptive context for the error.
/// @param error_code Windows error code.
void log_error(const wchar_t* context, ULONG error_code);

/// @brief Size of the properties buffer including session name.
/// @return Buffer size in bytes.
constexpr size_t properties_buffer_size() {
    return sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(wchar_t));
}

}  // namespace exeray::etw::session

#endif  // _WIN32
