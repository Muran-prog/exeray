/// @file helpers.hpp
/// @brief Helper functions for security event parsing.

#pragma once

#ifdef _WIN32

#include <cstdint>
#include <string>
#include <string_view>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "exeray/etw/parser.hpp"

namespace exeray::etw::security {

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out);

/// @brief Extract null-terminated wide string from event data.
std::wstring_view extract_wstring(const uint8_t* data, size_t max_len);

/// @brief Check if a privilege list contains dangerous privileges.
bool has_dangerous_privilege(std::wstring_view privileges);

/// @brief Get human-readable logon type name.
const char* logon_type_name(uint32_t type);

/// @brief Convert wide string to narrow for logging.
std::string wstring_to_narrow(std::wstring_view wstr, size_t max_len = 100);

/// @brief Log security event.
void log_security_event(const char* event_type, uint32_t pid,
                        std::wstring_view user, bool suspicious,
                        const char* details = nullptr);

}  // namespace exeray::etw::security

#endif  // _WIN32
