/// @file helpers.hpp
/// @brief DNS parser helper functions.

#pragma once

#ifdef _WIN32
#include <windows.h>
#include <evntrace.h>
#endif

#include <cstdint>
#include <string>
#include <string_view>

#include "exeray/etw/parser.hpp"

namespace exeray::etw::dns {

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out);

/// @brief Extract wide string from event data.
/// @param data Pointer to start of string.
/// @param max_len Maximum bytes to read.
/// @return String view (empty if null or invalid).
std::wstring_view extract_wstring(const uint8_t* data, size_t max_len);

/// @brief Convert wide string to narrow for logging.
std::string wstring_to_narrow(std::wstring_view wstr);

/// @brief Log DNS query event.
void log_dns_query(uint32_t pid, std::wstring_view domain, uint32_t query_type,
                   uint32_t result_code, bool is_suspicious);

}  // namespace exeray::etw::dns
