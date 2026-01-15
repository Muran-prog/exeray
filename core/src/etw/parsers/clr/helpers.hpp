/// @file helpers.hpp
/// @brief CLR parser helper function declarations.

#pragma once

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/event/types.hpp"

#include <string>
#include <string_view>

namespace exeray::etw::clr {

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out);

/// @brief Extract wide string from event data.
std::wstring_view extract_wstring(const uint8_t* data, size_t max_len);

/// @brief Convert wide string to narrow for logging.
std::string wstring_to_narrow(std::wstring_view wstr, size_t max_len = 60);

/// @brief Log CLR operation.
void log_clr_operation(uint32_t pid, event::ClrOp op,
                       std::wstring_view assembly, std::wstring_view method,
                       bool is_dynamic, bool is_suspicious);

}  // namespace exeray::etw::clr

#endif  // _WIN32
