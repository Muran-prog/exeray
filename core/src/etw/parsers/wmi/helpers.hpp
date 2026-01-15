/// @file helpers.hpp
/// @brief WMI parser helper function declarations.

#pragma once

#include "exeray/etw/parser.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/types.hpp"
#include <string>
#include <string_view>

namespace exeray::etw::wmi {

/// @brief Extract wide string from event data.
std::wstring_view extract_wstring(const uint8_t* data, size_t max_len);

/// @brief Convert wide string to narrow for logging.
std::string wstring_to_narrow(std::wstring_view wstr, size_t max_len = 80);

/// @brief Log WMI operation.
void log_wmi_operation(uint32_t pid, event::WmiOp op,
                       std::wstring_view ns, std::wstring_view query,
                       std::wstring_view host, bool is_suspicious);

}  // namespace exeray::etw::wmi
