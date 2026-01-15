/// @file detection.hpp
/// @brief WMI attack detection declarations.

#pragma once

#include <string_view>

namespace exeray::etw::wmi {

/// @brief Case-insensitive wide string contains check.
bool contains_icase(std::wstring_view haystack, const wchar_t* needle);

/// @brief Check if WMI query/method indicates suspicious activity.
bool is_suspicious_wmi_activity(std::wstring_view query_or_method,
                                 std::wstring_view wmi_namespace);

/// @brief Check if target host indicates remote WMI.
bool is_remote_host(std::wstring_view host);

}  // namespace exeray::etw::wmi
