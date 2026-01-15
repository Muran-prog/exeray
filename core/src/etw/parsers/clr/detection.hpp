/// @file detection.hpp
/// @brief CLR suspicious activity detection declarations.

#pragma once

#ifdef _WIN32

#include <string_view>

namespace exeray::etw::clr {

/// @brief Case-insensitive wide string contains check.
bool contains_icase(std::wstring_view haystack, const wchar_t* needle);

/// @brief Check if assembly comes from a suspicious path.
bool is_suspicious_path(std::wstring_view path);

/// @brief Check if a method name looks obfuscated.
bool is_obfuscated_name(std::wstring_view name);

}  // namespace exeray::etw::clr

#endif  // _WIN32
