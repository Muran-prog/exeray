/// @file detection.cpp
/// @brief CLR suspicious activity detection implementation.

#ifdef _WIN32

#include "detection.hpp"

#include <cstring>

namespace exeray::etw::clr {

bool contains_icase(std::wstring_view haystack, const wchar_t* needle) {
    if (haystack.empty() || needle == nullptr || needle[0] == L'\0') {
        return false;
    }

    size_t needle_len = wcslen(needle);
    if (needle_len > haystack.size()) {
        return false;
    }

    for (size_t i = 0; i <= haystack.size() - needle_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle_len; ++j) {
            wchar_t h = haystack[i + j];
            wchar_t n = needle[j];
            if (h >= L'A' && h <= L'Z') h = h - L'A' + L'a';
            if (n >= L'A' && n <= L'Z') n = n - L'A' + L'a';
            if (h != n) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

bool is_suspicious_path(std::wstring_view path) {
    if (path.empty()) return false;

    if (contains_icase(path, L"\\temp\\") ||
        contains_icase(path, L"\\tmp\\") ||
        contains_icase(path, L"\\appdata\\") ||
        contains_icase(path, L"\\downloads\\")) {
        return true;
    }
    return false;
}

bool is_obfuscated_name(std::wstring_view name) {
    if (name.empty()) return false;

    // Very short method names
    if (name.size() < 3) return true;

    // Check for high ratio of non-alphanumeric characters
    size_t non_alpha = 0;
    for (wchar_t c : name) {
        if (!((c >= L'a' && c <= L'z') ||
              (c >= L'A' && c <= L'Z') ||
              (c >= L'0' && c <= L'9') ||
              c == L'_' || c == L'.')) {
            ++non_alpha;
        }
    }

    // > 50% non-alphanumeric is suspicious
    return (non_alpha * 2 > name.size());
}

}  // namespace exeray::etw::clr

#endif  // _WIN32
