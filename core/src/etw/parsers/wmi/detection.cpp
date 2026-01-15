/// @file detection.cpp
/// @brief WMI attack detection implementations.

#ifdef _WIN32

#include "detection.hpp"
#include <cwchar>

namespace exeray::etw::wmi {

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
            // Fold to lowercase
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

bool is_suspicious_wmi_activity(std::wstring_view query_or_method,
                                 std::wstring_view wmi_namespace) {
    // Check for process creation (fileless execution)
    if (contains_icase(query_or_method, L"Win32_Process") &&
        contains_icase(query_or_method, L"Create")) {
        return true;
    }

    // Check for WMI event subscription persistence
    if (contains_icase(query_or_method, L"__EventConsumer") ||
        contains_icase(query_or_method, L"__EventFilter") ||
        contains_icase(query_or_method, L"__FilterToConsumerBinding") ||
        contains_icase(query_or_method, L"CommandLineEventConsumer") ||
        contains_icase(query_or_method, L"ActiveScriptEventConsumer")) {
        return true;
    }

    // Check for PowerShell execution via WMI
    if (contains_icase(query_or_method, L"powershell") ||
        contains_icase(query_or_method, L"pwsh")) {
        return true;
    }

    // Check for subscription namespace (common for persistence)
    if (contains_icase(wmi_namespace, L"subscription")) {
        return true;
    }

    return false;
}

bool is_remote_host(std::wstring_view host) {
    if (host.empty()) return false;

    // Local indicators
    if (host == L"." || host == L"localhost" ||
        contains_icase(host, L"127.0.0.1") ||
        contains_icase(host, L"::1")) {
        return false;
    }

    return true;
}

}  // namespace exeray::etw::wmi

#endif  // _WIN32
