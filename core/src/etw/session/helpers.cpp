/// @file helpers.cpp
/// @brief Session helper function implementations.

#ifdef _WIN32

#include "helpers.hpp"

#include <cstdio>

namespace exeray::etw::session {

void log_error(const wchar_t* context, ULONG error_code) {
    wchar_t* message = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&message), 0, nullptr);

    if (message) {
        std::fwprintf(stderr, L"[ETW] %ls: error %lu - %ls", context, error_code, message);
        LocalFree(message);
    } else {
        std::fwprintf(stderr, L"[ETW] %ls: error %lu\n", context, error_code);
    }
}

}  // namespace exeray::etw::session

#endif  // _WIN32
