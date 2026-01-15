/// @file helpers.cpp
/// @brief Helper function implementations for security event parsing.

#ifdef _WIN32

#include "helpers.hpp"
#include "constants.hpp"
#include "exeray/logging.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>

namespace exeray::etw::security {

std::wstring_view extract_wstring(const uint8_t* data, size_t max_len) {
    if (data == nullptr || max_len < 2) {
        return {};
    }
    const auto* wdata = reinterpret_cast<const wchar_t*>(data);
    size_t max_chars = max_len / sizeof(wchar_t);
    size_t len = 0;
    while (len < max_chars && wdata[len] != L'\0') {
        ++len;
    }
    return {wdata, len};
}

bool has_dangerous_privilege(std::wstring_view privileges) {
    for (const auto* priv : DANGEROUS_PRIVILEGES) {
        if (privileges.find(priv) != std::wstring_view::npos) {
            return true;
        }
    }
    return false;
}

const char* logon_type_name(uint32_t type) {
    switch (type) {
        case logon_types::INTERACTIVE: return "Interactive";
        case logon_types::NETWORK: return "Network";
        case logon_types::BATCH: return "Batch";
        case logon_types::SERVICE: return "Service";
        case logon_types::UNLOCK: return "Unlock";
        case logon_types::NETWORK_CLEARTEXT: return "NetworkCleartext";
        case logon_types::NEW_CREDENTIALS: return "NewCredentials";
        case logon_types::REMOTE_INTERACTIVE: return "RemoteInteractive";
        case logon_types::CACHED_INTERACTIVE: return "CachedInteractive";
        default: return "Unknown";
    }
}

std::string wstring_to_narrow(std::wstring_view wstr, size_t max_len) {
    std::string result;
    result.reserve((std::min)(wstr.size(), max_len));
    for (size_t i = 0; i < wstr.size() && i < max_len; ++i) {
        result.push_back(static_cast<char>(wstr[i] & 0x7F));
    }
    if (wstr.size() > max_len) {
        result += "...";
    }
    return result;
}

void log_security_event(const char* event_type, uint32_t pid,
                        std::wstring_view user, bool suspicious,
                        const char* details) {
    std::string user_str = wstring_to_narrow(user);
    if (suspicious) {
        if (details) {
            EXERAY_WARN("{}: pid={}, user={}, {} [SUSPICIOUS]", event_type, pid, user_str, details);
        } else {
            EXERAY_WARN("{}: pid={}, user={} [SUSPICIOUS]", event_type, pid, user_str);
        }
    } else {
        if (details) {
            EXERAY_TRACE("{}: pid={}, user={}, {}", event_type, pid, user_str, details);
        } else {
            EXERAY_TRACE("{}: pid={}, user={}", event_type, pid, user_str);
        }
    }
}

}  // namespace exeray::etw::security

#endif  // _WIN32
