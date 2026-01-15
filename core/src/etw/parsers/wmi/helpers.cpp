/// @file helpers.cpp
/// @brief WMI parser helper functions.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/event/types.hpp"
#include "exeray/logging.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <string>
#include <string_view>

namespace exeray::etw::wmi {

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

void log_wmi_operation(uint32_t pid, event::WmiOp op,
                       std::wstring_view ns, std::wstring_view query,
                       std::wstring_view host, bool is_suspicious) {
    const char* op_name = "Unknown";
    switch (op) {
        case event::WmiOp::Query: op_name = "Query"; break;
        case event::WmiOp::ExecMethod: op_name = "ExecMethod"; break;
        case event::WmiOp::Subscribe: op_name = "Subscribe"; break;
        case event::WmiOp::Connect: op_name = "Connect"; break;
    }

    std::string ns_str = wstring_to_narrow(ns, 80);
    std::string query_str = wstring_to_narrow(query, 80);
    std::string host_str = wstring_to_narrow(host, 80);

    if (is_suspicious) {
        if (!host.empty()) {
            EXERAY_WARN("Suspicious WMI {}: pid={}, ns={}, query={}, host={}",
                        op_name, pid, ns_str, query_str, host_str);
        } else {
            EXERAY_WARN("Suspicious WMI {}: pid={}, ns={}, query={}",
                        op_name, pid, ns_str, query_str);
        }
    } else {
        if (!host.empty()) {
            EXERAY_TRACE("WMI {}: pid={}, ns={}, query={}, host={}",
                         op_name, pid, ns_str, query_str, host_str);
        } else {
            EXERAY_TRACE("WMI {}: pid={}, ns={}, query={}",
                         op_name, pid, ns_str, query_str);
        }
    }
}

}  // namespace exeray::etw::wmi

#endif  // _WIN32
