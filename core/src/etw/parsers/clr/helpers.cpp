/// @file helpers.cpp
/// @brief CLR parser helper function implementations.

#ifdef _WIN32

#include "helpers.hpp"
#include "exeray/logging.hpp"

// Disable Windows min/max macros
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>

namespace exeray::etw::clr {

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

void log_clr_operation(uint32_t pid, event::ClrOp op,
                       std::wstring_view assembly, std::wstring_view method,
                       bool is_dynamic, bool is_suspicious) {
    const char* op_name = "Unknown";
    switch (op) {
        case event::ClrOp::AssemblyLoad:   op_name = "AssemblyLoad"; break;
        case event::ClrOp::AssemblyUnload: op_name = "AssemblyUnload"; break;
        case event::ClrOp::MethodJit:      op_name = "MethodJit"; break;
    }

    std::string asm_str = wstring_to_narrow(assembly);
    std::string method_str = wstring_to_narrow(method);

    if (is_suspicious) {
        if (is_dynamic) {
            EXERAY_WARN("Suspicious CLR {} [DYNAMIC/IN-MEMORY]: pid={}, asm={}, method={}",
                        op_name, pid, asm_str, method_str);
        } else {
            EXERAY_WARN("Suspicious CLR {}: pid={}, asm={}, method={}",
                        op_name, pid, asm_str, method_str);
        }
    } else {
        if (is_dynamic) {
            EXERAY_TRACE("CLR {} [DYNAMIC/IN-MEMORY]: pid={}, asm={}, method={}",
                         op_name, pid, asm_str, method_str);
        } else {
            EXERAY_TRACE("CLR {}: pid={}, asm={}, method={}",
                         op_name, pid, asm_str, method_str);
        }
    }
}

}  // namespace exeray::etw::clr

#endif  // _WIN32
