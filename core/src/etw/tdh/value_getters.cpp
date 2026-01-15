/// @file value_getters.cpp
/// @brief TDH value getter functions.

#ifdef _WIN32

#include "exeray/etw/tdh/internal.hpp"

namespace exeray::etw::tdh::detail {

std::wstring get_wstring_prop(const TdhParsedEvent& event, const std::wstring& name) {
    auto it = event.properties.find(name);
    if (it != event.properties.end()) {
        if (auto* str = std::get_if<std::wstring>(&it->second)) {
            return *str;
        }
    }
    return L"";
}

uint32_t get_uint32_prop(const TdhParsedEvent& event, const std::wstring& name) {
    auto it = event.properties.find(name);
    if (it != event.properties.end()) {
        if (auto* val = std::get_if<uint32_t>(&it->second)) {
            return *val;
        }
        if (auto* val = std::get_if<uint64_t>(&it->second)) {
            return static_cast<uint32_t>(*val);
        }
        if (auto* val = std::get_if<int32_t>(&it->second)) {
            return static_cast<uint32_t>(*val);
        }
    }
    return 0;
}

uint64_t get_uint64_prop(const TdhParsedEvent& event, const std::wstring& name) {
    auto it = event.properties.find(name);
    if (it != event.properties.end()) {
        if (auto* val = std::get_if<uint64_t>(&it->second)) {
            return *val;
        }
        if (auto* val = std::get_if<uint32_t>(&it->second)) {
            return static_cast<uint64_t>(*val);
        }
    }
    return 0;
}

}  // namespace exeray::etw::tdh::detail

#else  // !_WIN32

namespace exeray::etw::tdh::detail {
// Empty translation unit for non-Windows
}

#endif  // _WIN32
