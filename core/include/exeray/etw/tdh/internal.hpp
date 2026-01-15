/// @file internal.hpp
/// @brief Internal helpers for TDH parser modules.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "exeray/event/types.hpp"
#include "exeray/etw/parser.hpp"

namespace exeray::event {
class StringPool;
}

namespace exeray::etw {

/// @brief Property value types that TDH can extract.
using TdhPropertyValue = std::variant<
    uint64_t,
    uint32_t,
    int32_t,
    std::wstring,
    std::vector<uint8_t>
>;

/// @brief TDH-parsed event as key-value pairs.
struct TdhParsedEvent {
    std::unordered_map<std::wstring, TdhPropertyValue> properties;
    uint16_t event_id{0};
    uint8_t event_version{0};
};

namespace tdh::detail {

/// @brief Get pointer size from event header flags.
ULONG get_pointer_size(const EVENT_RECORD* record);

/// @brief Extract property name from TRACE_EVENT_INFO.
std::wstring get_property_name(PTRACE_EVENT_INFO info, ULONG property_index);

/// @brief Get property size from event info.
ULONG get_property_size(
    PTRACE_EVENT_INFO info,
    const EVENT_RECORD* record,
    ULONG property_index
);

/// @brief Extract a single property value from event data.
std::optional<TdhPropertyValue> extract_property(
    PTRACE_EVENT_INFO info,
    const EVENT_RECORD* record,
    ULONG property_index,
    PBYTE& user_data,
    ULONG& user_data_length
);

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out);

/// @brief Get wide string property or empty.
std::wstring get_wstring_prop(const TdhParsedEvent& event, const std::wstring& name);

/// @brief Get uint32 property or 0.
uint32_t get_uint32_prop(const TdhParsedEvent& event, const std::wstring& name);

/// @brief Get uint64 property or 0.
uint64_t get_uint64_prop(const TdhParsedEvent& event, const std::wstring& name);

}  // namespace tdh::detail
}  // namespace exeray::etw

#endif  // _WIN32
