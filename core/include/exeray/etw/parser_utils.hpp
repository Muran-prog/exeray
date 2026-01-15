/// @file parser_utils.hpp
/// @brief Common utilities for ETW event parsers.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <cstdint>
#include <cstring>
#include <string_view>

#include "exeray/event/types.hpp"
#include "exeray/etw/parser.hpp"

namespace exeray::etw {

/// @brief Extract common fields from EVENT_RECORD header.
/// @param record Pointer to the raw ETW event record.
/// @param out Output ParsedEvent to populate.
/// @param cat Event category to set.
inline void extract_common(const EVENT_RECORD* record, ParsedEvent& out, event::Category cat) {
    out.pid = record->EventHeader.ProcessId;
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = cat;
}

/// @brief Initialize payload with zero-filling and set category.
/// @tparam PayloadType Type of the payload struct.
/// @param result Output ParsedEvent to populate.
/// @param cat Event category to set.
/// @param payload Reference to the payload struct to zero-initialize.
template<typename PayloadType>
void init_payload(ParsedEvent& result, event::Category cat, PayloadType& payload) {
    result.payload.category = cat;
    std::memset(&payload, 0, sizeof(PayloadType));
}

/// @brief Extract wide string from event data.
/// @param data Pointer to start of string.
/// @param max_len Maximum bytes to read.
/// @return String view (empty if null or invalid).
inline std::wstring_view extract_wstring(const uint8_t* data, size_t max_len) {
    if (data == nullptr || max_len < 2) {
        return {};
    }

    // Find null terminator
    const auto* wdata = reinterpret_cast<const wchar_t*>(data);
    size_t max_chars = max_len / sizeof(wchar_t);
    size_t len = 0;
    while (len < max_chars && wdata[len] != L'\0') {
        ++len;
    }
    return {wdata, len};
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {

// Stub for non-Windows platforms
struct EVENT_RECORD;

inline void extract_common(const EVENT_RECORD* /*record*/, ParsedEvent& /*out*/, event::Category /*cat*/) {
    // No-op on non-Windows
}

template<typename PayloadType>
void init_payload(ParsedEvent& /*result*/, event::Category /*cat*/, PayloadType& /*payload*/) {
    // No-op on non-Windows
}

inline std::wstring_view extract_wstring(const uint8_t* /*data*/, size_t /*max_len*/) {
    return {};
}

}  // namespace exeray::etw

#endif  // _WIN32
