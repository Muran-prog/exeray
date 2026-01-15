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

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {

// Stub for non-Windows platforms
struct EVENT_RECORD;

inline void extract_common(const EVENT_RECORD* /*record*/, ParsedEvent& /*out*/, event::Category /*cat*/) {
    // No-op on non-Windows
}

}  // namespace exeray::etw

#endif  // _WIN32
