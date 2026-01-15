/// @file parser.hpp
/// @brief TDH parsing functions.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <optional>

#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/tdh/schema_cache.hpp"

namespace exeray::etw {

/// @brief Parse an event using TDH API.
std::optional<TdhParsedEvent> parse_with_tdh(
    const EVENT_RECORD* record,
    TdhSchemaCache* cache = nullptr
);

/// @brief Global schema cache instance.
TdhSchemaCache& global_tdh_cache();

}  // namespace exeray::etw

#else  // !_WIN32

#include <optional>
#include "exeray/etw/tdh/schema_cache.hpp"

namespace exeray::etw {

struct TdhParsedEvent {};

inline std::optional<TdhParsedEvent> parse_with_tdh(
    const void* /*record*/,
    TdhSchemaCache* /*cache*/ = nullptr
) {
    return std::nullopt;
}

inline TdhSchemaCache& global_tdh_cache() {
    static TdhSchemaCache cache;
    return cache;
}

}  // namespace exeray::etw

#endif  // _WIN32
