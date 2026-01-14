#pragma once

/// @file tdh_parser.hpp
/// @brief TDH (Trace Data Helper) fallback parser for unknown ETW event versions.

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "exeray/event/types.hpp"
#include "exeray/etw/parser.hpp"

namespace exeray::event {
class StringPool;  // Forward declaration
}  // namespace exeray::event

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
///
/// Contains all properties extracted from the event using TDH API.
/// Property names are wide strings as provided by the event manifest.
struct TdhParsedEvent {
    std::unordered_map<std::wstring, TdhPropertyValue> properties;
    uint16_t event_id{0};
    uint8_t event_version{0};
};

/// @brief Cache for event schemas to avoid repeated TdhGetEventInformation calls.
///
/// Event schemas (TRACE_EVENT_INFO) are cached by provider GUID + event ID + version.
/// This provides significant performance improvement when processing many events
/// of the same type. Thread-safe via internal mutex.
class TdhSchemaCache {
public:
    /// @brief Get or fetch schema for an event.
    /// @param record The event record to get schema for.
    /// @return Pointer to cached TRACE_EVENT_INFO, or nullptr on failure.
    PTRACE_EVENT_INFO get_schema(const EVENT_RECORD* record);

    /// @brief Clear all cached schemas.
    void clear();

    /// @brief Get number of cached schemas.
    size_t size() const;

private:
    /// @brief Key for schema cache lookup.
    struct EventKey {
        GUID provider_guid;
        uint16_t event_id;
        uint8_t event_version;

        bool operator==(const EventKey& other) const;
    };

    struct EventKeyHash {
        size_t operator()(const EventKey& key) const;
    };

    mutable std::mutex mutex_;
    std::unordered_map<EventKey, std::vector<BYTE>, EventKeyHash> cache_;
};

/// @brief Parse an event using TDH API.
/// @param record The event record to parse.
/// @param cache Optional schema cache for performance (can be nullptr).
/// @return Parsed event with properties, or nullopt on failure.
///
/// This is the slow path (~10x slower than hardcoded offsets). Use only when
/// fast parsing fails due to unknown event version or structure changes.
std::optional<TdhParsedEvent> parse_with_tdh(
    const EVENT_RECORD* record,
    TdhSchemaCache* cache = nullptr
);

/// @brief Convert TDH-parsed event to ParsedEvent for Process category.
/// @param tdh_event The TDH-parsed event.
/// @param record Original event record for common fields.
/// @param strings String pool for interning strings.
/// @return ParsedEvent with process payload.
ParsedEvent convert_tdh_to_process(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for File category.
ParsedEvent convert_tdh_to_file(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for Registry category.
ParsedEvent convert_tdh_to_registry(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for Network category.
ParsedEvent convert_tdh_to_network(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for Image category.
ParsedEvent convert_tdh_to_image(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for Thread category.
ParsedEvent convert_tdh_to_thread(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for Memory category.
ParsedEvent convert_tdh_to_memory(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for Script category.
ParsedEvent convert_tdh_to_script(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for AMSI category.
ParsedEvent convert_tdh_to_amsi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for DNS category.
ParsedEvent convert_tdh_to_dns(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for Security category.
ParsedEvent convert_tdh_to_security(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for WMI category.
ParsedEvent convert_tdh_to_wmi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Convert TDH-parsed event to ParsedEvent for CLR category.
ParsedEvent convert_tdh_to_clr(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

/// @brief Global schema cache instance.
/// @return Reference to the global TdhSchemaCache.
TdhSchemaCache& global_tdh_cache();

}  // namespace exeray::etw

#else  // !_WIN32

// Stub declarations for non-Windows platforms
#include <optional>
#include "exeray/etw/parser.hpp"

namespace exeray::event {
class StringPool;
}

namespace exeray::etw {

struct TdhParsedEvent {};

class TdhSchemaCache {
public:
    void clear() {}
    size_t size() const { return 0; }
};

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
