/// @file schema_cache.hpp
/// @brief TDH schema cache for ETW event parsing.

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
#include <mutex>
#include <unordered_map>
#include <vector>

namespace exeray::etw {

/// @brief Cache for event schemas to avoid repeated TdhGetEventInformation calls.
class TdhSchemaCache {
public:
    /// @brief Get or fetch schema for an event.
    PTRACE_EVENT_INFO get_schema(const EVENT_RECORD* record);

    /// @brief Clear all cached schemas.
    void clear();

    /// @brief Get number of cached schemas.
    size_t size() const;

private:
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

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {

class TdhSchemaCache {
public:
    void clear() {}
    size_t size() const { return 0; }
};

}  // namespace exeray::etw

#endif  // _WIN32
