#pragma once

/**
 * @file aliases.hpp
 * @brief Type aliases for Event Graph system.
 */

#include <cstdint>

namespace exeray::event {

/// Unique identifier for events in the graph.
using EventId = std::uint64_t;

/// Interned string identifier for zero-copy string storage.
using StringId = std::uint32_t;

/// High-resolution timestamp in nanoseconds since epoch.
using Timestamp = std::uint64_t;

/// Invalid event identifier sentinel.
constexpr EventId INVALID_EVENT = 0;

/// Invalid string identifier sentinel.
constexpr StringId INVALID_STRING = 0;

}  // namespace exeray::event
