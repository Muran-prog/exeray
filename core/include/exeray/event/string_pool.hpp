#pragma once

/**
 * @file string_pool.hpp
 * @brief Thread-safe string interning pool with Arena-backed storage.
 *
 * Provides efficient string deduplication by storing unique strings in a
 * contiguous memory arena and returning stable StringId handles.
 */

#include <cstddef>
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "../arena.hpp"
#include "types.hpp"

namespace exeray::event {

/**
 * @brief Thread-safe string interning pool.
 *
 * Stores unique strings in Arena memory and provides O(1) average lookup.
 * Strings are stored with length prefix: [len:u32][chars...]
 *
 * StringId is the offset + 1 from arena base (so INVALID_STRING = 0 is never returned).
 *
 * Thread-safety: std::shared_mutex (multiple readers, exclusive writer).
 */
class StringPool {
public:
    explicit StringPool(Arena& arena, std::size_t initial_capacity = 4096);

    /// Intern string, return existing ID if present, or allocate new.
    StringId intern(std::string_view str);

    /// Intern wide string by converting to UTF-8.
    /// @param wstr Wide string view (e.g., from ETW event data).
    /// @return StringId for the interned UTF-8 string.
    StringId intern_wide(std::wstring_view wstr);

    /// Get string by ID. Returns empty view for INVALID_STRING.
    [[nodiscard]] std::string_view get(StringId id) const noexcept;

    /// Number of unique strings interned.
    [[nodiscard]] std::size_t count() const noexcept;

    /// Bytes used for string storage (length prefixes + data).
    [[nodiscard]] std::size_t bytes_used() const noexcept;

    // Non-copyable, non-movable
    StringPool(const StringPool&) = delete;
    StringPool& operator=(const StringPool&) = delete;
    StringPool(StringPool&&) = delete;
    StringPool& operator=(StringPool&&) = delete;

private:
    Arena& arena_;
    std::unordered_map<std::string_view, StringId> strings_;
    mutable std::shared_mutex mutex_;
    std::size_t bytes_used_ = 0;
};

}  // namespace exeray::event
