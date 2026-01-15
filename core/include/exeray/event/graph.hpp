#pragma once

/**
 * @file graph.hpp
 * @brief Thread-safe Event Graph container for event storage and traversal.
 *
 * Provides a contiguous, arena-allocated storage for events with support for
 * concurrent push operations and thread-safe iteration.
 */

#include <atomic>
#include <cstddef>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <string_view>

#include "../arena.hpp"
#include "node.hpp"
#include "string_pool.hpp"

namespace exeray::event {

/**
 * @brief Thread-safe container for event nodes.
 *
 * Events are stored in a contiguous, arena-allocated array for cache-friendly
 * access. Supports concurrent push operations using atomic counters and
 * provides thread-safe iteration using a shared mutex.
 *
 * Thread-safety model:
 * - push(): Lock-free using atomic operations
 * - get()/exists(): Lock-free reads
 * - for_each*(): Acquires shared lock for consistent iteration
 *
 * Usage example:
 * @code
 * Arena arena(1024 * 1024);
 * StringPool strings(arena);
 * EventGraph graph(arena, strings, 65536);
 *
 * EventPayload payload{};
 * payload.category = Category::FileSystem;
 * payload.file.path = strings.intern("C:\\test.txt");
 *
 * EventId id = graph.push(Category::FileSystem,
 *                         static_cast<uint8_t>(FileOp::Create),
 *                         Status::Success, INVALID_EVENT, payload);
 *
 * EventView view = graph.get(id);
 * @endcode
 */
class EventGraph {
public:
    /**
     * @brief Construct an event graph with specified capacity.
     * @param arena Arena for memory allocation.
     * @param strings String pool for string resolution.
     * @param capacity Maximum number of events (default: 65536).
     */
    explicit EventGraph(Arena& arena, StringPool& strings,
                        std::size_t capacity = 65536);

    // Non-copyable, non-movable
    EventGraph(const EventGraph&) = delete;
    EventGraph& operator=(const EventGraph&) = delete;
    EventGraph(EventGraph&&) = delete;
    EventGraph& operator=(EventGraph&&) = delete;

    // -------------------------------------------------------------------------
    // Event Operations
    // -------------------------------------------------------------------------

    /**
     * @brief Add an event to the graph (thread-safe).
     * @param cat Event category.
     * @param op Category-specific operation code.
     * @param status Operation result status.
     * @param parent Parent event ID (INVALID_EVENT for root events).
     * @param correlation_id Correlation ID for grouping related events.
     * @param payload Category-specific payload data.
     * @return Unique event ID, or INVALID_EVENT if capacity exceeded.
     */
    EventId push(Category cat, std::uint8_t op, Status status,
                 EventId parent, uint32_t correlation_id,
                 const EventPayload& payload);

    /**
     * @brief Get event view by ID (thread-safe read).
     * @param id Event identifier.
     * @return EventView for the event. Undefined behavior if ID is invalid.
     * @pre exists(id) must be true.
     */
    [[nodiscard]] EventView get(EventId id) const;

    /**
     * @brief Check if an event exists.
     * @param id Event identifier to check.
     * @return true if event exists, false otherwise.
     */
    [[nodiscard]] bool exists(EventId id) const noexcept;

    /**
     * @brief Get current event count.
     * @return Number of events in the graph.
     */
    [[nodiscard]] std::size_t count() const noexcept;

    // -------------------------------------------------------------------------
    // Iteration
    // -------------------------------------------------------------------------

    /**
     * @brief Iterate over all events.
     * @tparam F Callable taking EventView.
     * @param fn Function to call for each event.
     */
    template <typename F>
    void for_each(F&& fn) const;

    /**
     * @brief Iterate over events of a specific category.
     * @tparam F Callable taking EventView.
     * @param cat Category to filter by.
     * @param fn Function to call for each matching event.
     */
    template <typename F>
    void for_each_category(Category cat, F&& fn) const;

    /**
     * @brief Iterate over direct children of a parent event.
     * @tparam F Callable taking EventView.
     * @param parent Parent event ID.
     * @param fn Function to call for each child event.
     */
    template <typename F>
    void for_each_child(EventId parent, F&& fn) const;

    /**
     * @brief Iterate over events with a specific correlation ID.
     * @tparam F Callable taking EventView.
     * @param correlation_id Correlation ID to filter by.
     * @param fn Function to call for each matching event.
     */
    template <typename F>
    void for_each_correlation(uint32_t correlation_id, F&& fn) const;

    // -------------------------------------------------------------------------
    // String Convenience Methods
    // -------------------------------------------------------------------------

    /**
     * @brief Resolve a StringId to its string value.
     * @param id String identifier.
     * @return String view, empty if invalid.
     */
    [[nodiscard]] std::string_view resolve_string(StringId id) const;

    /**
     * @brief Intern a string in the string pool.
     * @param str String to intern.
     * @return String identifier.
     */
    StringId intern_string(std::string_view str);

private:
    Arena& arena_;
    StringPool& strings_;
    EventNode* nodes_;
    std::size_t capacity_;
    std::atomic<std::size_t> count_{0};
    std::atomic<EventId> next_id_{1};
    mutable std::shared_mutex mutex_;

    // Indexes for O(1) lookup
    std::unordered_multimap<EventId, std::size_t> parent_index_;
    std::unordered_multimap<uint32_t, std::size_t> correlation_index_;
};

// =============================================================================
// Template Implementation
// =============================================================================

template <typename F>
void EventGraph::for_each(F&& fn) const {
    std::shared_lock lock(mutex_);
    const auto current_count = count_.load(std::memory_order_acquire);
    for (std::size_t i = 0; i < current_count; ++i) {
        fn(EventView(&nodes_[i]));
    }
}

template <typename F>
void EventGraph::for_each_category(Category cat, F&& fn) const {
    std::shared_lock lock(mutex_);
    const auto current_count = count_.load(std::memory_order_acquire);
    for (std::size_t i = 0; i < current_count; ++i) {
        if (nodes_[i].payload.category == cat) {
            fn(EventView(&nodes_[i]));
        }
    }
}

template <typename F>
void EventGraph::for_each_child(EventId parent, F&& fn) const {
    std::shared_lock lock(mutex_);
    auto [first, last] = parent_index_.equal_range(parent);
    for (auto it = first; it != last; ++it) {
        fn(EventView(&nodes_[it->second]));
    }
}

template <typename F>
void EventGraph::for_each_correlation(uint32_t correlation_id, F&& fn) const {
    std::shared_lock lock(mutex_);
    auto [first, last] = correlation_index_.equal_range(correlation_id);
    for (auto it = first; it != last; ++it) {
        fn(EventView(&nodes_[it->second]));
    }
}

}  // namespace exeray::event
