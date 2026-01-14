#pragma once

/// @file correlator.hpp
/// @brief Event Correlation Engine for linking events into parent-child chains.
///
/// Provides O(1) lookups for parent events and correlation IDs to enable
/// attack analysis through process trees and event chains.

#include <atomic>
#include <cstdint>
#include <shared_mutex>
#include <unordered_map>

#include "node.hpp"
#include "types.hpp"

namespace exeray::event {

/// @brief Thread-safe event correlator for building event chains.
///
/// Maintains mappings from process IDs to their most recent events,
/// enabling O(1) parent lookups during ETW event processing.
///
/// Thread-safety model:
/// - All methods are thread-safe (shared_mutex for read/write)
/// - Designed for concurrent ETW callbacks from multiple providers
/// - Atomic counter for correlation ID generation
class Correlator {
public:
    Correlator() = default;
    ~Correlator() = default;

    // Non-copyable, non-movable (owns mutex)
    Correlator(const Correlator&) = delete;
    Correlator& operator=(const Correlator&) = delete;
    Correlator(Correlator&&) = delete;
    Correlator& operator=(Correlator&&) = delete;

    // -------------------------------------------------------------------------
    // Parent Lookups
    // -------------------------------------------------------------------------

    /// @brief Find parent event for a child process.
    /// @param parent_pid Parent process ID from ProcessPayload.
    /// @return EventId of the parent's ProcessCreate event, or INVALID_EVENT.
    [[nodiscard]] EventId find_process_parent(uint32_t parent_pid);

    /// @brief Find parent event for a thread (owning process).
    /// @param pid Process ID that owns the thread.
    /// @return EventId of the process's most recent event, or INVALID_EVENT.
    [[nodiscard]] EventId find_thread_parent(uint32_t pid);

    /// @brief Find parent event for memory/image operations.
    /// @param pid Process ID associated with the operation.
    /// @return EventId of the process's most recent event, or INVALID_EVENT.
    [[nodiscard]] EventId find_operation_parent(uint32_t pid);

    // -------------------------------------------------------------------------
    // Correlation IDs
    // -------------------------------------------------------------------------

    /// @brief Get or create a correlation ID for a process tree.
    ///
    /// If the PID already has a correlation ID, returns it.
    /// Otherwise, generates a new one and associates it with the PID.
    /// Child processes inherit their parent's correlation ID.
    ///
    /// @param pid Process ID to correlate.
    /// @param parent_pid Optional parent PID to inherit correlation from.
    /// @return Correlation ID for the process tree.
    [[nodiscard]] uint32_t get_correlation_id(uint32_t pid, uint32_t parent_pid = 0);

    // -------------------------------------------------------------------------
    // Event Registration
    // -------------------------------------------------------------------------

    /// @brief Register an event for future parent lookups.
    ///
    /// Must be called after pushing to EventGraph to enable correlation.
    /// For ProcessCreate events, updates the PID -> EventId mapping.
    ///
    /// @param node The event node that was just pushed to the graph.
    void register_event(const EventNode& node);

    /// @brief Register a process creation event explicitly.
    /// @param pid Process ID.
    /// @param event_id EventId of the ProcessCreate event.
    void register_process(uint32_t pid, EventId event_id);

private:
    mutable std::shared_mutex mutex_;

    /// Maps PID -> EventId of most recent ProcessCreate event
    std::unordered_map<uint32_t, EventId> process_events_;

    /// Maps PID -> correlation_id for process tree grouping
    std::unordered_map<uint32_t, uint32_t> pid_correlations_;

    /// Atomic counter for generating new correlation IDs
    std::atomic<uint32_t> next_correlation_{1};
};

}  // namespace exeray::event
