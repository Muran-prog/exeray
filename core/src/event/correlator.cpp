/// @file correlator.cpp
/// @brief Event Correlation Engine implementation.

#include "exeray/event/correlator.hpp"
#include "exeray/event/payload.hpp"

#include <mutex>

namespace exeray::event {

// =============================================================================
// Parent Lookups
// =============================================================================

EventId Correlator::find_process_parent(uint32_t parent_pid) {
    if (parent_pid == 0) {
        return INVALID_EVENT;
    }

    std::shared_lock lock(mutex_);
    auto it = process_events_.find(parent_pid);
    if (it != process_events_.end()) {
        return it->second;
    }
    return INVALID_EVENT;
}

EventId Correlator::find_thread_parent(uint32_t pid) {
    if (pid == 0) {
        return INVALID_EVENT;
    }

    std::shared_lock lock(mutex_);
    auto it = process_events_.find(pid);
    if (it != process_events_.end()) {
        return it->second;
    }
    return INVALID_EVENT;
}

EventId Correlator::find_operation_parent(uint32_t pid) {
    // Same logic as thread parent - find owning process
    return find_thread_parent(pid);
}

// =============================================================================
// Correlation IDs
// =============================================================================

uint32_t Correlator::get_correlation_id(uint32_t pid, uint32_t parent_pid) {
    if (pid == 0) {
        return 0;
    }

    // First check if PID already has a correlation ID (read lock)
    {
        std::shared_lock lock(mutex_);
        auto it = pid_correlations_.find(pid);
        if (it != pid_correlations_.end()) {
            return it->second;
        }
    }

    // Need to create a new correlation ID (write lock)
    std::unique_lock lock(mutex_);

    // Double-check after acquiring write lock
    auto it = pid_correlations_.find(pid);
    if (it != pid_correlations_.end()) {
        return it->second;
    }

    // Try to inherit from parent process
    uint32_t corr_id = 0;
    if (parent_pid != 0) {
        auto parent_it = pid_correlations_.find(parent_pid);
        if (parent_it != pid_correlations_.end()) {
            corr_id = parent_it->second;
        }
    }

    // Generate new correlation ID if not inherited
    if (corr_id == 0) {
        corr_id = next_correlation_.fetch_add(1, std::memory_order_relaxed);
    }

    pid_correlations_[pid] = corr_id;
    return corr_id;
}

// =============================================================================
// Event Registration
// =============================================================================

void Correlator::register_event(const EventNode& node) {
    // Only register ProcessCreate events for parent lookups
    if (node.payload.category != Category::Process) {
        return;
    }

    // Check if it's a ProcessCreate operation (op code 0 or 1 typically)
    // ProcessOp::Create = 0
    if (node.operation != static_cast<uint8_t>(ProcessOp::Create)) {
        return;
    }

    const auto& proc = node.payload.process;
    register_process(proc.pid, node.id);
}

void Correlator::register_process(uint32_t pid, EventId event_id) {
    if (pid == 0 || event_id == INVALID_EVENT) {
        return;
    }

    std::unique_lock lock(mutex_);
    process_events_[pid] = event_id;
}

}  // namespace exeray::event
