#include "exeray/event/graph.hpp"

#include <cassert>
#include <chrono>
#include <cstring>

namespace exeray::event {

EventGraph::EventGraph(Arena& arena, StringPool& strings, std::size_t capacity)
    : arena_(arena),
      strings_(strings),
      nodes_(arena.allocate<EventNode>(capacity)),
      capacity_(capacity) {
    // Initialize nodes memory to zero for debug consistency
    if (nodes_ != nullptr) {
        std::memset(nodes_, 0, sizeof(EventNode) * capacity);
    }
}

EventId EventGraph::push(Category cat, std::uint8_t op, Status status,
                         EventId parent, uint32_t correlation_id,
                         const EventPayload& payload) {
    // Reserve a slot atomically
    const auto index = count_.fetch_add(1, std::memory_order_acq_rel);

    // Check capacity
    if (index >= capacity_) {
        // Rollback count if we exceeded capacity
        count_.fetch_sub(1, std::memory_order_relaxed);
        return INVALID_EVENT;
    }

    // Generate unique ID atomically
    const auto id = next_id_.fetch_add(1, std::memory_order_relaxed);

    // Get current timestamp
    const auto now = std::chrono::steady_clock::now();
    const auto timestamp = static_cast<Timestamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch())
            .count());

    // Write event data to reserved slot
    EventNode& node = nodes_[index];
    node.id = id;
    node.parent_id = parent;
    node.timestamp = timestamp;
    node.status = status;
    node.operation = op;
    node.correlation_id = correlation_id;
    std::memset(node._pad, 0, sizeof(node._pad));

    // Copy payload - category must already match the expected category
    assert(payload.category == cat && "payload.category must match cat parameter");
    node.payload = payload;

    // Update indexes under lock
    {
        std::unique_lock lock(mutex_);
        if (parent != INVALID_EVENT) {
            parent_index_.emplace(parent, index);
        }
        if (correlation_id != 0) {
            correlation_index_.emplace(correlation_id, index);
        }
    }

    return id;
}

EventView EventGraph::get(EventId id) const {
    // EventId starts at 1, so index = id - 1
    const auto index = id - 1;
    return EventView(&nodes_[index]);
}

bool EventGraph::exists(EventId id) const noexcept {
    if (id == INVALID_EVENT) {
        return false;
    }
    const auto current_count = count_.load(std::memory_order_acquire);
    // ID starts at 1, so valid IDs are 1..current_count
    return id <= current_count;
}

std::size_t EventGraph::count() const noexcept {
    return count_.load(std::memory_order_acquire);
}

std::string_view EventGraph::resolve_string(StringId id) const {
    return strings_.get(id);
}

StringId EventGraph::intern_string(std::string_view str) {
    return strings_.intern(str);
}

}  // namespace exeray::event
