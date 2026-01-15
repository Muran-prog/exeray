#pragma once

/**
 * @file node.hpp
 * @brief Event Node structure and immutable view for the Event Graph system.
 *
 * Defines the cache-aligned EventNode structure (64 bytes) and the
 * EventView class for type-safe, immutable access to event data.
 */

#include <stdexcept>
#include <cstdint>
#include <type_traits>

#include "payload.hpp"
#include "types.hpp"

namespace exeray::event {

// ---------------------------------------------------------------------------
// EventNode Structure
// ---------------------------------------------------------------------------

/**
 * @brief Cache-aligned event node structure.
 *
 * Represents a single event in the event graph. The structure is carefully
 * sized to exactly 64 bytes (one cache line) for optimal memory access
 * patterns and minimal cache contention.
 *
 * Memory layout:
 *   - id:             8 bytes (EventId)
 *   - parent_id:      8 bytes (EventId, 0 = root event)
 *   - timestamp:      8 bytes (nanoseconds since epoch)
 *   - correlation_id: 4 bytes (groups related events)
 *   - status:         1 byte  (operation result)
 *   - operation:      1 byte  (category-specific operation code)
 *   - _pad:           2 bytes (explicit padding)
 *   - payload:        32 bytes (category-specific data)
 *   - Total:          64 bytes
 */
struct alignas(64) EventNode {
    EventId id;              ///< Unique event identifier
    EventId parent_id;       ///< Parent event ID (0 = root event)
    Timestamp timestamp;     ///< High-resolution timestamp (ns since epoch)
    uint32_t correlation_id; ///< Correlation ID for grouping related events
    Status status;           ///< Operation result status
    uint8_t operation;       ///< Category-specific operation code
    uint8_t _pad[2];         ///< Explicit padding for alignment
    EventPayload payload;    ///< Category-specific payload data (32 bytes)
};

// ---------------------------------------------------------------------------
// Static Assertions - EventNode
// ---------------------------------------------------------------------------

static_assert(sizeof(EventNode) == 64,
              "EventNode must be exactly 64 bytes (one cache line)");
static_assert(alignof(EventNode) == 64,
              "EventNode must be aligned to 64 bytes");
static_assert(std::is_trivially_copyable_v<EventNode>,
              "EventNode must be trivially copyable for zero-copy semantics");
static_assert(std::is_standard_layout_v<EventNode>,
              "EventNode must be standard layout for C interop");

// ---------------------------------------------------------------------------
// EventView Class
// ---------------------------------------------------------------------------

/**
 * @brief Immutable view into an EventNode.
 *
 * Provides type-safe, read-only access to event data. The view does not
 * own the underlying EventNode and is only valid while the node exists.
 *
 * Usage example:
 * @code
 * const EventNode* node = get_event_from_graph(event_id);
 * EventView view(node);
 * if (view.category() == Category::FileSystem) {
 *     const auto& file = view.as_file();
 *     // use file.path, file.size, etc.
 * }
 * @endcode
 */
class EventView {
public:
    /**
     * @brief Construct a view from an EventNode pointer.
     * @param node Pointer to the event node (must not be null).
     */
    explicit EventView(const EventNode* node)
        : node_(node) {
        if (node_ == nullptr) [[unlikely]] {
            throw std::logic_error("EventView requires non-null node");
        }
    }

    /// @name Core Accessors
    /// @{

    /// Get the unique event identifier.
    [[nodiscard]] EventId id() const noexcept { return node_->id; }

    /// Get the parent event ID (0 = root event).
    [[nodiscard]] EventId parent_id() const noexcept { return node_->parent_id; }

    /// Get the event timestamp (nanoseconds since epoch).
    [[nodiscard]] Timestamp timestamp() const noexcept { return node_->timestamp; }

    /// Get the event category from the payload.
    [[nodiscard]] Category category() const noexcept {
        return node_->payload.category;
    }

    /// Get the operation result status.
    [[nodiscard]] Status status() const noexcept { return node_->status; }

    /// Get the raw operation code.
    [[nodiscard]] uint8_t operation() const noexcept { return node_->operation; }

    /// Get the correlation ID for event grouping.
    [[nodiscard]] uint32_t correlation_id() const noexcept { return node_->correlation_id; }

    /// @}

    /// @name Typed Operation Accessors
    /// @{

    /// Get operation as FileOp (throws on invalid category).
    [[nodiscard]] FileOp file_op() const {
        if (category() != Category::FileSystem) [[unlikely]] {
            throw std::logic_error("Invalid category for file_op");
        }
        return static_cast<FileOp>(node_->operation);
    }

    /// Get operation as RegistryOp (throws on invalid category).
    [[nodiscard]] RegistryOp registry_op() const {
        if (category() != Category::Registry) [[unlikely]] {
            throw std::logic_error("Invalid category for registry_op");
        }
        return static_cast<RegistryOp>(node_->operation);
    }

    /// Get operation as NetworkOp (throws on invalid category).
    [[nodiscard]] NetworkOp network_op() const {
        if (category() != Category::Network) [[unlikely]] {
            throw std::logic_error("Invalid category for network_op");
        }
        return static_cast<NetworkOp>(node_->operation);
    }

    /// Get operation as ProcessOp (throws on invalid category).
    [[nodiscard]] ProcessOp process_op() const {
        if (category() != Category::Process) [[unlikely]] {
            throw std::logic_error("Invalid category for process_op");
        }
        return static_cast<ProcessOp>(node_->operation);
    }

    /// Get operation as SchedulerOp (throws on invalid category).
    [[nodiscard]] SchedulerOp scheduler_op() const {
        if (category() != Category::Scheduler) [[unlikely]] {
            throw std::logic_error("Invalid category for scheduler_op");
        }
        return static_cast<SchedulerOp>(node_->operation);
    }

    /// Get operation as InputOp (throws on invalid category).
    [[nodiscard]] InputOp input_op() const {
        if (category() != Category::Input) [[unlikely]] {
            throw std::logic_error("Invalid category for input_op");
        }
        return static_cast<InputOp>(node_->operation);
    }

    /// Get operation as ImageOp (throws on invalid category).
    [[nodiscard]] ImageOp image_op() const {
        if (category() != Category::Image) [[unlikely]] {
            throw std::logic_error("Invalid category for image_op");
        }
        return static_cast<ImageOp>(node_->operation);
    }

    /// Get operation as ThreadOp (throws on invalid category).
    [[nodiscard]] ThreadOp thread_op() const {
        if (category() != Category::Thread) [[unlikely]] {
            throw std::logic_error("Invalid category for thread_op");
        }
        return static_cast<ThreadOp>(node_->operation);
    }

    /// Get operation as MemoryOp (throws on invalid category).
    [[nodiscard]] MemoryOp memory_op() const {
        if (category() != Category::Memory) [[unlikely]] {
            throw std::logic_error("Invalid category for memory_op");
        }
        return static_cast<MemoryOp>(node_->operation);
    }

    /// @}

    /// @name Typed Payload Accessors
    /// @{

    /// Get file payload reference (throws on invalid category).
    [[nodiscard]] const FilePayload& as_file() const {
        if (category() != Category::FileSystem) [[unlikely]] {
            throw std::logic_error("Invalid category for as_file");
        }
        return node_->payload.file;
    }

    /// Get registry payload reference (throws on invalid category).
    [[nodiscard]] const RegistryPayload& as_registry() const {
        if (category() != Category::Registry) [[unlikely]] {
            throw std::logic_error("Invalid category for as_registry");
        }
        return node_->payload.registry;
    }

    /// Get network payload reference (throws on invalid category).
    [[nodiscard]] const NetworkPayload& as_network() const {
        if (category() != Category::Network) [[unlikely]] {
            throw std::logic_error("Invalid category for as_network");
        }
        return node_->payload.network;
    }

    /// Get process payload reference (throws on invalid category).
    [[nodiscard]] const ProcessPayload& as_process() const {
        if (category() != Category::Process) [[unlikely]] {
            throw std::logic_error("Invalid category for as_process");
        }
        return node_->payload.process;
    }

    /// Get scheduler payload reference (throws on invalid category).
    [[nodiscard]] const SchedulerPayload& as_scheduler() const {
        if (category() != Category::Scheduler) [[unlikely]] {
            throw std::logic_error("Invalid category for as_scheduler");
        }
        return node_->payload.scheduler;
    }

    /// Get input payload reference (throws on invalid category).
    [[nodiscard]] const InputPayload& as_input() const {
        if (category() != Category::Input) [[unlikely]] {
            throw std::logic_error("Invalid category for as_input");
        }
        return node_->payload.input;
    }

    /// Get image payload reference (throws on invalid category).
    [[nodiscard]] const ImagePayload& as_image() const {
        if (category() != Category::Image) [[unlikely]] {
            throw std::logic_error("Invalid category for as_image");
        }
        return node_->payload.image;
    }

    /// Get thread payload reference (throws on invalid category).
    [[nodiscard]] const ThreadPayload& as_thread() const {
        if (category() != Category::Thread) [[unlikely]] {
            throw std::logic_error("Invalid category for as_thread");
        }
        return node_->payload.thread;
    }

    /// Get memory payload reference (throws on invalid category).
    [[nodiscard]] const MemoryPayload& as_memory() const {
        if (category() != Category::Memory) [[unlikely]] {
            throw std::logic_error("Invalid category for as_memory");
        }
        return node_->payload.memory;
    }

    /// @}

    /// @name Utility
    /// @{

    /// Check if this event is a root event (no parent).
    [[nodiscard]] bool is_root() const noexcept {
        return node_->parent_id == INVALID_EVENT;
    }

    /// Get direct access to the underlying node (const only).
    [[nodiscard]] const EventNode* node() const noexcept { return node_; }

    /// @}

private:
    const EventNode* node_;  ///< Non-owning pointer to the event node
};

// ---------------------------------------------------------------------------
// Static Assertions - EventView
// ---------------------------------------------------------------------------

static_assert(sizeof(EventView) == sizeof(void*),
              "EventView should be pointer-sized");
static_assert(std::is_trivially_copyable_v<EventView>,
              "EventView must be trivially copyable");

}  // namespace exeray::event
