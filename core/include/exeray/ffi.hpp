#pragma once

#include "exeray/engine.hpp"
#include <memory>

namespace exeray {

class Handle {
public:
    Handle(std::size_t arena_mb, std::size_t threads)
        : engine_(EngineConfig{arena_mb * 1024 * 1024, threads}) {}

    void submit() { engine_.submit(); }

    std::uint64_t generation() const { return engine_.generation(); }
    std::uint64_t timestamp_ns() const { return engine_.timestamp_ns(); }
    std::uint64_t flags() const { return engine_.flags(); }
    float progress() const { return engine_.progress(); }

    bool idle() const { return engine_.idle(); }
    std::size_t threads() const { return engine_.threads(); }

    // Event graph access
    event::EventGraph& graph() { return engine_.graph(); }
    const event::EventGraph& graph() const { return engine_.graph(); }

private:
    Engine engine_;
};

inline std::unique_ptr<Handle> create(std::size_t arena_mb, std::size_t threads) {
    return std::make_unique<Handle>(arena_mb, threads);
}

// Event accessor functions for FFI
inline std::size_t event_count(const Handle& h) {
    return h.graph().count();
}

inline std::uint64_t event_get_id(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    // IDs are 1-indexed, so we need id = index + 1
    return h.graph().get(static_cast<event::EventId>(index + 1)).id();
}

inline std::uint64_t event_get_parent(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return h.graph().get(static_cast<event::EventId>(index + 1)).parent_id();
}

inline std::uint64_t event_get_timestamp(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return h.graph().get(static_cast<event::EventId>(index + 1)).timestamp();
}

inline std::uint8_t event_get_category(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return static_cast<std::uint8_t>(
        h.graph().get(static_cast<event::EventId>(index + 1)).category());
}

inline std::uint8_t event_get_status(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return static_cast<std::uint8_t>(
        h.graph().get(static_cast<event::EventId>(index + 1)).status());
}

inline std::uint8_t event_get_operation(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return h.graph().get(static_cast<event::EventId>(index + 1)).operation();
}

}

