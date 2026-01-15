/// @file engine/correlation.cpp
/// @brief Event correlation API: get_process_tree, get_event_chain.

#include "exeray/engine.hpp"

namespace exeray {

std::vector<event::EventView> Engine::get_process_tree(uint32_t pid) {
    std::vector<event::EventView> result;

    // Find the process's most recent ProcessCreate event
    event::EventId current_id = correlator_.find_thread_parent(pid);
    if (current_id == event::INVALID_EVENT) {
        return result;
    }

    // Walk up the parent chain, collecting process events
    constexpr std::size_t max_depth = 100;  // Prevent infinite loops
    std::size_t depth = 0;

    while (current_id != event::INVALID_EVENT && depth < max_depth) {
        if (!graph_.exists(current_id)) {
            break;
        }

        auto view = graph_.get(current_id);
        result.push_back(view);

        // Move to parent
        current_id = view.parent_id();
        ++depth;
    }

    return result;
}

std::vector<event::EventView> Engine::get_event_chain(uint32_t correlation_id) {
    std::vector<event::EventView> result;

    if (correlation_id == 0) {
        return result;
    }

    // Collect all events with matching correlation ID
    graph_.for_each_correlation(correlation_id, [&result](event::EventView view) {
        result.push_back(view);
    });

    return result;
}

}  // namespace exeray
