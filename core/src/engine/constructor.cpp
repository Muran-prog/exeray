/// @file engine/constructor.cpp
/// @brief Engine constructor and destructor implementation.

#include "exeray/engine.hpp"
#include "exeray/logging.hpp"

namespace exeray {

Engine::Engine(EngineConfig config)
    : arena_(config.arena_size),
      strings_(arena_),
      graph_(arena_, strings_),
      correlator_(),
      pool_(config.num_threads),
      config_(std::move(config)) {
    // Initialize consumer context with graph, correlator, and target_pid
    consumer_ctx_.graph = &graph_;
    consumer_ctx_.target_pid = &target_pid_;
    consumer_ctx_.strings = &strings_;
    consumer_ctx_.correlator = &correlator_;
}

Engine::~Engine() {
    // Ensure cleanup on destruction
    if (monitoring_.load(std::memory_order_acquire)) {
        stop_monitoring();
    }
}

}  // namespace exeray
