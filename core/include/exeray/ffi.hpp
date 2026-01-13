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

private:
    Engine engine_;
};

inline std::unique_ptr<Handle> create(std::size_t arena_mb, std::size_t threads) {
    return std::make_unique<Handle>(arena_mb, threads);
}

}
