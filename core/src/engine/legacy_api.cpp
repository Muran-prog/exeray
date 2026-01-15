/// @file engine/legacy_api.cpp
/// @brief Legacy task API: submit, generation, timestamp_ns, flags, progress, idle, threads.

#include "exeray/engine.hpp"

#include <chrono>

namespace exeray {

void Engine::submit() {
    flags_.store(StatusFlags::PENDING, std::memory_order_release);
    pool_.submit([this] { process(); });
}

std::uint64_t Engine::generation() const {
    return generation_.load(std::memory_order_acquire);
}

std::uint64_t Engine::timestamp_ns() const {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

std::uint64_t Engine::flags() const {
    return flags_.load(std::memory_order_acquire);
}

float Engine::progress() const {
    return progress_.load(std::memory_order_relaxed);
}

bool Engine::idle() const {
    return flags_.load(std::memory_order_acquire) == StatusFlags::IDLE;
}

std::size_t Engine::threads() const {
    return pool_.size();
}

}  // namespace exeray
