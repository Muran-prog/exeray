#pragma once

#include "exeray/arena.hpp"
#include "exeray/thread_pool.hpp"
#include "exeray/types.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>

namespace exeray {

struct EngineConfig {
    std::size_t arena_size;
    std::size_t num_threads;
};

class Engine {
public:
    explicit Engine(EngineConfig config)
        : arena_(config.arena_size),
          pool_(config.num_threads) {}

    void submit() {
        flags_.store(StatusFlags::PENDING, std::memory_order_release);
        pool_.submit([this] { process(); });
    }

    std::uint64_t generation() const {
        return generation_.load(std::memory_order_acquire);
    }

    std::uint64_t timestamp_ns() const {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    }

    std::uint64_t flags() const {
        return flags_.load(std::memory_order_acquire);
    }

    float progress() const {
        return progress_.load(std::memory_order_relaxed);
    }

    bool idle() const {
        return flags_.load(std::memory_order_acquire) == StatusFlags::IDLE;
    }

    std::size_t threads() const {
        return pool_.size();
    }

private:
    void process() {
        for (int i = 0; i <= 100; ++i) {
            progress_.store(static_cast<float>(i) / 100.0f, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        generation_.fetch_add(1, std::memory_order_release);
        flags_.store(StatusFlags::COMPLETE | StatusFlags::READY, std::memory_order_release);
    }

    Arena arena_;
    ThreadPool pool_;
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<std::uint64_t> flags_{StatusFlags::IDLE};
    std::atomic<float> progress_{0.0f};
};

}
