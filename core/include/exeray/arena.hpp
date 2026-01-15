#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>

namespace exeray {

/// @brief A simple bump allocator for fast, contiguous memory allocation.
/// 
/// @note Thread-safe. Uses atomic compare-exchange for lock-free allocation.
///       For bulk allocations, consider reserving slots atomically before 
///       writing (see EventGraph::push).
class Arena {
public:
    explicit Arena(std::size_t capacity)
        : base_(static_cast<std::uint8_t*>(
              ::operator new(capacity, std::align_val_t{64}))),
          capacity_(capacity) {}

    ~Arena() {
        ::operator delete(base_, std::align_val_t{64});
    }

    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&&) = delete;
    Arena& operator=(Arena&&) = delete;

    template<typename T>
    T* allocate(std::size_t count = 1) {
        // Overflow check: ensure sizeof(T) * count won't overflow
        if (count > (std::numeric_limits<std::size_t>::max)() / sizeof(T)) {
            return nullptr;
        }

        constexpr auto align = alignof(T) < 64 ? 64 : alignof(T);
        const std::size_t size = sizeof(T) * count;

        std::size_t current = offset_.load(std::memory_order_relaxed);
        std::size_t aligned_offset;
        std::size_t new_offset;

        do {
            aligned_offset = (current + align - 1) & ~(align - 1);
            new_offset = aligned_offset + size;

            if (new_offset > capacity_) {
                return nullptr;
            }
        } while (!offset_.compare_exchange_weak(current, new_offset,
                                                 std::memory_order_release,
                                                 std::memory_order_relaxed));

        return reinterpret_cast<T*>(base_ + aligned_offset);
    }

    void reset() { offset_.store(0, std::memory_order_release); }
    std::size_t used() const { return offset_.load(std::memory_order_acquire); }
    std::size_t capacity() const { return capacity_; }
    const std::uint8_t* base() const { return base_; }

private:
    std::uint8_t* base_;
    std::atomic<std::size_t> offset_ = 0;
    std::size_t capacity_;
};

}
