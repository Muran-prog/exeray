#pragma once

#include <cstddef>
#include <cstdint>
#include <new>

namespace exeray {

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
        constexpr auto align = alignof(T) < 64 ? 64 : alignof(T);
        offset_ = (offset_ + align - 1) & ~(align - 1);

        if (offset_ + sizeof(T) * count > capacity_) {
            return nullptr;
        }

        auto* ptr = reinterpret_cast<T*>(base_ + offset_);
        offset_ += sizeof(T) * count;
        return ptr;
    }

    void reset() { offset_ = 0; }
    std::size_t used() const { return offset_; }
    std::size_t capacity() const { return capacity_; }
    const std::uint8_t* base() const { return base_; }

private:
    std::uint8_t* base_;
    std::size_t offset_ = 0;
    std::size_t capacity_;
};

}
