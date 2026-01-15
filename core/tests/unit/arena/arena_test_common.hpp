#pragma once

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <set>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"

namespace exeray {
namespace arena_test {

class ArenaTest : public ::testing::Test {
protected:
    static constexpr std::size_t kDefaultCapacity = 64 * 1024;  // 64KB
};

struct alignas(1) Tiny {
    char c;
};

struct alignas(8) Aligned8 {
    std::uint64_t value;
};

struct alignas(16) Aligned16 {
    char data[16];
};

struct alignas(32) Aligned32 {
    char data[32];
};

struct alignas(64) CacheLine {
    char data[64];
};

struct alignas(128) Aligned128 {
    char data[128];
};

struct Huge {
    char data[1024 * 1024];  // 1MB
};

}  // namespace arena_test
}  // namespace exeray
