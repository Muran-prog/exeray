#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

TEST_F(ArenaTest, Allocate_ExactCapacity_Succeeds) {
    constexpr std::size_t kCapacity = 1024;
    Arena arena{kCapacity};

    // Due to 64-byte alignment, we can allocate up to capacity
    // Note: First allocation may start at offset 0 (already aligned)
    char* ptr = arena.allocate<char>(kCapacity);

    // Should succeed since arena is 64-byte aligned from start
    ASSERT_NE(ptr, nullptr);
    EXPECT_GE(arena.used(), kCapacity);
    EXPECT_LE(arena.used(), arena.capacity());
}

TEST_F(ArenaTest, Allocate_ExceedsCapacity_ReturnsNullptr) {
    constexpr std::size_t kCapacity = 1024;
    Arena arena{kCapacity};

    std::size_t used_before = arena.used();

    // Try to allocate more than capacity
    char* ptr = arena.allocate<char>(2048);
    EXPECT_EQ(ptr, nullptr);

    // State should not have changed
    EXPECT_EQ(arena.used(), used_before);
}

TEST_F(ArenaTest, Allocate_CapacityExhaustion_GracefulFailure) {
    constexpr std::size_t kCapacity = 1000;
    Arena arena{kCapacity};

    int success_count = 0;
    while (true) {
        char* ptr = arena.allocate<char>(100);
        if (ptr == nullptr) {
            break;
        }
        ++success_count;
    }

    // Should have allocated some but not infinite
    EXPECT_GT(success_count, 0);
    EXPECT_LE(arena.used(), arena.capacity());
}

TEST_F(ArenaTest, Allocate_AfterExhaustion_StillNullptr) {
    constexpr std::size_t kCapacity = 512;
    Arena arena{kCapacity};

    // Exhaust the arena
    while (arena.allocate<CacheLine>() != nullptr) {
        // Keep allocating until exhausted
    }

    std::size_t used_after_exhaustion = arena.used();

    // Multiple attempts after exhaustion should all fail
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(arena.allocate<int>(), nullptr);
        EXPECT_EQ(arena.allocate<char>(), nullptr);
        EXPECT_EQ(arena.allocate<CacheLine>(), nullptr);
    }

    // No side effects - used should not change
    EXPECT_EQ(arena.used(), used_after_exhaustion);
}

}  // namespace arena_test
}  // namespace exeray
