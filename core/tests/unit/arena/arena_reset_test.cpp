#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

TEST_F(ArenaTest, Reset_AfterAllocations_ZeroesOffset) {
    Arena arena{kDefaultCapacity};

    // Allocate some objects
    for (int i = 0; i < 100; ++i) {
        ASSERT_NE(arena.allocate<int>(), nullptr);
    }

    EXPECT_GT(arena.used(), 0U);

    // Reset
    arena.reset();

    EXPECT_EQ(arena.used(), 0U);
}

TEST_F(ArenaTest, Reset_NewAllocationsStartFromBase) {
    Arena arena{kDefaultCapacity};

    // First allocation
    int* first = arena.allocate<int>();
    ASSERT_NE(first, nullptr);

    // More allocations
    for (int i = 0; i < 50; ++i) {
        arena.allocate<CacheLine>();
    }

    // Reset
    arena.reset();

    // New allocation should start from the same base address
    int* after_reset = arena.allocate<int>();
    ASSERT_NE(after_reset, nullptr);

    // Should be at the same position as first allocation
    EXPECT_EQ(first, after_reset);
}

}  // namespace arena_test
}  // namespace exeray
