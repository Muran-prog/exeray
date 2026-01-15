#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

TEST_F(ArenaTest, Allocate_CountOverflow_ReturnsNullptr) {
    Arena arena{kDefaultCapacity};

    // sizeof(int) * SIZE_MAX will overflow
    int* ptr = arena.allocate<int>(std::numeric_limits<std::size_t>::max());
    EXPECT_EQ(ptr, nullptr);

    // Arena should still be usable
    int* valid_ptr = arena.allocate<int>();
    EXPECT_NE(valid_ptr, nullptr);
}

TEST_F(ArenaTest, Allocate_SizeOverflow_ReturnsNullptr) {
    Arena arena{kDefaultCapacity};

    // SIZE_MAX / 2 + 1 for a 2-byte type will overflow when multiplied
    std::size_t dangerous_count =
        std::numeric_limits<std::size_t>::max() / sizeof(std::uint16_t) + 1;
    std::uint16_t* ptr = arena.allocate<std::uint16_t>(dangerous_count);
    EXPECT_EQ(ptr, nullptr);
}

TEST_F(ArenaTest, Allocate_BoundaryCount_HandlesCorrectly) {
    // Very large arena for this test
    constexpr std::size_t kHugeCapacity = 16 * 1024 * 1024;  // 16MB
    Arena arena{kHugeCapacity};

    // Boundary case: exactly max / sizeof(T) - should not overflow
    std::size_t max_count =
        std::numeric_limits<std::size_t>::max() / sizeof(int);
    int* ptr = arena.allocate<int>(max_count);

    // Should return nullptr because capacity is too small, not because of
    // overflow
    EXPECT_EQ(ptr, nullptr);

    // But smaller allocations should work
    int* valid = arena.allocate<int>(1000);
    EXPECT_NE(valid, nullptr);
}

}  // namespace arena_test
}  // namespace exeray
