#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

TEST_F(ArenaTest, Allocate_ZeroCount_Behavior) {
    Arena arena{kDefaultCapacity};

    // Document the expected behavior for zero-count allocation
    // The implementation returns a valid pointer (current offset) for count=0
    int* ptr = arena.allocate<int>(0);

    // Based on implementation: size = sizeof(int) * 0 = 0
    // This should succeed and return a valid aligned pointer
    // (the pointer is valid but shouldn't be dereferenced for 0 elements)
    EXPECT_NE(ptr, nullptr);
}

TEST_F(ArenaTest, Allocate_HugeStruct_SingleObject) {
    constexpr std::size_t kHugeCapacity = 4 * 1024 * 1024;  // 4MB
    Arena arena{kHugeCapacity};

    // Allocate a 1MB struct
    Huge* ptr = arena.allocate<Huge>();
    ASSERT_NE(ptr, nullptr);

    // Verify it's writable
    ptr->data[0] = 'A';
    ptr->data[sizeof(Huge) - 1] = 'Z';

    EXPECT_EQ(ptr->data[0], 'A');
    EXPECT_EQ(ptr->data[sizeof(Huge) - 1], 'Z');
}

TEST_F(ArenaTest, Allocate_MinimalCapacity_Behavior) {
    // The arena can allocate a single byte even with small capacity
    // because the base is already 64-byte aligned and first allocation
    // starts at offset 0 (already aligned). The allocation succeeds
    // as long as sizeof(T) <= capacity.
    constexpr std::size_t kTinyCapacity = 32;
    Arena arena{kTinyCapacity};

    // Single char allocation succeeds - only needs 1 byte
    char* ptr = arena.allocate<char>();
    EXPECT_NE(ptr, nullptr);

    // But 64-byte aligned struct that's 64 bytes won't fit
    // because used() now > 0 and needs padding to next 64-byte boundary
    CacheLine* cl = arena.allocate<CacheLine>();
    EXPECT_EQ(cl, nullptr);
}

}  // namespace arena_test
}  // namespace exeray
