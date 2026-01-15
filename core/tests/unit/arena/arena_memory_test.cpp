#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

TEST_F(ArenaTest, Allocate_WriteRead_DataIntegrity) {
    Arena arena{kDefaultCapacity};
    constexpr int kNumInts = 1000;

    std::vector<int*> pointers;
    pointers.reserve(kNumInts);

    // Allocate and write unique values
    for (int i = 0; i < kNumInts; ++i) {
        int* ptr = arena.allocate<int>();
        ASSERT_NE(ptr, nullptr);
        *ptr = i * 7 + 13;  // Unique pattern
        pointers.push_back(ptr);
    }

    // Read all values and verify
    for (int i = 0; i < kNumInts; ++i) {
        EXPECT_EQ(*pointers[i], i * 7 + 13)
            << "Data corruption at index " << i;
    }
}

TEST_F(ArenaTest, Allocate_PatternFill_NoCorruption) {
    Arena arena{kDefaultCapacity};

    // Allocate and fill with pattern
    constexpr std::size_t kBlockSize = 256;
    std::uint32_t* block1 = arena.allocate<std::uint32_t>(kBlockSize);
    ASSERT_NE(block1, nullptr);

    for (std::size_t i = 0; i < kBlockSize; ++i) {
        block1[i] = 0xDEADBEEF;
    }

    // Allocate more memory
    std::uint32_t* block2 = arena.allocate<std::uint32_t>(kBlockSize);
    ASSERT_NE(block2, nullptr);

    for (std::size_t i = 0; i < kBlockSize; ++i) {
        block2[i] = 0xCAFEBABE;
    }

    // Verify first block is not corrupted
    for (std::size_t i = 0; i < kBlockSize; ++i) {
        EXPECT_EQ(block1[i], 0xDEADBEEF)
            << "Corruption in block1 at index " << i;
    }

    // Verify second block
    for (std::size_t i = 0; i < kBlockSize; ++i) {
        EXPECT_EQ(block2[i], 0xCAFEBABE)
            << "Corruption in block2 at index " << i;
    }
}

}  // namespace arena_test
}  // namespace exeray
