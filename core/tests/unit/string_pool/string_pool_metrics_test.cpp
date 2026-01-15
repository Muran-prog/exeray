#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 8. Memory Metrics Tests
// ============================================================================

TEST_F(StringPoolTest, BytesUsed_AfterInterns_AccurateCount) {
    EXPECT_EQ(pool_.bytes_used(), 0U);

    // Intern strings of known lengths
    // Storage format: [len:u32][chars...]
    pool_.intern("abc");     // 4 + 3 = 7 bytes
    pool_.intern("hello");   // 4 + 5 = 9 bytes
    pool_.intern("");        // 4 + 0 = 4 bytes

    std::size_t expected = (4 + 3) + (4 + 5) + (4 + 0);
    EXPECT_EQ(pool_.bytes_used(), expected);
}

TEST_F(StringPoolTest, BytesUsed_Deduplication_NoDuplicateBytes) {
    pool_.intern("test");
    std::size_t after_first = pool_.bytes_used();
    EXPECT_EQ(after_first, 4U + 4U);  // 4 bytes len + 4 bytes "test"

    // Intern same string 1000 times
    for (int i = 0; i < 1000; ++i) {
        pool_.intern("test");
    }

    // bytes_used should not change (deduplication)
    EXPECT_EQ(pool_.bytes_used(), after_first);
}

TEST_F(StringPoolTest, Count_Accurate_AfterOperations) {
    constexpr int kUniqueStrings = 50;
    constexpr int kDuplicatesEach = 10;

    EXPECT_EQ(pool_.count(), 0U);

    // Intern N unique strings, M duplicates each
    for (int i = 0; i < kUniqueStrings; ++i) {
        std::string str = "unique_" + std::to_string(i);
        for (int j = 0; j < kDuplicatesEach; ++j) {
            pool_.intern(str);
        }
    }

    // Count should reflect only unique strings
    EXPECT_EQ(pool_.count(), kUniqueStrings);
}

}  // namespace
}  // namespace exeray::event
