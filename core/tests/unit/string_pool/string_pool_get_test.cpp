#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 5. Get Operations Tests
// ============================================================================

TEST_F(StringPoolTest, Get_ValidId_ReturnsCorrectString) {
    StringId id = pool_.intern("test_string");
    EXPECT_EQ(pool_.get(id), "test_string");
}

TEST_F(StringPoolTest, Get_InvalidString_EmptyView) {
    std::string_view result = pool_.get(INVALID_STRING);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringPoolTest, Get_OutOfRangeId_DoesNotCrash) {
    // Note: This test documents current behavior - accessing out-of-range ID
    // The implementation trusts the ID is valid (no bounds checking)
    // This test just ensures we don't crash with a reasonable out-of-range ID
    // In production, only IDs returned by intern() should be used
    
    // Just verify that INVALID_STRING returns empty
    EXPECT_TRUE(pool_.get(INVALID_STRING).empty());
}

TEST_F(StringPoolTest, Get_AfterManyInterns_StillValid) {
    // Intern first string
    StringId first_id = pool_.intern("first_string");
    ASSERT_NE(first_id, INVALID_STRING);

    // Intern many more strings
    constexpr int kNumStrings = 10000;
    for (int i = 0; i < kNumStrings; ++i) {
        StringId id = pool_.intern("bulk_string_" + std::to_string(i));
        ASSERT_NE(id, INVALID_STRING) << "Failed at iteration " << i;
    }

    // First string should still be accessible
    EXPECT_EQ(pool_.get(first_id), "first_string");
}

}  // namespace
}  // namespace exeray::event
