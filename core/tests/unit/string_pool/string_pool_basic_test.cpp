#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 1. Basic Interning Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_SimpleString_ReturnsValidId) {
    StringId id = pool_.intern("hello");

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), "hello");
}

TEST_F(StringPoolTest, Intern_SameStringTwice_ReturnsSameId) {
    StringId id1 = pool_.intern("test");
    StringId id2 = pool_.intern("test");

    EXPECT_NE(id1, INVALID_STRING);
    EXPECT_EQ(id1, id2) << "Deduplication failed: same string returned different IDs";
}

TEST_F(StringPoolTest, Intern_DifferentStrings_DifferentIds) {
    StringId id1 = pool_.intern("foo");
    StringId id2 = pool_.intern("bar");

    EXPECT_NE(id1, INVALID_STRING);
    EXPECT_NE(id2, INVALID_STRING);
    EXPECT_NE(id1, id2);
}

TEST_F(StringPoolTest, Intern_1000UniqueStrings_AllUnique) {
    constexpr int kNumStrings = 1000;
    std::set<StringId> unique_ids;

    for (int i = 0; i < kNumStrings; ++i) {
        StringId id = pool_.intern("string_" + std::to_string(i));
        ASSERT_NE(id, INVALID_STRING) << "Failed at string " << i;
        auto [_, inserted] = unique_ids.insert(id);
        EXPECT_TRUE(inserted) << "Duplicate ID for string_" << i;
    }

    EXPECT_EQ(unique_ids.size(), kNumStrings);
    EXPECT_EQ(pool_.count(), kNumStrings);
}

}  // namespace
}  // namespace exeray::event
