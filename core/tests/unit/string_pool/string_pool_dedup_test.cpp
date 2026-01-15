#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 6. Deduplication Correctness Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_SameContentDifferentCase_DifferentIds) {
    StringId id_lower = pool_.intern("hello");
    StringId id_upper = pool_.intern("Hello");
    StringId id_caps = pool_.intern("HELLO");

    EXPECT_NE(id_lower, INVALID_STRING);
    EXPECT_NE(id_upper, INVALID_STRING);
    EXPECT_NE(id_caps, INVALID_STRING);

    // Case-sensitive: all different
    EXPECT_NE(id_lower, id_upper);
    EXPECT_NE(id_lower, id_caps);
    EXPECT_NE(id_upper, id_caps);
}

TEST_F(StringPoolTest, Intern_TrailingSpace_DifferentFromWithout) {
    StringId id_no_space = pool_.intern("test");
    StringId id_trailing = pool_.intern("test ");
    StringId id_leading = pool_.intern(" test");

    EXPECT_NE(id_no_space, id_trailing);
    EXPECT_NE(id_no_space, id_leading);
    EXPECT_NE(id_trailing, id_leading);
}

TEST_F(StringPoolTest, Intern_BinaryContent_ByteExact) {
    // Binary content with null bytes - using explicit length
    const char binary[] = {'\x00', '\x01', '\x02', '\x03'};
    std::string_view sv(binary, 4);

    StringId id = pool_.intern(sv);
    EXPECT_NE(id, INVALID_STRING);

    std::string_view result = pool_.get(id);
    EXPECT_EQ(result.size(), 4U);
    EXPECT_EQ(result[0], '\x00');
    EXPECT_EQ(result[1], '\x01');
    EXPECT_EQ(result[2], '\x02');
    EXPECT_EQ(result[3], '\x03');
}

}  // namespace
}  // namespace exeray::event
