#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 2. Empty and Special Strings Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_EmptyString_ValidId) {
    StringId id = pool_.intern("");

    EXPECT_NE(id, INVALID_STRING);
    
    std::string_view result = pool_.get(id);
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(result, "");
}

TEST_F(StringPoolTest, Intern_Whitespace_PreservedExactly) {
    const std::string_view whitespace = "  \t\n  ";
    StringId id = pool_.intern(whitespace);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), whitespace);
    EXPECT_EQ(pool_.get(id).size(), whitespace.size());
}

TEST_F(StringPoolTest, Intern_NullCharInMiddle_TruncatedAtNullByStringView) {
    // string_view created from "hello\0world" will have length 5 (stops at null)
    // This documents the expected behavior based on how string_view is constructed
    const char* cstr = "hello\0world";
    std::string_view sv(cstr);  // Length = 5 (truncated at null)
    
    StringId id = pool_.intern(sv);
    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), "hello");
    EXPECT_EQ(pool_.get(id).size(), 5U);

    // To include null in middle, must use explicit length
    std::string_view sv_full(cstr, 11);  // "hello\0world" = 11 chars
    StringId id_full = pool_.intern(sv_full);
    EXPECT_NE(id_full, INVALID_STRING);
    EXPECT_EQ(pool_.get(id_full).size(), 11U);
}

}  // namespace
}  // namespace exeray::event
