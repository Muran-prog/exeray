#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 3. Unicode Stress Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_Cyrillic_CorrectlyStored) {
    const std::string_view cyrillic = "Привет мир";  // UTF-8 encoded
    StringId id = pool_.intern(cyrillic);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), cyrillic);
}

TEST_F(StringPoolTest, Intern_Chinese_CorrectlyStored) {
    const std::string_view chinese = "你好世界";  // UTF-8 encoded
    StringId id = pool_.intern(chinese);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), chinese);
}

TEST_F(StringPoolTest, Intern_Emoji_4ByteUtf8) {
    const std::string_view emoji = "🔥💀🎉";  // Each emoji is 4 UTF-8 bytes
    StringId id = pool_.intern(emoji);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), emoji);
    // 3 emoji × 4 bytes = 12 bytes
    EXPECT_EQ(pool_.get(id).size(), 12U);
}

TEST_F(StringPoolTest, Intern_MixedScripts_Preserved) {
    const std::string_view mixed = "Hello Мир 世界 🌍";
    StringId id = pool_.intern(mixed);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), mixed);
}

TEST_F(StringPoolTest, Intern_RTL_Arabic_Preserved) {
    const std::string_view arabic = "مرحبا";  // Arabic "hello"
    StringId id = pool_.intern(arabic);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), arabic);
}

}  // namespace
}  // namespace exeray::event
