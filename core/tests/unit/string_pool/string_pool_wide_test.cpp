#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 4. Wide String Conversion Tests (intern_wide)
// ============================================================================

TEST_F(StringPoolTest, InternWide_SimpleAscii_ConvertsToUtf8) {
    StringId id = pool_.intern_wide(L"hello");

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), "hello");
}

TEST_F(StringPoolTest, InternWide_Cyrillic_ProperConversion) {
    // L"Привет" in wide chars
    StringId id = pool_.intern_wide(L"Привет");

    EXPECT_NE(id, INVALID_STRING);
    // Verify UTF-8 bytes are correct (Cyrillic chars are 2 bytes each in UTF-8)
    std::string_view result = pool_.get(id);
    EXPECT_EQ(result, "Привет");
}

TEST_F(StringPoolTest, InternWide_SurrogatePairs_HandledCorrectly) {
    // 🔥 (U+1F525) encoded as surrogate pair: 0xD83D 0xDD25
    wchar_t emoji[] = {static_cast<wchar_t>(0xD83D), static_cast<wchar_t>(0xDD25), 0};
    StringId id = pool_.intern_wide(emoji);

    EXPECT_NE(id, INVALID_STRING);
    std::string_view result = pool_.get(id);
    
    // Should produce 4-byte UTF-8 sequence for U+1F525
    EXPECT_EQ(result.size(), 4U);
    EXPECT_EQ(result, "🔥");
}

TEST_F(StringPoolTest, InternWide_LoneSurrogate_ReplacementChar) {
    // Lone high surrogate followed by regular ASCII
    wchar_t invalid[] = {static_cast<wchar_t>(0xD83D), L'A', 0};
    StringId id = pool_.intern_wide(invalid);

    EXPECT_NE(id, INVALID_STRING);
    std::string_view result = pool_.get(id);
    
    // Lone surrogate should become U+FFFD (3 UTF-8 bytes) + 'A' (1 byte)
    // U+FFFD = EF BF BD in UTF-8
    EXPECT_EQ(result.size(), 4U);  // 3 + 1
    
    // Check for replacement character (EF BF BD)
    EXPECT_EQ(static_cast<unsigned char>(result[0]), 0xEF);
    EXPECT_EQ(static_cast<unsigned char>(result[1]), 0xBF);
    EXPECT_EQ(static_cast<unsigned char>(result[2]), 0xBD);
    EXPECT_EQ(result[3], 'A');
}

TEST_F(StringPoolTest, InternWide_MaxPath_NoTruncation) {
    // Simulate a very long Windows path (not quite 32767, but long enough)
    constexpr std::size_t kLongPathLen = 4096;
    std::wstring long_path(kLongPathLen, L'x');
    long_path[0] = L'C';
    long_path[1] = L':';
    long_path[2] = L'\\';

    StringId id = pool_.intern_wide(long_path);
    EXPECT_NE(id, INVALID_STRING);

    std::string_view result = pool_.get(id);
    EXPECT_EQ(result.size(), kLongPathLen);  // ASCII chars = same byte count
}

TEST_F(StringPoolTest, InternWide_Empty_ValidId) {
    StringId id = pool_.intern_wide(L"");

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_TRUE(pool_.get(id).empty());
}

}  // namespace
}  // namespace exeray::event
