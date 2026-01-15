/// @file file_parser_unicode_test.cpp
/// @brief Unicode/path edge case tests for File ETW parser.

#include "file_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Payload Initialization
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_InitializesDefaultValues) {
    // Create a record with path only, no attributes
    auto data = build_file_create_data(L"C:\\default.txt", 0);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    // Default initialization: size = 0, attributes = 0 (from our build func)
    EXPECT_EQ(result.payload.file.size, 0u);
    EXPECT_EQ(result.payload.file.attributes, 0u);
}

// =============================================================================
// Unicode Path Edge Cases
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_EmptyPath_ReturnsINVALID_STRING) {
    auto data = build_file_create_data(L"");

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.path, event::INVALID_STRING);
}

TEST_F(FileParserTest, ParseFileCreate_PathWithNullChars_TruncatesAtFirst) {
    // Build path with embedded null: "C:\test" + NULL + "extra"
    std::wstring path_with_null = L"C:\\test";
    path_with_null += L'\0';
    path_with_null += L"extra";

    // Manually build the buffer to include embedded null
    const size_t ptr_size = 8;
    size_t total_size = ptr_size * 2 + sizeof(uint32_t) * 4 +
                        (path_with_null.size() + 1) * sizeof(wchar_t);
    std::vector<uint8_t> buffer(total_size, 0);

    size_t offset = ptr_size * 2 + sizeof(uint32_t) * 4;
    std::memcpy(buffer.data() + offset, path_with_null.data(),
                (path_with_null.size() + 1) * sizeof(wchar_t));

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = buffer.data();
    record.UserDataLength = static_cast<USHORT>(buffer.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\test");  // Truncated at first null
}

TEST_F(FileParserTest, ParseFileCreate_DeviceNtPath_ExtractsCorrectly) {
    auto data = build_file_create_data(L"\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe");

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe");
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(FileParserUnicodeTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
