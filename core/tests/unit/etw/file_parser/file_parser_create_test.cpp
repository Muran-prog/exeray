/// @file file_parser_create_test.cpp
/// @brief Create operation tests for File ETW parser.

#include "file_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Create Operations
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_ValidEvent_ExtractsPath) {
    auto data = build_file_create_data(L"C:\\Windows\\System32\\notepad.exe");

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::FileSystem);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::FileOp::Create));
    EXPECT_NE(result.payload.file.path, event::INVALID_STRING);

    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\Windows\\System32\\notepad.exe");
}

TEST_F(FileParserTest, ParseFileCreate_ExtractsFileAttributes) {
    constexpr uint32_t HIDDEN_READONLY = 0x03;  // FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
    auto data = build_file_create_data(L"C:\\test.txt", HIDDEN_READONLY);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.attributes, HIDDEN_READONLY);
}

TEST_F(FileParserTest, ParseFileCreate_LongPath_MaxPath32K) {
    // Build a long path (limited by USHORT UserDataLength max 65535)
    // Header is ~32 bytes, so max path is ~32750 wchars
    // Use 16000 chars as a safe long path test
    std::wstring long_path = L"\\\\?\\C:\\";
    long_path.append(16000 - long_path.size(), L'a');

    auto data = build_file_create_data(long_path);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.file.path, event::INVALID_STRING);

    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path.size(), 16000u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(FileParserCreateTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
