/// @file file_parser_invalid_test.cpp
/// @brief Invalid input tests for File ETW parser.

#include "file_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Invalid Input
// =============================================================================

TEST_F(FileParserTest, ParseFileEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_file_event(nullptr, strings_.get());
    EXPECT_FALSE(result.valid);
}

TEST_F(FileParserTest, ParseFileCreate_TruncatedUserData_ReturnsInvalid) {
    std::vector<uint8_t> data(15, 0);  // < 16 bytes minimum

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(FileParserTest, ParseFileRead_TruncatedUserData_ReturnsInvalid) {
    std::vector<uint8_t> data(23, 0);  // < 24 bytes minimum

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(FileParserInvalidTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
