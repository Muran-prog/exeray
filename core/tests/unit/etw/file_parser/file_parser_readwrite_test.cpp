/// @file file_parser_readwrite_test.cpp
/// @brief Read/Write operation tests for File ETW parser.

#include "file_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Read/Write Operations
// =============================================================================

TEST_F(FileParserTest, ParseFileRead_ExtractsIoSize) {
    auto data = build_file_read_write_data(65536);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::FileOp::Read));
    EXPECT_EQ(result.payload.file.size, 65536u);
}

TEST_F(FileParserTest, ParseFileWrite_ExtractsIoSize) {
    auto data = build_file_read_write_data(65536);

    EVENT_RECORD record = make_record(ids::file::WRITE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::FileOp::Write));
    EXPECT_EQ(result.payload.file.size, 65536u);
}

TEST_F(FileParserTest, ParseFileRead_ZeroIoSize_Valid) {
    auto data = build_file_read_write_data(0);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.size, 0u);
}

TEST_F(FileParserTest, ParseFileRead_MaxIoSize_NoOverflow) {
    auto data = build_file_read_write_data(0xFFFFFFFF);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.size, 0xFFFFFFFFu);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(FileParserReadWriteTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
