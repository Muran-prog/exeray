/// @file file_parser_pointer_test.cpp
/// @brief Pointer size handling tests for File ETW parser.

#include "file_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Pointer Size Handling
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_64bit_CorrectOffsets) {
    // 64-bit: Irp(8), FileObject(8), FileKey(8)
    auto data = build_file_create_data(L"C:\\test64.txt", 0, true);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\test64.txt");
}

TEST_F(FileParserTest, ParseFileCreate_32bit_CorrectOffsets) {
    // 32-bit: Irp(4), FileObject(4), FileKey(4)
    auto data = build_file_create_data(L"C:\\test32.txt", 0, false);

    EVENT_RECORD record = make_record(ids::file::CREATE, false);
    record.EventHeader.Flags = 0;
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\test32.txt");
}

TEST_F(FileParserTest, ParseFileRead_64bit_Offset8Bytes) {
    // Offset field is always UINT64 (8 bytes) regardless of pointer size
    auto data = build_file_read_write_data(4096, true);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.size, 4096u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(FileParserPointerTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
