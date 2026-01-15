/// @file process_parser_basic_test.cpp
/// @brief Basic event parsing tests for Process ETW parser.

#include "process_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

TEST_F(ProcessParserTest, ParseProcessStart_ValidEvent_ExtractsAllFields) {
    auto data = build_process_start_data(
        1234, 5678, 2, "notepad.exe", L"notepad.exe C:\\test.txt"
    );
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Process);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::Create));
    EXPECT_EQ(result.payload.process.pid, 1234u);
    EXPECT_EQ(result.payload.process.parent_pid, 5678u);
    EXPECT_NE(result.payload.process.image_path, event::INVALID_STRING);
    EXPECT_NE(result.payload.process.command_line, event::INVALID_STRING);
    
    auto image_path = strings_->get(result.payload.process.image_path);
    auto cmd_line = strings_->get(result.payload.process.command_line);
    EXPECT_EQ(image_path, "notepad.exe");
    EXPECT_EQ(cmd_line, "notepad.exe C:\\test.txt");
}

TEST_F(ProcessParserTest, ParseProcessStart_64bit_CorrectPointerHandling) {
    auto data = build_process_start_data(
        4321, 8765, 1, "test64.exe", L"test64", true
    );
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 4321u);
    EXPECT_EQ(result.payload.process.parent_pid, 8765u);
}

TEST_F(ProcessParserTest, ParseProcessStart_32bit_CorrectPointerHandling) {
    auto data = build_process_start_data(
        1111, 2222, 1, "test32.exe", L"test32", false
    );
    
    EVENT_RECORD record = make_record(ids::process::START, false);
    record.EventHeader.Flags = 0;
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 1111u);
    EXPECT_EQ(result.payload.process.parent_pid, 2222u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ProcessParserBasicTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
